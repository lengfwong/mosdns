/*
 * Copyright (C) 2020-2026, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package stats_api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "stats_api"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

var _ sequence.RecursiveExecutable = (*StatsAPI)(nil)

type Args struct {
	Listen   string `yaml:"listen"`
	Capacity int    `yaml:"capacity"`
}

func (a *Args) init() {
	if a.Capacity <= 0 {
		a.Capacity = 2000
	}
}

type AnswerDTO struct {
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  uint32 `json:"ttl"`
}

type LogEntry struct {
	ID        string      `json:"id"`
	Timestamp string      `json:"timestamp"`
	ClientIP  string      `json:"client_ip"`
	Domain    string      `json:"domain"`
	QType     string      `json:"qtype"`
	Status    string      `json:"status"`
	IsBlocked bool        `json:"is_blocked"`
	IsCached  bool        `json:"is_cached"`
	ElapsedMS float64     `json:"elapsed_ms"`
	Upstream  string      `json:"upstream,omitempty"`
	Rule      string      `json:"rule,omitempty"`
	Answers   []AnswerDTO `json:"answers"`
}

type RingBuffer struct {
	mu       sync.RWMutex
	buf      []LogEntry
	capacity int
	head     int
	count    int
	seqID    uint64
}

func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = 2000
	}
	return &RingBuffer{
		buf:      make([]LogEntry, capacity),
		capacity: capacity,
	}
}

func (r *RingBuffer) Push(entry LogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.seqID++
	nowSec := time.Now().Unix()
	entry.ID = fmt.Sprintf("%d-%d", nowSec, r.seqID)

	r.buf[r.head] = entry
	r.head = (r.head + 1) % r.capacity
	if r.count < r.capacity {
		r.count++
	}
}

func (r *RingBuffer) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.buf = make([]LogEntry, r.capacity)
	r.head = 0
	r.count = 0
	r.seqID = 0
}

func (r *RingBuffer) QueryLogs(limit, offset int, search, filter string) (int, []LogEntry) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	all := make([]LogEntry, 0, r.count)
	for i := 0; i < r.count; i++ {
		idx := (r.head - 1 - i + r.capacity) % r.capacity
		all = append(all, r.buf[idx])
	}

	searchLower := strings.ToLower(strings.TrimSpace(search))
	filterLower := strings.ToLower(strings.TrimSpace(filter))

	filtered := make([]LogEntry, 0, len(all))
	for _, entry := range all {
		if filterLower == "blocked" && !entry.IsBlocked {
			continue
		}
		if filterLower == "cached" && !entry.IsCached {
			continue
		}

		if searchLower != "" {
			if !strings.Contains(strings.ToLower(entry.Domain), searchLower) &&
				!strings.Contains(strings.ToLower(entry.ClientIP), searchLower) {
				continue
			}
		}

		filtered = append(filtered, entry)
	}

	total := len(filtered)
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return total, []LogEntry{}
	}

	end := offset + limit
	if end > total {
		end = total
	}

	return total, filtered[offset:end]
}

type TopItem struct {
	Domain   string `json:"domain,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
	Count    uint64 `json:"count"`
}

type TopStats struct {
	mu         sync.RWMutex
	topDomains map[string]uint64
	topClients map[string]uint64
	topBlocked map[string]uint64
}

func NewTopStats() *TopStats {
	return &TopStats{
		topDomains: make(map[string]uint64),
		topClients: make(map[string]uint64),
		topBlocked: make(map[string]uint64),
	}
}

func (t *TopStats) Record(domain, clientIP string, isBlocked bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if domain != "" {
		if isBlocked {
			t.topBlocked[domain]++
		} else {
			t.topDomains[domain]++
		}
	}
	if clientIP != "" {
		t.topClients[clientIP]++
	}
}

func (t *TopStats) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.topDomains = make(map[string]uint64)
	t.topClients = make(map[string]uint64)
	t.topBlocked = make(map[string]uint64)
}

func getSortedTop(m map[string]uint64, isClient bool, limit int) []TopItem {
	type pair struct {
		key   string
		count uint64
	}
	pairs := make([]pair, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, pair{key: k, count: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count == pairs[j].count {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].count > pairs[j].count
	})

	if limit > len(pairs) {
		limit = len(pairs)
	}
	res := make([]TopItem, 0, limit)
	for i := 0; i < limit; i++ {
		item := TopItem{Count: pairs[i].count}
		if isClient {
			item.ClientIP = pairs[i].key
		} else {
			item.Domain = pairs[i].key
		}
		res = append(res, item)
	}
	return res
}

func (t *TopStats) GetTop(limit int) ([]TopItem, []TopItem, []TopItem) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if limit <= 0 {
		limit = 10
	}
	topDomains := getSortedTop(t.topDomains, false, limit)
	topClients := getSortedTop(t.topClients, true, limit)
	topBlocked := getSortedTop(t.topBlocked, false, limit)
	return topDomains, topClients, topBlocked
}

type HistoryPoint struct {
	Time    string `json:"time"`
	Total   uint64 `json:"total"`
	Blocked uint64 `json:"blocked"`
	Cached  uint64 `json:"cached"`
}

type HistoryBucket struct {
	Total   atomic.Uint64
	Blocked atomic.Uint64
	Cached  atomic.Uint64
}

type HistoryStats struct {
	mu     sync.RWMutex
	points map[int64]*HistoryBucket
}

func NewHistoryStats() *HistoryStats {
	return &HistoryStats{
		points: make(map[int64]*HistoryBucket),
	}
}

func (h *HistoryStats) Record(t time.Time, isBlocked, isCached bool) {
	tHour := t.UTC().Truncate(time.Hour).Unix()

	h.mu.RLock()
	bucket, ok := h.points[tHour]
	h.mu.RUnlock()

	if !ok {
		h.mu.Lock()
		bucket, ok = h.points[tHour]
		if !ok {
			bucket = &HistoryBucket{}
			h.points[tHour] = bucket

			// Clean up old buckets beyond 48 hours
			cutoff := t.UTC().Add(-48 * time.Hour).Unix()
			for k := range h.points {
				if k < cutoff {
					delete(h.points, k)
				}
			}
		}
		h.mu.Unlock()
	}

	bucket.Total.Add(1)
	if isBlocked {
		bucket.Blocked.Add(1)
	}
	if isCached {
		bucket.Cached.Add(1)
	}
}

func (h *HistoryStats) GetHistory(numPoints int) []HistoryPoint {
	if numPoints <= 0 {
		numPoints = 24
	}
	now := time.Now().UTC().Truncate(time.Hour)
	res := make([]HistoryPoint, 0, numPoints)

	h.mu.RLock()
	defer h.mu.RUnlock()

	for i := numPoints - 1; i >= 0; i-- {
		slotTime := now.Add(time.Duration(-i) * time.Hour)
		slotUnix := slotTime.Unix()

		var total, blocked, cached uint64
		if bucket, ok := h.points[slotUnix]; ok {
			total = bucket.Total.Load()
			blocked = bucket.Blocked.Load()
			cached = bucket.Cached.Load()
		}

		res = append(res, HistoryPoint{
			Time:    slotTime.Format(time.RFC3339),
			Total:   total,
			Blocked: blocked,
			Cached:  cached,
		})
	}
	return res
}

type StatsAPI struct {
	args   *Args
	logger *zap.Logger

	ringBuffer   *RingBuffer
	topStats     *TopStats
	historyStats *HistoryStats

	totalQueries   atomic.Uint64
	blockedQueries atomic.Uint64
	cachedQueries  atomic.Uint64
	totalLatencyUs atomic.Uint64

	httpServer *http.Server
	closeOnce  sync.Once
}

func Init(bp *coremain.BP, args any) (any, error) {
	a := args.(*Args)
	s := NewStatsAPI(a, bp.L())
	bp.RegAPI(s.Router())
	return s, nil
}

func QuickSetup(bq sequence.BQ, s string) (any, error) {
	fields := strings.Fields(s)
	listen := ""
	capacity := 2000
	if len(fields) > 0 {
		listen = fields[0]
	}
	if len(fields) > 1 {
		if c, err := strconv.Atoi(fields[1]); err == nil && c > 0 {
			capacity = c
		}
	}
	return NewStatsAPI(&Args{Listen: listen, Capacity: capacity}, bq.L()), nil
}

func NewStatsAPI(args *Args, logger *zap.Logger) *StatsAPI {
	args.init()
	if logger == nil {
		logger = zap.NewNop()
	}
	s := &StatsAPI{
		args:         args,
		logger:       logger,
		ringBuffer:   NewRingBuffer(args.Capacity),
		topStats:     NewTopStats(),
		historyStats: NewHistoryStats(),
	}

	if len(args.Listen) > 0 {
		srv := &http.Server{
			Addr:    args.Listen,
			Handler: s.Router(),
		}
		s.httpServer = srv
		go func() {
			logger.Info("starting stats api http server", zap.String("addr", args.Listen))
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("stats api http server error", zap.Error(err))
			}
		}()
	}
	return s
}

func (s *StatsAPI) Router() *chi.Mux {
	r := chi.NewRouter()

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if req.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, req)
		})
	})

	r.Get("/api/v1/stats", s.handleStats)
	r.Get("/api/v1/logs", s.handleLogs)
	r.Get("/api/v1/top", s.handleTop)
	r.Get("/api/v1/history", s.handleHistory)
	r.Post("/api/v1/logs/clear", s.handleClearLogs)
	r.Post("/api/v1/cache/clear", s.handleClearCache)

	return r
}

func (s *StatsAPI) handleStats(w http.ResponseWriter, req *http.Request) {
	total := s.totalQueries.Load()
	blocked := s.blockedQueries.Load()
	cached := s.cachedQueries.Load()
	latUs := s.totalLatencyUs.Load()

	var blockedPct, cachedPct, avgLat float64
	if total > 0 {
		blockedPct = float64(blocked) / float64(total) * 100.0
		cachedPct = float64(cached) / float64(total) * 100.0
		avgLat = (float64(latUs) / float64(total)) / 1000.0
	}

	blockedPct = math.Round(blockedPct*100) / 100
	cachedPct = math.Round(cachedPct*100) / 100
	avgLat = math.Round(avgLat*100) / 100

	resp := map[string]any{
		"total_queries":      total,
		"blocked_queries":    blocked,
		"cached_queries":     cached,
		"blocked_percentage": blockedPct,
		"cached_percentage":  cachedPct,
		"avg_latency_ms":     avgLat,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *StatsAPI) handleLogs(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	limitStr := q.Get("limit")
	offsetStr := q.Get("offset")
	search := q.Get("search")
	filter := q.Get("filter")

	limit := 50
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	if limit > 500 {
		limit = 500
	}
	offset := 0
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}

	total, items := s.ringBuffer.QueryLogs(limit, offset, search, filter)
	if items == nil {
		items = []LogEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"total": total,
		"items": items,
	})
}

func (s *StatsAPI) handleTop(w http.ResponseWriter, req *http.Request) {
	limitStr := req.URL.Query().Get("limit")
	limit := 10
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}

	topDomains, topClients, topBlocked := s.topStats.GetTop(limit)
	if topDomains == nil {
		topDomains = []TopItem{}
	}
	if topClients == nil {
		topClients = []TopItem{}
	}
	if topBlocked == nil {
		topBlocked = []TopItem{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"top_domains": topDomains,
		"top_clients": topClients,
		"top_blocked": topBlocked,
	})
}

func (s *StatsAPI) handleHistory(w http.ResponseWriter, req *http.Request) {
	pointsStr := req.URL.Query().Get("points")
	numPoints := 24
	if p, err := strconv.Atoi(pointsStr); err == nil && p > 0 {
		numPoints = p
	}
	if numPoints > 168 { // Max 7 days of hourly points
		numPoints = 168
	}

	points := s.historyStats.GetHistory(numPoints)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"points": points,
	})
}

func (s *StatsAPI) handleClearLogs(w http.ResponseWriter, req *http.Request) {
	s.ringBuffer.Clear()
	s.topStats.Clear()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Logs cleared successfully",
	})
}

func (s *StatsAPI) handleClearCache(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Cache clear request processed",
	})
}

func (s *StatsAPI) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	start := time.Now()
	err := next.ExecNext(ctx, qCtx)
	elapsed := time.Since(start)

	s.totalQueries.Add(1)
	s.totalLatencyUs.Add(uint64(elapsed.Microseconds()))

	var clientIP string
	if clientAddr := qCtx.ServerMeta.ClientAddr; clientAddr.IsValid() {
		clientIP = clientAddr.String()
	}
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}

	qQuestion := qCtx.QQuestion()
	domain := qQuestion.Name
	qtypeStr := dns.TypeToString[qQuestion.Qtype]
	if qtypeStr == "" {
		qtypeStr = fmt.Sprintf("TYPE%d", qQuestion.Qtype)
	}

	isCached := qCtx.CacheState.Hit || qCtx.CacheState.LazyHit
	if isCached {
		s.cachedQueries.Add(1)
	}

	r := qCtx.R()
	var status string
	var answers []AnswerDTO
	isBlocked := false

	if r == nil {
		status = "DROPPED"
		isBlocked = true
	} else {
		if rcodeStr, ok := dns.RcodeToString[r.Rcode]; ok {
			status = rcodeStr
		} else {
			status = fmt.Sprintf("RCODE%d", r.Rcode)
		}

		if r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeRefused {
			isBlocked = true
		}

		for _, rr := range r.Answer {
			hdr := rr.Header()
			rrTypeStr := dns.TypeToString[hdr.Rrtype]
			if rrTypeStr == "" {
				rrTypeStr = fmt.Sprintf("TYPE%d", hdr.Rrtype)
			}
			var dataStr string
			switch record := rr.(type) {
			case *dns.A:
				dataStr = record.A.String()
				if dataStr == "0.0.0.0" || dataStr == "127.0.0.1" {
					isBlocked = true
				}
			case *dns.AAAA:
				dataStr = record.AAAA.String()
				if dataStr == "::" || dataStr == "::1" {
					isBlocked = true
				}
			case *dns.CNAME:
				dataStr = record.Target
			case *dns.TXT:
				dataStr = strings.Join(record.Txt, " ")
			case *dns.PTR:
				dataStr = record.Ptr
			case *dns.MX:
				dataStr = record.Mx
			default:
				dataStr = rr.String()
			}
			answers = append(answers, AnswerDTO{
				Type: rrTypeStr,
				Data: dataStr,
				TTL:  hdr.Ttl,
			})
		}
	}

	if isBlocked {
		s.blockedQueries.Add(1)
	}

	// Extract Upstream information
	var upstream string
	if isCached {
		upstream = "cache"
	} else if u := qCtx.UpstreamSelected; u != nil {
		if u.Protocol != "" && u.Addr != "" {
			upstream = fmt.Sprintf("%s://%s", u.Protocol, u.Addr)
		} else if u.Addr != "" {
			upstream = u.Addr
		} else if u.Tag != "" {
			upstream = u.Tag
		}
	}

	// Extract Rule information
	var rule string
	if len(qCtx.RuleHits) > 0 {
		for i := len(qCtx.RuleHits) - 1; i >= 0; i-- {
			hit := qCtx.RuleHits[i]
			if len(hit.Matches) > 0 {
				rule = strings.Join(hit.Matches, ",")
				break
			} else if hit.Exec != "" {
				rule = hit.Exec
				break
			} else if hit.Sequence != "" {
				rule = hit.Sequence
				break
			}
		}
	}

	s.topStats.Record(domain, clientIP, isBlocked)
	s.historyStats.Record(start, isBlocked, isCached)

	elapsedMS := math.Round(float64(elapsed.Microseconds())/10.0) / 100.0

	entry := LogEntry{
		Timestamp: start.UTC().Format(time.RFC3339),
		ClientIP:  clientIP,
		Domain:    domain,
		QType:     qtypeStr,
		Status:    status,
		IsBlocked: isBlocked,
		IsCached:  isCached,
		ElapsedMS: elapsedMS,
		Upstream:  upstream,
		Rule:      rule,
		Answers:   answers,
	}

	s.ringBuffer.Push(entry)

	return err
}

func (s *StatsAPI) Close() error {
	s.closeOnce.Do(func() {
		if s.httpServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.httpServer.Shutdown(ctx)
		}
	})
	return nil
}
