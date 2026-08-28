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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func TestRingBuffer(t *testing.T) {
	rb := NewRingBuffer(5)
	for i := 1; i <= 10; i++ {
		rb.Push(LogEntry{
			Domain:    fmt.Sprintf("example%d.com.", i),
			ClientIP:  "192.168.1.1",
			IsBlocked: i%2 == 0,
			IsCached:  i%3 == 0,
		})
	}

	total, logs := rb.QueryLogs(10, 0, "", "all")
	if total != 5 {
		t.Fatalf("expected total 5, got %d", total)
	}
	if len(logs) != 5 {
		t.Fatalf("expected 5 logs, got %d", len(logs))
	}

	if logs[0].Domain != "example10.com." {
		t.Errorf("expected newest domain example10.com., got %s", logs[0].Domain)
	}

	totalSearch, searchLogs := rb.QueryLogs(10, 0, "example9", "all")
	if totalSearch != 1 || searchLogs[0].Domain != "example9.com." {
		t.Errorf("search failed, total: %d", totalSearch)
	}

	totalBlocked, blockedLogs := rb.QueryLogs(10, 0, "", "blocked")
	if totalBlocked != 3 {
		t.Errorf("expected 3 blocked logs, got %d", totalBlocked)
	}
	for _, l := range blockedLogs {
		if !l.IsBlocked {
			t.Errorf("expected blocked log, got unblocked: %s", l.Domain)
		}
	}

	_, pageLogs := rb.QueryLogs(2, 1, "", "all")
	if len(pageLogs) != 2 {
		t.Fatalf("expected 2 page items, got %d", len(pageLogs))
	}
	if pageLogs[0].Domain != logs[1].Domain {
		t.Errorf("pagination offset mismatch: got %s, expected %s", pageLogs[0].Domain, logs[1].Domain)
	}

	// Test Clear
	rb.Clear()
	totalClear, logsClear := rb.QueryLogs(10, 0, "", "all")
	if totalClear != 0 || len(logsClear) != 0 {
		t.Errorf("expected 0 logs after clear, got %d", totalClear)
	}
}

func TestTopStats(t *testing.T) {
	top := NewTopStats()

	top.Record("a.com.", "192.168.1.1", false)
	top.Record("a.com.", "192.168.1.1", true)
	top.Record("b.com.", "192.168.1.2", true)
	top.Record("a.com.", "192.168.1.2", false)

	domains, clients, blocked := top.GetTop(10)

	if len(domains) == 0 || domains[0].Domain != "a.com." || domains[0].Count != 3 {
		t.Errorf("top domains mismatch: %+v", domains)
	}

	if len(clients) < 2 {
		t.Fatalf("expected at least 2 clients, got %d", len(clients))
	}

	if len(blocked) < 2 {
		t.Fatalf("expected at least 2 blocked domains, got %d", len(blocked))
	}

	// Test Clear
	top.Clear()
	dClear, _, _ := top.GetTop(10)
	if len(dClear) != 0 {
		t.Errorf("expected 0 top domains after clear, got %d", len(dClear))
	}
}

func TestHistoryStats(t *testing.T) {
	h := NewHistoryStats()
	now := time.Now()

	h.Record(now, false, false)
	h.Record(now, true, false)
	h.Record(now, false, true)

	points := h.GetHistory(24)
	if len(points) != 24 {
		t.Fatalf("expected 24 history points, got %d", len(points))
	}

	lastPoint := points[len(points)-1]
	if lastPoint.Total != 3 || lastPoint.Blocked != 1 || lastPoint.Cached != 1 {
		t.Errorf("history point mismatch: %+v", lastPoint)
	}
}

func TestStatsAPIHTTPEndpoints(t *testing.T) {
	s := NewStatsAPI(&Args{Capacity: 100}, zap.NewNop())
	router := s.Router()

	s.ringBuffer.Push(LogEntry{
		Domain:    "test.com.",
		ClientIP:  "192.168.1.50",
		IsBlocked: true,
		IsCached:  false,
		ElapsedMS: 15.5,
		Upstream:  "UDP://8.8.8.8:53",
		Rule:      "qname test.com.",
	})
	s.totalQueries.Add(1)
	s.blockedQueries.Add(1)
	s.totalLatencyUs.Add(15500)
	s.topStats.Record("test.com.", "192.168.1.50", true)
	s.historyStats.Record(time.Now(), true, false)

	// Test GET /api/v1/stats
	reqStats := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	wStats := httptest.NewRecorder()
	router.ServeHTTP(wStats, reqStats)

	if wStats.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", wStats.Code)
	}

	var statsResp map[string]any
	if err := json.Unmarshal(wStats.Body.Bytes(), &statsResp); err != nil {
		t.Fatalf("failed to unmarshal stats response: %v", err)
	}
	if statsResp["total_queries"].(float64) != 1 {
		t.Errorf("expected total_queries 1, got %v", statsResp["total_queries"])
	}

	// Test GET /api/v1/history
	reqHist := httptest.NewRequest(http.MethodGet, "/api/v1/history?points=24", nil)
	wHist := httptest.NewRecorder()
	router.ServeHTTP(wHist, reqHist)

	if wHist.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for history, got %d", wHist.Code)
	}
	var histResp map[string]any
	if err := json.Unmarshal(wHist.Body.Bytes(), &histResp); err != nil {
		t.Fatalf("failed to unmarshal history response: %v", err)
	}
	histPoints := histResp["points"].([]any)
	if len(histPoints) != 24 {
		t.Errorf("expected 24 history points, got %d", len(histPoints))
	}

	// Test POST /api/v1/logs/clear
	reqClearLogs := httptest.NewRequest(http.MethodPost, "/api/v1/logs/clear", nil)
	wClearLogs := httptest.NewRecorder()
	router.ServeHTTP(wClearLogs, reqClearLogs)

	if wClearLogs.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for clear logs, got %d", wClearLogs.Code)
	}

	// Verify logs ring buffer is empty
	totalLogs, logs := s.ringBuffer.QueryLogs(10, 0, "", "all")
	if totalLogs != 0 || len(logs) != 0 {
		t.Errorf("expected 0 logs after clear, got %d", totalLogs)
	}

	// Test POST /api/v1/cache/clear
	reqClearCache := httptest.NewRequest(http.MethodPost, "/api/v1/cache/clear", nil)
	wClearCache := httptest.NewRecorder()
	router.ServeHTTP(wClearCache, reqClearCache)

	if wClearCache.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for clear cache, got %d", wClearCache.Code)
	}
}

func TestStatsAPIExec(t *testing.T) {
	s := NewStatsAPI(&Args{Capacity: 100}, zap.NewNop())

	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	qCtx.SetUpstreamSelected("8.8.8.8:53", "UDP", "remote", "forward_remote")
	qCtx.AddRuleHit("main_sequence", []string{"qname google.com."}, "forward_remote")

	execFunc := sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		time.Sleep(10 * time.Millisecond)
		resp := new(dns.Msg)
		resp.SetReply(qCtx.Q())
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{142, 250, 190, 46},
		})
		qCtx.SetResponse(resp)
		return nil
	})

	walker := sequence.NewChainWalker([]*sequence.ChainNode{
		{E: execFunc},
	}, nil)

	err := s.Exec(context.Background(), qCtx, walker)
	if err != nil {
		t.Fatalf("Exec returned error: %v", err)
	}

	if s.totalQueries.Load() != 1 {
		t.Errorf("expected 1 total query, got %d", s.totalQueries.Load())
	}

	totalLogs, logs := s.ringBuffer.QueryLogs(10, 0, "", "all")
	if totalLogs != 1 {
		t.Fatalf("expected 1 log entry, got %d", totalLogs)
	}
	if logs[0].Domain != "google.com." {
		t.Errorf("expected domain google.com., got %s", logs[0].Domain)
	}
	if logs[0].Upstream != "UDP://8.8.8.8:53" {
		t.Errorf("expected upstream UDP://8.8.8.8:53, got %s", logs[0].Upstream)
	}
	if logs[0].Rule != "qname google.com." {
		t.Errorf("expected rule qname google.com., got %s", logs[0].Rule)
	}
}
