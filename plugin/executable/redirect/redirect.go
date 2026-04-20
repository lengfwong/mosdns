/*
 * Copyright (C) 2020-2022, IrineSistiana
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

package redirect

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "redirect"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ sequence.RecursiveExecutable = (*Redirect)(nil)

type Args struct {
	Rules []string `yaml:"rules"`
	Files []string `yaml:"files"`
}

type Redirect struct {
	m  atomic.Pointer[domain.MixMatcher[string]]
	fw *utils.FileWatcher
}

func Init(bp *coremain.BP, args any) (any, error) {
	r, err := NewRedirect(bp, args.(*Args))
	if err != nil {
		return nil, err
	}
	bp.L().Info("redirect rules loaded", zap.Int("length", r.Len()))
	return r, nil
}

func NewRedirect(bp *coremain.BP, args *Args) (*Redirect, error) {
	r := &Redirect{}
	parseFunc := func(s string) (p, v string, err error) {
		f := strings.Fields(s)
		if len(f) != 2 {
			return "", "", fmt.Errorf("redirect rule must have 2 fields, but got %d", len(f))
		}
		return f[0], dns.Fqdn(f[1]), nil
	}

	loadInner := func() (*domain.MixMatcher[string], error) {
		m := domain.NewMixMatcher[string]()
		m.SetDefaultMatcher(domain.MatcherFull)
		for i, rule := range args.Rules {
			if err := domain.Load[string](m, rule, parseFunc); err != nil {
				return nil, fmt.Errorf("failed to load rule #%d %s, %w", i, rule, err)
			}
		}
		for i, file := range args.Files {
			b, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read file #%d %s, %w", i, file, err)
			}
			if err := domain.LoadFromTextReader[string](m, bytes.NewReader(b), parseFunc); err != nil {
				return nil, fmt.Errorf("failed to load file #%d %s, %w", i, file, err)
			}
		}
		return m, nil
	}

	inner, err := loadInner()
	if err != nil {
		return nil, err
	}
	r.m.Store(inner)

	if len(args.Files) > 0 {
		r.fw = utils.StartFileWatcher(args.Files, time.Second*3, func(changedFiles []string) {
			newInner, err := loadInner()
			if err == nil {
				r.m.Store(newInner)
				bp.L().Info("reloaded files", zap.Strings("files", changedFiles), zap.Int("length", newInner.Len()))
			}
		})
	}

	return r, nil
}

func (r *Redirect) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	q := qCtx.Q()
	if len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET {
		return next.ExecNext(ctx, qCtx)
	}

	orgQName := q.Question[0].Name
	inner := r.m.Load()
	if inner == nil {
		return next.ExecNext(ctx, qCtx)
	}

	redirectTarget, ok := inner.Match(orgQName)
	if !ok {
		return next.ExecNext(ctx, qCtx)
	}

	q.Question[0].Name = redirectTarget
	defer func() {
		q.Question[0].Name = orgQName
	}()
	err := next.ExecNext(ctx, qCtx)
	if rResp := qCtx.R(); rResp != nil {
		// Restore original query name.
		for i := range rResp.Question {
			if rResp.Question[i].Name == redirectTarget {
				rResp.Question[i].Name = orgQName
			}
		}

		// Insert a CNAME record.
		newAns := make([]dns.RR, 1, len(rResp.Answer)+1)
		newAns[0] = &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   orgQName,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			Target: redirectTarget,
		}
		newAns = append(newAns, rResp.Answer...)
		rResp.Answer = newAns
	}
	return err
}

func (r *Redirect) Len() int {
	if inner := r.m.Load(); inner != nil {
		return inner.Len()
	}
	return 0
}

func (r *Redirect) Close() error {
	if r.fw != nil {
		return r.fw.Close()
	}
	return nil
}
