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

package hosts

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/hosts"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "hosts"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ sequence.Executable = (*Hosts)(nil)

type Args struct {
	Entries []string `yaml:"entries"`
	Files   []string `yaml:"files"`
}

type Hosts struct {
	h  atomic.Pointer[hosts.Hosts]
	fw *utils.FileWatcher
}

func Init(bp *coremain.BP, args any) (any, error) {
	return NewHosts(bp, args.(*Args))
}

func NewHosts(bp *coremain.BP, args *Args) (*Hosts, error) {
	h := &Hosts{}

	loadInner := func() (*hosts.Hosts, error) {
		m := domain.NewMixMatcher[*hosts.IPs]()
		m.SetDefaultMatcher(domain.MatcherFull)
		for i, entry := range args.Entries {
			if err := domain.Load[*hosts.IPs](m, entry, hosts.ParseIPs); err != nil {
				return nil, fmt.Errorf("failed to load entry #%d %s, %w", i, entry, err)
			}
		}
		for i, file := range args.Files {
			b, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read file #%d %s, %w", i, file, err)
			}
			if err := domain.LoadFromTextReader[*hosts.IPs](m, bytes.NewReader(b), hosts.ParseIPs); err != nil {
				return nil, fmt.Errorf("failed to load file #%d %s, %w", i, file, err)
			}
		}
		return hosts.NewHosts(m), nil
	}

	inner, err := loadInner()
	if err != nil {
		return nil, err
	}
	h.h.Store(inner)

	if len(args.Files) > 0 {
		h.fw = utils.StartFileWatcher(args.Files, time.Second*3, func(changedFiles []string) {
			newInner, err := loadInner()
			if err == nil {
				h.h.Store(newInner)
				bp.L().Info("reloaded files", zap.Strings("files", changedFiles))
			}
		})
	}

	return h, nil
}

func (h *Hosts) Response(q *dns.Msg) *dns.Msg {
	if inner := h.h.Load(); inner != nil {
		return inner.LookupMsg(q)
	}
	return nil
}

func (h *Hosts) Exec(_ context.Context, qCtx *query_context.Context) error {
	if inner := h.h.Load(); inner != nil {
		r := inner.LookupMsg(qCtx.Q())
		if r != nil {
			qCtx.SetResponse(r)
		}
	}
	return nil
}

func (h *Hosts) Close() error {
	if h.fw != nil {
		return h.fw.Close()
	}
	return nil
}
