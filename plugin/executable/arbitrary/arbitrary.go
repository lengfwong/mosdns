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

package arbitrary

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/pkg/zone_file"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"go.uber.org/zap"
)

const PluginType = "arbitrary"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	Rules []string `yaml:"rules"`
	Files []string `yaml:"files"`
}

var _ sequence.Executable = (*Arbitrary)(nil)

type Arbitrary struct {
	m  atomic.Pointer[zone_file.Matcher]
	fw *utils.FileWatcher
}

func NewArbitrary(bp *coremain.BP, args *Args) (*Arbitrary, error) {
	a := &Arbitrary{}

	loadInner := func() (*zone_file.Matcher, error) {
		m := new(zone_file.Matcher)
		for i, s := range args.Rules {
			if err := m.Load(strings.NewReader(s)); err != nil {
				return nil, fmt.Errorf("failed to load rr #%d [%s], %w", i, s, err)
			}
		}
		for i, file := range args.Files {
			b, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read file #%d [%s], %w", i, file, err)
			}
			if err := m.Load(bytes.NewReader(b)); err != nil {
				return nil, fmt.Errorf("failed to load rr file #%d [%s], %w", i, file, err)
			}
		}
		return m, nil
	}

	inner, err := loadInner()
	if err != nil {
		return nil, err
	}
	a.m.Store(inner)

	if len(args.Files) > 0 {
		a.fw = utils.StartFileWatcher(args.Files, time.Second*3, func(changedFiles []string) {
			newInner, err := loadInner()
			if err == nil {
				a.m.Store(newInner)
				bp.L().Info("reloaded files", zap.Strings("files", changedFiles))
			}
		})
	}

	return a, nil
}

func (a *Arbitrary) Exec(_ context.Context, qCtx *query_context.Context) error {
	if inner := a.m.Load(); inner != nil {
		if r := inner.Reply(qCtx.Q()); r != nil {
			qCtx.SetResponse(r)
		}
	}
	return nil
}

func (a *Arbitrary) Close() error {
	if a.fw != nil {
		return a.fw.Close()
	}
	return nil
}

func Init(bp *coremain.BP, v any) (any, error) {
	args := v.(*Args)
	return NewArbitrary(bp, args)
}
