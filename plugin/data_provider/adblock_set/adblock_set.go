/*
 * Copyright (C) 2025, IrineSistiana
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

package adblock_set

import (
	"fmt"
	"os"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
)

const PluginType = "adblock_set"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	m, err := NewAdblockSet(bp, args.(*Args))
	if err != nil {
		return nil, err
	}
	return m, nil
}

type Args struct {
	Files []string `yaml:"files"`
}

var _ data_provider.DomainMatcherProvider = (*AdblockSet)(nil)

type AdblockSet struct {
	matcher *AdblockMatcher
}

func (d *AdblockSet) GetDomainMatcher() domain.Matcher[struct{}] {
	return d
}

func (d *AdblockSet) Match(s string) (struct{}, bool) {
	if d.matcher != nil {
		return d.matcher.Match(s)
	}
	return struct{}{}, false
}

func NewAdblockSet(bp *coremain.BP, args *Args) (*AdblockSet, error) {
	ds := &AdblockSet{}
	m := &AdblockMatcher{
		blacklist: domain.NewMixMatcher[struct{}](),
		whitelist: domain.NewMixMatcher[struct{}](),
	}

	for _, f := range args.Files {
		if len(f) == 0 {
			continue
		}
		file, err := os.Open(f)
		if err != nil {
			return nil, fmt.Errorf("failed to open file %s: %w", f, err)
		}
		if err := ParseRules(file, m.blacklist, m.whitelist); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to parse rules from %s: %w", f, err)
		}
		file.Close()
	}

	ds.matcher = m
	return ds, nil
}
