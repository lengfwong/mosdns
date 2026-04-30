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
	"bufio"
	"io"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
)

// ParseRules reads AdBlock rules from r and adds them to blacklist and whitelist matchers.
func ParseRules(r io.Reader, blacklist, whitelist *domain.MixMatcher[struct{}]) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '!' || line[0] == '#' {
			continue
		}

		// Handle whitelists
		isWhitelist := false
		if strings.HasPrefix(line, "@@") {
			isWhitelist = true
			line = line[2:]
		}

		// Handle comments in rules (e.g., rule # comment)
		// But in AdBlock, # is usually for element hiding (##) or CSS selectors.
		// For DNS rules, we ignore anything starting with #.
		if strings.Contains(line, "##") || strings.Contains(line, "#?#") || strings.Contains(line, "#$#") {
			continue
		}

		// Strip options (e.g., $important, $third-party)
		if idx := strings.LastIndex(line, "$"); idx != -1 {
			// Check if it's a regex or something else.
			// In ABP, $ marks the start of options.
			line = line[:idx]
		}

		if line == "" {
			continue
		}

		target := blacklist
		if isWhitelist {
			target = whitelist
		}

		if err := parseAndAddRule(line, target); err != nil {
			// Skip invalid rules but maybe we should log them?
			continue
		}
	}
	return scanner.Err()
}

func parseAndAddRule(rule string, m *domain.MixMatcher[struct{}]) error {
	// 0. Native MosDNS rules: type:pattern
	if strings.Contains(rule, ":") {
		typ, _, _ := strings.Cut(rule, ":")
		switch typ {
		case "full", "domain", "regexp", "keyword":
			return m.Add(rule, struct{}{})
		}
	}

	// 1. Regex: /regexp/
	if strings.HasPrefix(rule, "/") && strings.HasSuffix(rule, "/") && len(rule) > 2 {
		return m.Add("regexp:"+rule[1:len(rule)-1], struct{}{})
	}

	// 2. Subdomain: ||example.com^
	if strings.HasPrefix(rule, "||") {
		domainStr := rule[2:]
		if strings.HasSuffix(domainStr, "^") {
			domainStr = domainStr[:len(domainStr)-1]
		}
		return m.Add("domain:"+domainStr, struct{}{})
	}

	// 3. Exact match: |example.com|
	if strings.HasPrefix(rule, "|") && strings.HasSuffix(rule, "|") && len(rule) > 2 {
		return m.Add("full:"+rule[1:len(rule)-1], struct{}{})
	}

	// 4. Keyword: *keyword*
	if strings.HasPrefix(rule, "*") && strings.HasSuffix(rule, "*") && len(rule) > 2 {
		return m.Add("keyword:"+rule[1:len(rule)-1], struct{}{})
	}

	// 5. Default: treat as exact match if it looks like a domain
	// Many lists are just a list of domains.
	// AdGuard Home treats rules without || or ^ as exact matches.
	return m.Add("full:"+rule, struct{}{})
}
