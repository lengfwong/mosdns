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
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/stretchr/testify/assert"
)

func TestParseAndMatch(t *testing.T) {
	rules := `
! Comment
# Another comment
||example.com^
@@||whitelist.com^
|exact.com|
@@|white-exact.com|
/.*regex.*/
@@/.*white-regex.*/
*keyword*
@@*white-keyword*
blocked.com
domain:ntp.org
full:metrics.icloud.com
`
	blacklist := domain.NewMixMatcher[struct{}]()
	whitelist := domain.NewMixMatcher[struct{}]()

	err := ParseRules(strings.NewReader(rules), blacklist, whitelist)
	assert.NoError(t, err)

	matcher := &AdblockMatcher{
		blacklist: blacklist,
		whitelist: whitelist,
	}

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"whitelist.com", false},
		{"sub.whitelist.com", false},
		{"exact.com", true},
		{"sub.exact.com", false}, // |exact.com| is exact match
		{"white-exact.com", false},
		{"myregex123", true},
		{"mywhite-regex123", false},
		{"somekeywordhere", true},
		{"some-white-keyword-here", false},
		{"blocked.com", true},
		{"other.com", false},
		{"ntp.org", true},       // matched by domain:ntp.org
		{"sub.ntp.org", true},   // matched by domain:ntp.org
		{"metrics.icloud.com", true}, // matched by full:metrics.icloud.com
		{"sub.metrics.icloud.com", false}, // full match only
	}

	for _, tt := range tests {
		_, ok := matcher.Match(tt.domain)
		assert.Equal(t, tt.want, ok, "Match(%s)", tt.domain)
	}
}

func TestStripOptions(t *testing.T) {
	rules := `
||example.com^$important,third-party
@@||whitelist.com^$dnstype=A
`
	blacklist := domain.NewMixMatcher[struct{}]()
	whitelist := domain.NewMixMatcher[struct{}]()

	err := ParseRules(strings.NewReader(rules), blacklist, whitelist)
	assert.NoError(t, err)

	matcher := &AdblockMatcher{
		blacklist: blacklist,
		whitelist: whitelist,
	}

	_, ok := matcher.Match("example.com")
	assert.True(t, ok)

	_, ok = matcher.Match("whitelist.com")
	assert.False(t, ok)
}
