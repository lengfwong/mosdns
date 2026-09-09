/*
 * Copyright (C) 2020-2026, by ChatGPT
 *
 */

package reject_soa

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "reject_soa"

const (
	DefaultRcode = dns.RcodeNameError
	DefaultTTL   = uint32(7200)
)

func init() {
	// Register full plugin initialization function for YAML config
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })

	// Register quick setup function for sequence syntax (e.g. "reject_soa 3 7200")
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

// Args supports YAML configuration parameters
type Args struct {
	Rcode int    `yaml:"rcode"`
	TTL   uint32 `yaml:"ttl"`
}

// RejectSOA has the same control-flow behavior as the built-in
// "reject": it is a RecursiveExcutable, and Execdeliberately does not continue the current ChainWalker.
var _ sequence.RecursiveExecutable = (*RejectSOA)(nil)

type RejectSOA struct {
	Rcode int    `yaml:"rcode"`
	TTL   uint32 `yaml:"ttl"`
}

func NewRejectSOA(rcode int, ttl uint32) *RejectSOA {
	return &RejectSOA{
		Rcode: rcode,
		TTL:   ttl,
	}
}

// QuickSetup accepts:
//
//	reject_soa
//	reject_soa <rcode>
//	reject_soa <rcode> <ttl>
//
// Defaults: rcode=3 (NXDOMAIN), ttl=7200.
func QuickSetup(_ sequence.BQ, s string) (any, error) {
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) > 2 {
		return nil, fmt.Errorf("[%s] too many arguments", PluginType)
	}

	p := &RejectSOA{
		Rcode: DefaultRcode,
		TTL:   DefaultTTL,
	}

	if len(fields) >= 1 {
		rcode, err := strconv.Atoi(fields[0])
		if err != nil || rcode < 0 || rcode > 0xFFF {
			return nil, fmt.Errorf("[%s] invalid rcode %q: %w", PluginType, fields[0], err)
		}
		p.Rcode = rcode
	}

	if len(fields) == 2 {
		ttl, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("[%s] invalid ttl %q: %w", PluginType, fields[1], err)
		}
		p.TTL = uint32(ttl)
	}

	return p, nil
}

func Init(_ *coremain.BP, args any) (any, error) {
	a := args.(*Args)
	rcode := a.Rcode
	if rcode == 0 {
		rcode = DefaultRcode
	}
	ttl := a.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	return NewRejectSOA(rcode, ttl), nil
}

// Exec generates an RCODE response with an SOA in the Authority section.
// It intentionally does not call cw.Next(), matching built-in reject/accept
// behavior to stop execution across all parent sequences--Doubt stop parent sequences....
func (p *RejectSOA) Exec(_ context.Context, qCtx *query_context.Context, _ sequence.ChainWalker) error {
	q := qCtx.Q()
	if q == nil {
		return nil
	}

	r := new(dns.Msg)
	r.SetReply(q)
	r.Rcode = p.Rcode
	r.Authoritative = true

	// Add fake SOA to the Authority section when Question exists
	if len(q.Question) > 0 {
		soa := dnsutils.FakeSOA(q.Question[0].Name)
		soa.Hdr.Ttl = p.TTL
		soa.Minttl = p.TTL
		r.Ns = append(r.Ns, soa)
	}

	qCtx.SetResponse(r)

	// Returning nil without invoking cw.Next() terminates sequence execution naturally
	return nil
}
