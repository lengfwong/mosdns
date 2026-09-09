package reject_soa

import (
	"context"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestQuickSetupDefaults(t *testing.T) {
	pAny, err := QuickSetup(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	p := pAny.(*RejectSOA)
	if p.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode=%d, want %d", p.Rcode, dns.RcodeNameError)
	}
	if p.TTL != 7200 {
		t.Fatalf("ttl=%d, want 7200", p.TTL)
	}

	pAny, err = QuickSetup(nil, "3 7200")
	if err != nil {
		t.Fatal(err)
	}
	p = pAny.(*RejectSOA)
	if p.Rcode != 3 || p.TTL != 7200 {
		t.Fatalf("got rcode=%d ttl=%d, want 3/7200", p.Rcode, p.TTL)
	}
}

func TestExecNXDomainSOA(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("dataflow.biliapi.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)

	p := &RejectSOA{Rcode: dns.RcodeNameError, TTL: 7200}
	if err := p.Exec(context.Background(), qCtx, sequence.ChainWalker{}); err != nil {
		t.Fatal(err)
	}

	r := qCtx.R()
	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode=%d, want NXDOMAIN", r.Rcode)
	}
	if len(r.Answer) != 0 {
		t.Fatalf("answer count=%d, want 0", len(r.Answer))
	}
	if len(r.Ns) != 1 {
		t.Fatalf("authority count=%d, want 1", len(r.Ns))
	}
	soa, ok := r.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("authority RR type=%T, want SOA", r.Ns[0])
	}
	if soa.Hdr.Ttl != 7200 {
		t.Fatalf("soa ttl=%d, want 7200", soa.Hdr.Ttl)
	}
	if soa.Minttl != 7200 {
		t.Fatalf("soa minimum=%d, want 7200", soa.Minttl)
	}
}
