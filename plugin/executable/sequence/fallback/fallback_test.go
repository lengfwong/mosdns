package fallback

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type mockExec struct {
	delay time.Duration
	resp  *dns.Msg
	err   error
}

func (m *mockExec) Exec(ctx context.Context, qCtx *query_context.Context) error {
	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.delay):
		}
	}
	if m.err != nil {
		return m.err
	}
	if m.resp != nil {
		qCtx.SetResponse(m.resp.Copy())
	}
	return nil
}

func TestFallbackPrimarySuccess(t *testing.T) {
	respP := new(dns.Msg)
	respP.SetRcode(new(dns.Msg), dns.RcodeSuccess)
	respP.Extra = append(respP.Extra, &dns.TXT{Hdr: dns.RR_Header{Name: "prim.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"primary"}})

	respS := new(dns.Msg)
	respS.SetRcode(new(dns.Msg), dns.RcodeSuccess)
	respS.Extra = append(respS.Extra, &dns.TXT{Hdr: dns.RR_Header{Name: "sec.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"secondary"}})

	fb := &fallback{
		logger:               zap.NewNop(),
		primary:              &mockExec{resp: respP},
		secondary:            &mockExec{resp: respS, delay: 50 * time.Millisecond},
		fastFallbackDuration: 100 * time.Millisecond,
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)

	err := fb.Exec(context.Background(), qCtx)
	assert.NoError(t, err)
	assert.NotNil(t, qCtx.R())
	assert.Equal(t, "prim.", qCtx.R().Extra[0].Header().Name)
}

func TestFallbackSecondaryOnPrimaryFail(t *testing.T) {
	respS := new(dns.Msg)
	respS.SetRcode(new(dns.Msg), dns.RcodeSuccess)

	fb := &fallback{
		logger:               zap.NewNop(),
		primary:              &mockExec{err: errors.New("upstream timeout")},
		secondary:            &mockExec{resp: respS},
		fastFallbackDuration: 100 * time.Millisecond,
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)

	err := fb.Exec(context.Background(), qCtx)
	assert.NoError(t, err)
	assert.NotNil(t, qCtx.R())
}

func TestFallbackSecondaryOnPrimaryTimeout(t *testing.T) {
	respS := new(dns.Msg)
	respS.SetRcode(new(dns.Msg), dns.RcodeSuccess)

	fb := &fallback{
		logger:               zap.NewNop(),
		primary:              &mockExec{delay: 200 * time.Millisecond, err: errors.New("timeout")},
		secondary:            &mockExec{resp: respS},
		fastFallbackDuration: 20 * time.Millisecond,
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)

	err := fb.Exec(context.Background(), qCtx)
	assert.NoError(t, err)
	assert.NotNil(t, qCtx.R())
}

func TestFallbackBothFail(t *testing.T) {
	fb := &fallback{
		logger:               zap.NewNop(),
		primary:              &mockExec{err: errors.New("primary failed")},
		secondary:            &mockExec{err: errors.New("secondary failed")},
		fastFallbackDuration: 20 * time.Millisecond,
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)

	err := fb.Exec(context.Background(), qCtx)
	assert.ErrorIs(t, err, ErrFailed)
}

func TestFallbackAlwaysStandbyPrimaryWins(t *testing.T) {
	respP := new(dns.Msg)
	respP.SetRcode(new(dns.Msg), dns.RcodeSuccess)
	respP.Extra = append(respP.Extra, &dns.TXT{Hdr: dns.RR_Header{Name: "prim.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"primary"}})

	respS := new(dns.Msg)
	respS.SetRcode(new(dns.Msg), dns.RcodeSuccess)
	respS.Extra = append(respS.Extra, &dns.TXT{Hdr: dns.RR_Header{Name: "sec.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"secondary"}})

	// Secondary finishes faster (5ms), but primary succeeds before threshold (50ms)
	fb := &fallback{
		logger:               zap.NewNop(),
		primary:              &mockExec{delay: 15 * time.Millisecond, resp: respP},
		secondary:            &mockExec{delay: 2 * time.Millisecond, resp: respS},
		fastFallbackDuration: 50 * time.Millisecond,
		alwaysStandby:        true,
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)

	err := fb.Exec(context.Background(), qCtx)
	assert.NoError(t, err)
	assert.NotNil(t, qCtx.R())
	assert.Equal(t, "prim.", qCtx.R().Extra[0].Header().Name)
}
