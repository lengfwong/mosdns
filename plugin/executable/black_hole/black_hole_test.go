package black_hole

import (
	"context"
	"sync"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestBlackHoleConcurrency(t *testing.T) {
	bh, err := NewBlackHole([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"})
	assert.NoError(t, err)

	const goroutines = 50
	const queriesPerGoroutine = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < queriesPerGoroutine; j++ {
				q := new(dns.Msg)
				q.SetQuestion("test.example.com.", dns.TypeA)
				qCtx := query_context.NewContext(q)
				err := bh.Exec(context.Background(), qCtx)
				assert.NoError(t, err)
				r := qCtx.R()
				assert.NotNil(t, r)
				assert.Equal(t, 4, len(r.Answer))
			}
		}()
	}
	wg.Wait()
}
