package http_server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgsInit(t *testing.T) {
	a := new(Args)
	a.init()
	assert.Equal(t, 30, a.IdleTimeout)
}
