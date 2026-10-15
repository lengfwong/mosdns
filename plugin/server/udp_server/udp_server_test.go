package udp_server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgsInit(t *testing.T) {
	a := new(Args)
	a.init()
	assert.Equal(t, "127.0.0.1:53", a.Listen)
}
