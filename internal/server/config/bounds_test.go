package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---- keys that size an allocation have an upper bound ----

func TestKeysThatSizeAnAllocationAreCapped(t *testing.T) {
	cases := map[string]struct{ ok, over, key string }{
		"accept backlog": {"tunnel:\n  accept_backlog: 256\n", "tunnel:\n  accept_backlog: 257\n", "tunnel.accept_backlog"},
		"udp flow buffer": {"udp:\n  enabled: true\n  flow_buffer_size: 256\n",
			"udp:\n  enabled: true\n  flow_buffer_size: 257\n", "udp.flow_buffer_size"},
		"request head": {"http_server:\n  max_header_bytes: 1048576\n", "http_server:\n  max_header_bytes: 1048577\n",
			"http_server.max_header_bytes"},
		"mail queue": {"mail:\n  queue_size: 4096\n", "mail:\n  queue_size: 4097\n", "mail.queue_size"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mustLoad(t, staticBase+tc.ok)
			err := requireRefused(t, staticBase+tc.over, tc.key)
			assert.Contains(t, err.Error(), "at most")
		})
	}
	// A typo with a few extra digits.
	requireRefused(t, staticBase+"tunnel:\n  accept_backlog: 100000000\n", "tunnel.accept_backlog")
	// Zero still selects the default, negative still disables the backlog
	// limit (yamux keeps its own 256).
	mustLoad(t, staticBase+"tunnel:\n  accept_backlog: 0\n")
	mustLoad(t, staticBase+"tunnel:\n  accept_backlog: -1\n")
}
