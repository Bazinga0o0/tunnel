package config

import "fmt"

// Upper bounds of the keys that size an allocation, so that a typo such as
// accept_backlog: 100000000 cannot make the server allocate without bound.
const (
	// maxAcceptBacklog is yamux's own default backlog. The backlog is a
	// queue made for every session before login, and apart from the control
	// stream a client may not open streams at all.
	maxAcceptBacklog = 256
	// maxFlowBufferSize bounds the datagram queue made for every UDP flow
	// when it starts (24 bytes a slot). What waits in it is bounded by
	// edge.udp.max_queued_bytes_per_flow anyway, and 256 slots (6 KiB) stay
	// well within what the memory budget counts for a flow
	// (edgeudp.FlowMemoryBytes).
	maxFlowBufferSize = 256
	// maxHeaderBytes is net/http's own default limit for a request head,
	// 1 MiB. The memory budget counts one and a half times max_header_bytes
	// for every public connection.
	maxHeaderBytes = 1 << 20
	// maxMailQueueSize bounds the mail queue made at start-up. A waiting
	// mail holds its rendered text, a few KiB.
	maxMailQueueSize = 4096
	// maxServiceRequestBody bounds services[].max_request_body_bytes: 256 MiB
	// (zero selects 64 MiB).
	maxServiceRequestBody = 268435456
)

// validateBounds refuses the values above the upper bounds.
func (c *Config) validateBounds() error {
	switch {
	case c.Tunnel.AcceptBacklog > maxAcceptBacklog:
		return fmt.Errorf("config: tunnel.accept_backlog must be at most %d", maxAcceptBacklog)
	case c.UDP.FlowBufferSize > maxFlowBufferSize:
		return fmt.Errorf("config: udp.flow_buffer_size must be at most %d", maxFlowBufferSize)
	case c.HTTPServer.MaxHeaderBytes > maxHeaderBytes:
		return fmt.Errorf("config: http_server.max_header_bytes must be at most %d", maxHeaderBytes)
	case c.Mail.QueueSize > maxMailQueueSize:
		return fmt.Errorf("config: mail.queue_size must be at most %d", maxMailQueueSize)
	}
	return nil
}
