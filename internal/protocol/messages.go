// Package protocol defines the wire protocol between tunnel client and server.
package protocol

import "encoding/json"

// MessageType identifies a control-plane message.
type MessageType string

const (
	TypeHello           MessageType = "hello"
	TypeHelloAck        MessageType = "hello_ack"
	TypeRegisterHTTP    MessageType = "register_http"
	TypeRegisterHTTPAck MessageType = "register_http_ack"
	TypeRegisterTCP     MessageType = "register_tcp"
	TypeRegisterTCPAck  MessageType = "register_tcp_ack"
	TypeRegisterUDP     MessageType = "register_udp"
	TypeRegisterUDPAck  MessageType = "register_udp_ack"
	TypePing            MessageType = "ping"
	TypePong            MessageType = "pong"
	TypeShutdown        MessageType = "shutdown"
)

// Envelope wraps every control message for dispatch.
type Envelope struct {
	Type    MessageType     `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Hello: client → server, initial auth + capability exchange.
type Hello struct {
	Token         string `json:"token"`
	ClientVersion string `json:"client_version"`
	OS            string `json:"os"`
}

// HelloAck: server → client, either success (SessionID set) or error (Error set).
type HelloAck struct {
	SessionID     string `json:"session_id,omitempty"`
	ServerVersion string `json:"server_version,omitempty"`
	Error         string `json:"error,omitempty"`
}

// RegisterHTTP: client → server, request an HTTP tunnel.
// Subdomain empty → server picks random.
type RegisterHTTP struct {
	Subdomain string `json:"subdomain,omitempty"`
}

// RegisterHTTPAck: server → client, result of registration.
type RegisterHTTPAck struct {
	PublicURL string `json:"public_url,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
	Error     string `json:"error,omitempty"`
}

// RegisterTCP: client → server, request a TCP tunnel.
// Port 0 → server picks from the configured pool.
type RegisterTCP struct {
	Port int `json:"port,omitempty"`
}

// RegisterTCPAck: server → client, result of TCP registration.
type RegisterTCPAck struct {
	PublicAddr string `json:"public_addr,omitempty"`
	Port       int    `json:"port,omitempty"`
	Error      string `json:"error,omitempty"`
}

// RegisterUDP: client → server, request a UDP tunnel.
// Port 0 → server picks from the configured UDP pool.
type RegisterUDP struct {
	Port int `json:"port,omitempty"`
}

// RegisterUDPAck: server → client, result of UDP registration.
type RegisterUDPAck struct {
	PublicAddr string `json:"public_addr,omitempty"`
	Port       int    `json:"port,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Shutdown: server → client, graceful close signal.
type Shutdown struct {
	Reason string `json:"reason"`
}
