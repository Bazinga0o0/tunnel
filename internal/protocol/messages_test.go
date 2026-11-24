package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHelloRoundtrip(t *testing.T) {
	orig := &Hello{Token: "twbl_abc", ClientVersion: "0.1.0", OS: "linux"}
	raw, err := json.Marshal(Envelope{Type: TypeHello, Payload: mustMarshal(t, orig)})
	require.NoError(t, err)

	var env Envelope
	require.NoError(t, json.Unmarshal(raw, &env))
	assert.Equal(t, TypeHello, env.Type)

	var got Hello
	require.NoError(t, json.Unmarshal(env.Payload, &got))
	assert.Equal(t, *orig, got)
}

func TestHelloAckError(t *testing.T) {
	ack := &HelloAck{Error: "invalid token"}
	raw, err := json.Marshal(ack)
	require.NoError(t, err)

	var got HelloAck
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, "invalid token", got.Error)
	assert.Empty(t, got.SessionID)
}

func TestRegisterHTTPAckSuccess(t *testing.T) {
	ack := &RegisterHTTPAck{PublicURL: "https://abc.localhost", Subdomain: "abc"}
	raw, err := json.Marshal(ack)
	require.NoError(t, err)

	var got RegisterHTTPAck
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, "abc", got.Subdomain)
}

func TestRegisterTCPRoundtrip(t *testing.T) {
	orig := &RegisterTCP{Port: 12345}
	raw, err := json.Marshal(Envelope{Type: TypeRegisterTCP, Payload: mustMarshal(t, orig)})
	require.NoError(t, err)

	var env Envelope
	require.NoError(t, json.Unmarshal(raw, &env))
	assert.Equal(t, TypeRegisterTCP, env.Type)

	var got RegisterTCP
	require.NoError(t, json.Unmarshal(env.Payload, &got))
	assert.Equal(t, *orig, got)
}

func TestRegisterTCPAckSuccess(t *testing.T) {
	ack := &RegisterTCPAck{PublicAddr: "example.com:12345", Port: 12345}
	raw, err := json.Marshal(ack)
	require.NoError(t, err)

	var got RegisterTCPAck
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, 12345, got.Port)
	assert.Equal(t, "example.com:12345", got.PublicAddr)
}

func mustMarshal(t *testing.T, v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestRegisterUDPRoundtrip(t *testing.T) {
	orig := &RegisterUDP{Port: 7000}
	raw, err := json.Marshal(Envelope{Type: TypeRegisterUDP, Payload: mustMarshal(t, orig)})
	require.NoError(t, err)

	var env Envelope
	require.NoError(t, json.Unmarshal(raw, &env))
	assert.Equal(t, TypeRegisterUDP, env.Type)

	var got RegisterUDP
	require.NoError(t, json.Unmarshal(env.Payload, &got))
	assert.Equal(t, *orig, got)
}

func TestRegisterUDPZeroPortOmitted(t *testing.T) {
	raw, err := json.Marshal(&RegisterUDP{})
	require.NoError(t, err)
	assert.Equal(t, `{}`, string(raw))
}

func TestRegisterUDPAckSuccess(t *testing.T) {
	ack := &RegisterUDPAck{PublicAddr: "udp.game.example.com:7000", Port: 7000}
	raw, err := json.Marshal(ack)
	require.NoError(t, err)

	var got RegisterUDPAck
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, 7000, got.Port)
	assert.Equal(t, "udp.game.example.com:7000", got.PublicAddr)
	assert.Empty(t, got.Error)
}

func TestRegisterUDPAckError(t *testing.T) {
	ack := &RegisterUDPAck{Error: "port unavailable"}
	raw, err := json.Marshal(ack)
	require.NoError(t, err)

	var got RegisterUDPAck
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, "port unavailable", got.Error)
	assert.Zero(t, got.Port)
	assert.Empty(t, got.PublicAddr)
}
