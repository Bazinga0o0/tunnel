package protocol

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamHeaderRoundtrip(t *testing.T) {
	orig := &StreamHeader{
		StreamType:   StreamTypeHTTP,
		OriginalHost: "abc.localhost",
		RemoteIP:     "1.2.3.4",
		Scheme:       "https",
	}
	var buf bytes.Buffer
	require.NoError(t, WriteStreamHeader(&buf, orig))

	got, err := ReadStreamHeader(&buf)
	require.NoError(t, err)
	assert.Equal(t, orig, got)
}

func TestStreamHeaderUDPRoundtrip(t *testing.T) {
	orig := &StreamHeader{
		StreamType: StreamTypeUDP,
		RemoteIP:   "1.2.3.4",
		RemotePort: 54321,
		PublicPort: 7000,
		FlowID:     0xdeadbeef,
	}
	var buf bytes.Buffer
	require.NoError(t, WriteStreamHeader(&buf, orig))

	got, err := ReadStreamHeader(&buf)
	require.NoError(t, err)
	assert.Equal(t, orig, got)
}

func TestStreamHeaderHTTPUnaffectedByNewFields(t *testing.T) {
	orig := &StreamHeader{
		StreamType:   StreamTypeHTTP,
		OriginalHost: "abc.localhost",
		RemoteIP:     "1.2.3.4",
		Scheme:       "https",
	}
	var buf bytes.Buffer
	require.NoError(t, WriteStreamHeader(&buf, orig))

	got, err := ReadStreamHeader(&buf)
	require.NoError(t, err)
	assert.Equal(t, orig, got)
	assert.Zero(t, got.RemotePort)
	assert.Zero(t, got.FlowID)
}

func TestStreamHeaderUDPOmitsZeroFields(t *testing.T) {
	h := &StreamHeader{StreamType: StreamTypeUDP}
	var buf bytes.Buffer
	require.NoError(t, WriteStreamHeader(&buf, h))

	// Skip the 4-byte length prefix added by WriteFrame.
	raw := buf.Bytes()[4:]
	assert.JSONEq(t, `{"stream_type":"udp"}`, string(raw))
}
