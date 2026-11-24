package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// StreamType identifies the payload kind of a data stream.
type StreamType string

const (
	StreamTypeHTTP StreamType = "http"
	StreamTypeTCP  StreamType = "tcp"
	StreamTypeUDP  StreamType = "udp"
)

// StreamHeader is the first frame of every data stream opened by the server.
type StreamHeader struct {
	StreamType   StreamType `json:"stream_type"`
	OriginalHost string     `json:"original_host,omitempty"`
	RemoteIP     string     `json:"remote_ip,omitempty"`
	RemotePort   int        `json:"remote_port,omitempty"` // UDP: source port of the public peer.
	Scheme       string     `json:"scheme,omitempty"`
	PublicPort   int        `json:"public_port,omitempty"`
	FlowID       uint64     `json:"flow_id,omitempty"` // UDP: server-assigned, non-zero, unique per flow.
}

// maxStreamHeaderSize bounds the JSON encoding of a StreamHeader in both
// directions: WriteStreamHeader refuses to send more, ReadStreamHeader refuses
// to read more.
const maxStreamHeaderSize = 4096

// maxPort is the highest valid TCP or UDP port number.
const maxPort = 65535

// ErrInvalidStreamHeader is returned by ReadStreamHeader and
// StreamHeader.Validate for a header whose content is not acceptable.
var ErrInvalidStreamHeader = errors.New("invalid stream header")

// ErrStreamHeaderTooLarge is returned by WriteStreamHeader when the encoded
// header exceeds the size the peer is willing to read.
var ErrStreamHeaderTooLarge = errors.New("stream header too large")

// Validate checks the content of a header: the stream type must be one of the
// known types, the port fields must be valid port numbers (0 means "not
// set"), and RemoteIP, when set, must be an IP address.
//
// The returned error wraps ErrInvalidStreamHeader. It names the offending
// field but never repeats its value, because the value comes from the peer
// and the error usually ends up in a log.
func (h *StreamHeader) Validate() error {
	switch h.StreamType {
	case StreamTypeHTTP, StreamTypeTCP, StreamTypeUDP:
	default:
		return fmt.Errorf("%w: unknown stream type", ErrInvalidStreamHeader)
	}
	if h.RemotePort < 0 || h.RemotePort > maxPort {
		return fmt.Errorf("%w: remote port out of range", ErrInvalidStreamHeader)
	}
	if h.PublicPort < 0 || h.PublicPort > maxPort {
		return fmt.Errorf("%w: public port out of range", ErrInvalidStreamHeader)
	}
	if h.RemoteIP != "" {
		if _, err := netip.ParseAddr(h.RemoteIP); err != nil {
			return fmt.Errorf("%w: remote ip is not an ip address", ErrInvalidStreamHeader)
		}
	}
	return nil
}

// WriteStreamHeader writes the header as a length-prefixed JSON frame. It
// returns ErrStreamHeaderTooLarge, without writing anything, when the encoded
// header is larger than ReadStreamHeader accepts.
func WriteStreamHeader(w io.Writer, h *StreamHeader) error {
	b, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("marshal stream header: %w", err)
	}
	if len(b) > maxStreamHeaderSize {
		return ErrStreamHeaderTooLarge
	}
	return WriteFrame(w, b)
}

// ReadStreamHeader reads a length-prefixed JSON-encoded StreamHeader and
// validates it (see StreamHeader.Validate).
func ReadStreamHeader(r io.Reader) (*StreamHeader, error) {
	raw, err := ReadFrame(r, maxStreamHeaderSize)
	if err != nil {
		return nil, err
	}
	var h StreamHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("unmarshal stream header: %w", err)
	}
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return &h, nil
}
