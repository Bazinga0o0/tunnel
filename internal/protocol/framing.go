package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// WriteFrame writes a uint32-BE length prefix followed by payload bytes.
func WriteFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if len(payload) == 0 {
		return nil
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// MaxDatagramSize caps any single UDP payload carried inside a yamux UDP
// stream. The on-wire length prefix is uint16-BE, so values above 65535 are
// not representable. We pin the cap to that limit (rather than the real UDP
// maximum of 65507) so the check matches the wire format exactly.
const MaxDatagramSize = 65535

// ErrDatagramTooLarge is returned by WriteDatagram when the payload exceeds
// MaxDatagramSize, and by ReadDatagram if a wire length somehow overflows
// MaxDatagramSize (defensive — uint16 cannot encode it, but kept so callers
// can rely on a single sentinel for size violations).
var ErrDatagramTooLarge = errors.New("datagram too large")

// WriteDatagram writes a uint16-BE length prefix followed by payload bytes.
// Empty payloads are valid (just the two-byte zero prefix).
func WriteDatagram(w io.Writer, payload []byte) error {
	if len(payload) > MaxDatagramSize {
		return ErrDatagramTooLarge
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write datagram length: %w", err)
	}
	if len(payload) == 0 {
		return nil
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write datagram payload: %w", err)
	}
	return nil
}

// ReadDatagram reads one length-prefixed datagram. If scratch is non-nil and
// at least as large as the incoming payload, the returned slice aliases into
// scratch (no allocation). Otherwise a fresh slice is allocated.
//
// A length of zero returns (nil, nil) without touching scratch.
func ReadDatagram(r io.Reader, scratch []byte) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read datagram length: %w", err)
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return nil, nil
	}
	if n > MaxDatagramSize {
		return nil, ErrDatagramTooLarge
	}
	var buf []byte
	if cap(scratch) >= n {
		buf = scratch[:n]
	} else {
		buf = make([]byte, n)
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read datagram payload: %w", err)
	}
	return buf, nil
}

// ReadFrame reads one length-prefixed frame. maxSize guards against DoS.
func ReadFrame(r io.Reader, maxSize uint32) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxSize {
		return nil, fmt.Errorf("frame too large: %d > %d", n, maxSize)
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	return buf, nil
}
