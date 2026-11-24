package protocol

import "net"

// PipeStream creates an in-process duplex Stream pair backed by net.Pipe.
// Both ends satisfy net.Conn (and therefore io.ReadWriteCloser), which is
// what the Stream interface requires. Useful for tests.
func PipeStream() (Stream, Stream) {
	a, b := net.Pipe()
	return a, b
}
