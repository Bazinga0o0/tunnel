package protocol

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestYamuxSessionOverPipe(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	serverSession, err := NewServerSession(serverConn)
	require.NoError(t, err)
	defer serverSession.Close()

	clientSession, err := NewClientSession(clientConn)
	require.NoError(t, err)
	defer clientSession.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := serverSession.AcceptStream()
		require.NoError(t, err)
		defer stream.Close()

		buf := make([]byte, 5)
		_, err = stream.Read(buf)
		require.NoError(t, err)
		require.Equal(t, "hello", string(buf))

		_, err = stream.Write([]byte("world"))
		require.NoError(t, err)
	}()

	stream, err := clientSession.OpenStream()
	require.NoError(t, err)
	defer stream.Close()

	_, err = stream.Write([]byte("hello"))
	require.NoError(t, err)

	buf := make([]byte, 5)
	_, err = stream.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "world", string(buf))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}
