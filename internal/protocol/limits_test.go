package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeRawHeader frames an arbitrary JSON document the way a peer would,
// bypassing WriteStreamHeader so that invalid headers can reach the reader.
func writeRawHeader(t *testing.T, doc string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, WriteFrame(&buf, []byte(doc)))
	return &buf
}

func TestReadStreamHeaderRejectsInvalidContent(t *testing.T) {
	cases := map[string]string{
		"unknown stream type":     `{"stream_type":"smtp"}`,
		"missing stream type":     `{"remote_ip":"1.2.3.4"}`,
		"stream type wrong case":  `{"stream_type":"HTTP"}`,
		"remote port above range": `{"stream_type":"udp","remote_port":65536}`,
		"remote port negative":    `{"stream_type":"udp","remote_port":-1}`,
		"public port above range": `{"stream_type":"tcp","public_port":70000}`,
		"public port negative":    `{"stream_type":"tcp","public_port":-5}`,
		"remote ip not an ip":     `{"stream_type":"tcp","remote_ip":"not-an-ip"}`,
		"remote ip with port":     `{"stream_type":"tcp","remote_ip":"1.2.3.4:80"}`,
		"remote ip is a hostname": `{"stream_type":"http","remote_ip":"example.com"}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			h, err := ReadStreamHeader(writeRawHeader(t, doc))
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidStreamHeader)
			assert.Nil(t, h)
		})
	}
}

func TestReadStreamHeaderAcceptsValidContent(t *testing.T) {
	cases := map[string]string{
		"http without remote ip": `{"stream_type":"http","original_host":"abc.localhost"}`,
		"tcp ipv4":               `{"stream_type":"tcp","remote_ip":"203.0.113.9","public_port":65535}`,
		"udp ipv6":               `{"stream_type":"udp","remote_ip":"2001:db8::1","remote_port":1,"public_port":1,"flow_id":7}`,
		"ipv6 with zone":         `{"stream_type":"tcp","remote_ip":"fe80::1%eth0","public_port":2000}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			h, err := ReadStreamHeader(writeRawHeader(t, doc))
			require.NoError(t, err)
			require.NotNil(t, h)
		})
	}
}

// The error text must not carry the peer-supplied value: it ends up in logs.
func TestReadStreamHeaderErrorOmitsPeerText(t *testing.T) {
	marker := strings.Repeat("Z", 200)
	doc, err := json.Marshal(map[string]any{"stream_type": marker})
	require.NoError(t, err)

	_, err = ReadStreamHeader(writeRawHeader(t, string(doc)))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "ZZZZ")
}

func TestWriteStreamHeaderBoundsSize(t *testing.T) {
	h := &StreamHeader{
		StreamType:   StreamTypeHTTP,
		OriginalHost: strings.Repeat("a", 4096),
	}
	var buf bytes.Buffer
	err := WriteStreamHeader(&buf, h)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStreamHeaderTooLarge)
	assert.Zero(t, buf.Len(), "nothing may be written when the header is too large")
}

// A header that WriteStreamHeader accepts must be readable again: the write
// bound and the read bound are the same number.
func TestWriteStreamHeaderLargestAcceptedIsReadable(t *testing.T) {
	// {"stream_type":"http","original_host":"<host>"} costs 41 bytes around
	// the host, so a host of 4055 bytes gives a header of exactly 4096 bytes.
	h := &StreamHeader{
		StreamType:   StreamTypeHTTP,
		OriginalHost: strings.Repeat("a", 4055),
	}
	var buf bytes.Buffer
	require.NoError(t, WriteStreamHeader(&buf, h))
	require.Equal(t, 4+4096, buf.Len(), "test must sit exactly on the bound")

	got, err := ReadStreamHeader(&buf)
	require.NoError(t, err)
	assert.Equal(t, h.OriginalHost, got.OriginalHost)

	h.OriginalHost += "a"
	buf.Reset()
	assert.ErrorIs(t, WriteStreamHeader(&buf, h), ErrStreamHeaderTooLarge)
}

// sessionPair returns a connected client and server session over loopback TCP.
func sessionPair(t *testing.T, opts ServerOptions) (client, server Session) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	acc := <-ch
	require.NoError(t, acc.err)

	server, err = NewServerSessionWithOptions(acc.conn, opts)
	require.NoError(t, err)
	client, err = NewClientSession(clientConn)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// wasReset reports whether the server reset the stream: a read fails with
// something other than its own (very short) deadline.
func wasReset(t *testing.T, s Stream) bool {
	t.Helper()
	d, ok := s.(interface{ SetReadDeadline(time.Time) error })
	require.True(t, ok)
	require.NoError(t, d.SetReadDeadline(time.Now().Add(2*time.Millisecond)))
	_, err := s.Read(make([]byte, 1))
	require.Error(t, err)
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

// countResetStreams opens n client streams that the server never accepts and
// reports how many of them the server reset.
//
// It does not wait a fixed time. It polls until every stream is accounted
// for: the server either holds it (it is live on the server's side, waiting
// in the backlog) or has reset it (the client sees that). Both numbers only
// reach their sum n when the server has worked through all n streams.
func countResetStreams(t *testing.T, client, server Session, n int) int {
	t.Helper()
	held, ok := server.(StreamCounter)
	require.True(t, ok)

	pending := make([]Stream, 0, n)
	for i := 0; i < n; i++ {
		s, err := client.OpenStream()
		require.NoError(t, err)
		pending = append(pending, s)
	}

	reset := 0
	giveUp := time.Now().Add(15 * time.Second)
	for {
		waiting := pending[:0]
		for _, s := range pending {
			if wasReset(t, s) {
				reset++
			} else {
				waiting = append(waiting, s)
			}
		}
		pending = waiting
		onServer := held.NumStreams()
		if onServer+reset == n {
			return reset
		}
		require.True(t, time.Now().Before(giveUp),
			"of %d streams the server holds %d and reset %d", n, onServer, reset)
		time.Sleep(5 * time.Millisecond)
	}
}

// The accept backlog holds streams the client opened and the server has not
// accepted. With the frame guard's stream rule a client can open only the
// control stream, so the backlog tests switch the rule off (PeerStreams: -1).
func TestServerSessionDefaultAcceptBacklog(t *testing.T) {
	client, server := sessionPair(t, ServerOptions{PeerStreams: -1})
	// 32 is the default; 40 streams leave 8 over.
	assert.Equal(t, 8, countResetStreams(t, client, server, 40), "streams beyond the default backlog of 32 must be reset")
}

func TestServerSessionDefaultAcceptBacklogAdmitsExactly32(t *testing.T) {
	client, server := sessionPair(t, ServerOptions{PeerStreams: -1})
	assert.Zero(t, countResetStreams(t, client, server, 32), "32 waiting streams fit into the default backlog")
}

func TestServerSessionExplicitAcceptBacklog(t *testing.T) {
	client, server := sessionPair(t, ServerOptions{AcceptBacklog: 4, PeerStreams: -1})
	assert.Equal(t, 6, countResetStreams(t, client, server, 10))
}

func TestServerSessionNegativeAcceptBacklogKeepsYamuxDefault(t *testing.T) {
	client, server := sessionPair(t, ServerOptions{AcceptBacklog: -1, PeerStreams: -1})
	assert.Zero(t, countResetStreams(t, client, server, 40),
		"a negative backlog disables the reduced limit of 32")
}

// NewServerSession uses the default options: among them the frame guard,
// which ends the connection at the client's second stream.
func TestNewServerSessionUsesTheDefaults(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	serverConn := <-ch
	require.NotNil(t, serverConn)

	server, err := NewServerSession(serverConn)
	require.NoError(t, err)
	defer server.Close()
	client, err := NewClientSession(clientConn)
	require.NoError(t, err)
	defer client.Close()

	_, err = client.OpenStream()
	require.NoError(t, err)
	_, err = server.AcceptStream()
	require.NoError(t, err, "the control stream")
	_, err = client.OpenStream()
	require.NoError(t, err)
	_, err = server.AcceptStream()
	require.ErrorIs(t, err, ErrSecondStream)
}

func TestSessionCountsLiveStreams(t *testing.T) {
	client, server := sessionPair(t, ServerOptions{PeerStreams: -1}) // two client streams
	counter, ok := server.(StreamCounter)
	require.True(t, ok, "server sessions must report their live stream count")
	assert.Zero(t, counter.NumStreams())

	s1, err := client.OpenStream()
	require.NoError(t, err)
	s2, err := client.OpenStream()
	require.NoError(t, err)
	require.Eventually(t, func() bool { return counter.NumStreams() == 2 }, 15*time.Second, 10*time.Millisecond)

	// Both ends must close before the stream stops counting.
	a1, err := server.AcceptStream()
	require.NoError(t, err)
	require.NoError(t, s1.Close())
	assert.Equal(t, 2, counter.NumStreams(), "a half-closed stream is still live")
	require.NoError(t, a1.Close())
	require.Eventually(t, func() bool { return counter.NumStreams() == 1 }, 15*time.Second, 10*time.Millisecond)
	_ = s2
}

// StreamCloseTimeout replaces yamux's five minutes after which a stream the
// server closed is removed although the client never answered with a FIN.
func TestServerSessionStreamCloseTimeout(t *testing.T) {
	client, server := sessionPair(t, ServerOptions{StreamCloseTimeout: 100 * time.Millisecond})
	ctrl, err := client.OpenStream()
	require.NoError(t, err)
	_, err = ctrl.Write([]byte("x"))
	require.NoError(t, err)
	st, err := server.AcceptStream()
	require.NoError(t, err)
	counter := server.(StreamCounter)
	require.Equal(t, 1, counter.NumStreams())
	require.NoError(t, st.Close()) // the client keeps its side open
	require.Eventually(t, func() bool { return counter.NumStreams() == 0 }, 2*time.Second, 10*time.Millisecond,
		"the stream the client kept open is still registered")
}
