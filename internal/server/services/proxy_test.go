package services

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/config"
)

const (
	goodToken = "tun_good-token"
	accountID = int64(42)
	email     = "real@example.com"
)

// fakeVerifier knows one token. It names the account with a refusal too:
// only the verdict may count.
type fakeVerifier struct{}

func (fakeVerifier) VerifyWithUser(_ context.Context, raw string) (int64, bool) {
	return accountID, raw == goodToken
}

// fakeEmails knows the address of the one account.
type fakeEmails struct{}

func (fakeEmails) LookupEmails(_ context.Context, ids []int64) (map[int64]string, error) {
	out := map[int64]string{}
	for _, id := range ids {
		if id == accountID {
			out[id] = email
		}
	}
	return out, nil
}

// upstream is the service behind the proxy. It reads the whole body and
// records what it got.
type upstream struct {
	mu       sync.Mutex
	requests int
	header   http.Header
	body     []int // length of each body read to its end
	url      string
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		u.mu.Lock()
		u.requests++
		u.header = r.Header.Clone()
		if err == nil {
			u.body = append(u.body, len(data))
		}
		u.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	u.url = srv.URL
	return u
}

func (u *upstream) snapshot() (requests int, header http.Header, bodies []int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.requests, u.header, append([]int(nil), u.body...)
}

// newTestProxy runs the proxy for up behind a plain HTTP server: the
// deadlines need a real connection.
func newTestProxy(t *testing.T, up *upstream, maxBody int64) (*proxy, string) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h, err := NewProxy(config.Service{
		Name: "myservice", Subdomain: "myservice", Upstream: up.url, MaxRequestBodyBytes: maxBody,
	}, fakeVerifier{}, fakeEmails{}, logger)
	require.NoError(t, err)
	p := h.(*proxy)
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return p, srv.URL
}

func do(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return res
}

// normalized is a header name in the form isIdentityHeader compares.
func normalized(key string) string { return strings.ToLower(strings.ReplaceAll(key, "_", "-")) }

// A client with a valid token cannot pass an identity of
// its own choosing, in no spelling and not as a second value.
func TestProxyPassesVerifiedIdentityOnly(t *testing.T) {
	up := newUpstream(t)
	_, front := newTestProxy(t, up, 0)

	req, err := http.NewRequest(http.MethodGet, front+"/v1/me", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+goodToken)
	req.Header.Add("X-Tunnel-Account-Email", "evil@x")
	req.Header.Add("X-Tunnel-Account-Email", "evil2@x")
	req.Header["X_Tunnel_Account_Id"] = []string{"1"}
	req.Header["x-tunnel-account-id"] = []string{"2"}
	req.Header["X-Tunnel_Account-Email"] = []string{"evil3@x"}
	req.Header.Set("X-Real-Ip", "203.0.113.9")
	req.Header["X_Forwarded_For"] = []string{"203.0.113.9"}
	res := do(t, req)
	require.Equal(t, http.StatusOK, res.StatusCode)

	n, h, _ := up.snapshot()
	require.Equal(t, 1, n)
	assert.Equal(t, []string{"42"}, h.Values("X-Tunnel-Account-Id"))
	assert.Equal(t, []string{email}, h.Values("X-Tunnel-Account-Email"))
	for key := range h {
		switch normalized(key) {
		case "x-tunnel-account-id", "x-tunnel-account-email":
			assert.Contains(t, []string{"X-Tunnel-Account-Id", "X-Tunnel-Account-Email"}, key, "client spelling %q reached the service", key)
		case "authorization":
			t.Errorf("the service got the Authorization header %q", key)
		case "x-real-ip":
			t.Errorf("the service got the client's %q", key)
		case "x-forwarded-for":
			assert.Equal(t, "X-Forwarded-For", key, "client spelling %q reached the service", key)
		}
	}
	assert.Equal(t, "127.0.0.1", h.Get("X-Forwarded-For"), "the client address comes from the connection")
}

func TestProxyRejectsBadToken(t *testing.T) {
	up := newUpstream(t)
	_, front := newTestProxy(t, up, 0)

	for name, auth := range map[string][]string{
		"none":            nil,
		"wrong token":     {"Bearer tun_wrong"},
		"empty token":     {"Bearer "},
		"other scheme":    {"Basic " + goodToken},
		"token alone":     {goodToken},
		"second header":   {"Bearer tun_wrong", "Bearer " + goodToken},
		"good then wrong": {"Bearer " + goodToken, "Bearer tun_wrong"},
	} {
		req, err := http.NewRequest(http.MethodPost, front+"/v1/runs", strings.NewReader("payload"))
		require.NoError(t, err)
		for _, v := range auth {
			req.Header.Add("Authorization", v)
		}
		res := do(t, req)
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode, name)
		assert.Equal(t, "Bearer", res.Header.Get("WWW-Authenticate"), name)
	}
	n, _, _ := up.snapshot()
	assert.Zero(t, n, "no refused request reaches the service")
}

// onlyReader hides the length of its reader: the client sends the body
// chunked, the proxy learns its size only by reading it.
type onlyReader struct{ io.Reader }

func TestProxyEnforcesBodyLimit(t *testing.T) {
	const limit = 1024
	up := newUpstream(t)
	_, front := newTestProxy(t, up, limit)

	post := func(body io.Reader) *http.Response {
		req, err := http.NewRequest(http.MethodPost, front+"/v1/upload", body)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+goodToken)
		return do(t, req)
	}
	over := strings.Repeat("x", 2*limit)
	assert.Equal(t, http.StatusRequestEntityTooLarge, post(strings.NewReader(over)).StatusCode, "announced length")
	n, _, _ := up.snapshot()
	assert.Zero(t, n, "a body announced over the limit is refused before the service is asked")
	assert.Equal(t, http.StatusRequestEntityTooLarge, post(onlyReader{strings.NewReader(over)}).StatusCode, "chunked")
	_, _, bodies := up.snapshot()
	assert.Empty(t, bodies, "the service never gets a whole body over the limit")

	assert.Equal(t, http.StatusOK, post(onlyReader{strings.NewReader(over[:limit])}).StatusCode, "at the limit")
	_, _, bodies = up.snapshot()
	assert.Equal(t, []int{limit}, bodies)
}

// trickle sends size bytes in steps over d through a pipe.
func trickle(t *testing.T, size int, d time.Duration) io.Reader {
	t.Helper()
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	const steps = 15
	go func() {
		chunk := strings.Repeat("x", size/steps)
		for i := 0; i < steps; i++ {
			time.Sleep(d / steps)
			if _, err := pw.Write([]byte(chunk)); err != nil {
				return
			}
		}
		_ = pw.Close()
	}()
	return onlyReader{pr}
}

// A large upload over a slow line must not be cut by the
// proxy's deadline; one that takes longer than the deadline is.
func TestProxySlowUploadWithinDeadline(t *testing.T) {
	up := newUpstream(t)
	p, front := newTestProxy(t, up, 0)
	p.timeout = 2 * time.Second

	post := func(body io.Reader) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodPost, front+"/v1/upload", body)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+goodToken)
		res, err := http.DefaultClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}
		return res, err
	}

	res, err := post(trickle(t, 1500, 1500*time.Millisecond))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	_, _, bodies := up.snapshot()
	assert.Equal(t, []int{1500}, bodies, "the service got the whole body")

	res, err = post(trickle(t, 1500, 3*time.Second))
	if err == nil {
		assert.NotEqual(t, http.StatusOK, res.StatusCode, "a body slower than the deadline is cut")
	}
	_, _, bodies = up.snapshot()
	assert.Equal(t, []int{1500}, bodies, "the slow body did not reach the service whole")
}

// No request switches protocols: after the switch the client would talk to
// the service directly, past the identity headers, the body limit and the
// deadlines. The refusal also ends the connection.
func TestProxyRefusesProtocolUpgrade(t *testing.T) {
	up := newUpstream(t)
	_, front := newTestProxy(t, up, 0)
	addr := strings.TrimPrefix(front, "http://")

	const auth = "Authorization: Bearer " + goodToken + "\r\n"
	for name, head := range map[string]string{
		"websocket": "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
		"h2c":                     "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n",
		"upgrade among options":   "Connection: keep-alive, Upgrade\r\n",
		"HTTP2-Settings alone":    "HTTP2-Settings: AAMAAABkAAQAAP__\r\n",
		"upgrade in another case": "Connection: UPGRADE\r\n",
	} {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		require.NoError(t, err)
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		_, err = conn.Write([]byte("GET /v1/live HTTP/1.1\r\nHost: myservice.tunnel.test\r\n" + auth + head + "\r\n"))
		require.NoError(t, err)
		res, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err, name)
		_ = res.Body.Close()
		_ = conn.Close()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode, name)
		assert.True(t, res.Close, "%s: the refusal ends the connection", name)
	}
	n, _, _ := up.snapshot()
	assert.Zero(t, n, "no upgrade request reaches the service")
}

// stuckVerifier answers only when its context ends, as a token check on a
// database that does not answer.
type stuckVerifier struct{}

func (stuckVerifier) VerifyWithUser(ctx context.Context, _ string) (int64, bool) {
	<-ctx.Done()
	return 0, false
}

// stuckEmails answers only when its context ends.
type stuckEmails struct{}

func (stuckEmails) LookupEmails(ctx context.Context, _ []int64) (map[int64]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A token check or account lookup that does not answer is given up after
// the proxy's check deadline with 503: the token may be valid, 401 would
// tell the client it is not.
func TestProxyGivesUpAStuckIdentityCheck(t *testing.T) {
	for name, deps := range map[string]struct {
		v Verifier
		e EmailLookup
	}{
		"token check":    {stuckVerifier{}, fakeEmails{}},
		"account lookup": {fakeVerifier{}, stuckEmails{}},
	} {
		t.Run(name, func(t *testing.T) {
			up := newUpstream(t)
			h, err := NewProxy(config.Service{Name: "myservice", Subdomain: "myservice", Upstream: up.url},
				deps.v, deps.e, slog.New(slog.NewTextHandler(io.Discard, nil)))
			require.NoError(t, err)
			p := h.(*proxy)
			p.checkTimeout = 100 * time.Millisecond
			srv := httptest.NewServer(p)
			t.Cleanup(srv.Close)

			req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/me", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+goodToken)
			client := &http.Client{Timeout: 5 * time.Second}
			start := time.Now()
			res, err := client.Do(req)
			require.NoError(t, err, "the proxy answers without waiting for the client to give up")
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
			assert.Empty(t, res.Header.Get("WWW-Authenticate"), "not a refusal of the token")
			assert.Less(t, time.Since(start), 3*time.Second)
			n, _, _ := up.snapshot()
			assert.Zero(t, n, "the request does not reach the service")
		})
	}
}

// X-Forwarded-Host is the public host in the form the server routes on:
// lower case, without a port and without a trailing dot, whatever the
// client wrote.
func TestProxyForwardsTheNormalizedHost(t *testing.T) {
	up := newUpstream(t)
	_, front := newTestProxy(t, up, 0)

	for _, host := range []string{"myservice.tunnel.test", "MyService.Tunnel.Test.:443", "myservice.tunnel.test:8443"} {
		req, err := http.NewRequest(http.MethodGet, front+"/v1/me", nil)
		require.NoError(t, err)
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+goodToken)
		req.Header.Set("X-Forwarded-Host", "evil.example")
		res := do(t, req)
		require.Equal(t, http.StatusOK, res.StatusCode, host)
		_, h, _ := up.snapshot()
		assert.Equal(t, []string{"myservice.tunnel.test"}, h.Values("X-Forwarded-Host"), host)
	}
}
