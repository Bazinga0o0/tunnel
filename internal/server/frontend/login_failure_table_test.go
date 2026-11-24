package frontend

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failureTableKeys lists the keys of the per-account failure table in the
// order of its clock (front first), and the credit of each.
func failureTableKeys(l *rateLimiter) (keys []string, credits []int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for el := l.order.Front(); el != nil; el = el.Next() {
		e := el.Value.(*rlEntry)
		keys = append(keys, e.key)
		credits = append(credits, e.credit)
	}
	return keys, credits
}

// clientGone makes a request look like one whose client closed the
// connection after sending it: its context has ended.
func clientGone(r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	*r = *r.WithContext(ctx)
}

// Logins that end without counting (the client went away, the server could
// not decide, the password was right) must leave the per-account failure
// table as if they had never been made. Otherwise they rotate the table's
// clock for free and bring a locked account to the front, where one counted
// failure erases one of its failures. The "rotate" strategy against the
// real handler: the table full of junk addresses, the
// victim at its limit; each round sends a given-back login for every entry
// in front of the victim (one client address, cancelled contexts) and then
// one counted failure for a new address.
func TestGivenBackLoginsDoNotMoveTheFailureTable(t *testing.T) {
	const k = 8
	s := newStack(t, func(o *Options, _ *stack) { o.RateLimitMaxKeys = k }) // 10 failures per account
	s.createUser(t, "victim@example.com", "pw12345678")
	s.createUser(t, "junk-1@example.com", "pw12345678") // one junk address is an account the attacker owns
	lim := limitersOf(t, s.h)
	hashes := countHashesOf(t, "short-pw-1", "guess-password-1")
	cheap := strings.Repeat("x", 1025)
	victim := accountKey("victim@example.com")

	peer := 0
	nextPeer := func() string { peer++; return fmt.Sprintf("198.51.100.%d:1", peer) }
	junk := 0
	addrOf := map[string]string{}
	newJunk := func() {
		junk++
		addr := fmt.Sprintf("junk-%d@example.com", junk)
		addrOf[accountKey(addr)] = addr
		require.Equal(t, http.StatusUnauthorized, s.login(t, nextPeer(), addr, cheap).Code)
	}
	for i := 0; i < k-1; i++ {
		newJunk()
	}
	vp := nextPeer()
	for i := 0; i < 10; i++ {
		require.Equal(t, http.StatusUnauthorized, s.login(t, vp, "victim@example.com", cheap).Code)
	}
	require.Equal(t, k, lim.loginAccount.size())
	before, beforeCredits := failureTableKeys(lim.loginAccount)

	const rotator = "203.0.113.7:1"
	free := 0
	// Free logins alone change nothing at all: order and credit stay.
	for _, key := range before {
		if key == victim {
			continue
		}
		w := postFormFrom(t, s.h, nil, "/login", url.Values{"email": {addrOf[key]}, "password": {"short-pw-1"}}, rotator, clientGone)
		require.NotEqual(t, http.StatusUnauthorized, w.Code, "given back, not counted")
		free++
	}
	// A successful login of the owned junk account is given back too.
	require.Equal(t, http.StatusSeeOther, s.login(t, "203.0.113.8:1", "junk-1@example.com", "pw12345678").Code)
	after, afterCredits := failureTableKeys(lim.loginAccount)
	assert.Equal(t, before, after, "logins that were given back moved entries")
	assert.Equal(t, beforeCredits, afterCredits, "logins that were given back changed credit")

	// The attack in rounds: free logins for every entry in front of the
	// victim, then one counted failure.
	for round := 0; round < 10; round++ {
		keys, _ := failureTableKeys(lim.loginAccount)
		for _, key := range keys {
			if key == victim {
				break
			}
			if addr, ok := addrOf[key]; ok {
				postFormFrom(t, s.h, nil, "/login", url.Values{"email": {addr}, "password": {"short-pw-1"}}, rotator, clientGone)
				free++
			}
		}
		newJunk()
	}
	assert.Equal(t, 10, lim.loginAccount.count(victim), "10 counted failures and %d free logins must not erase the victim's failures", free)
	w := s.login(t, nextPeer(), "victim@example.com", "guess-password-1")
	require.Equal(t, http.StatusTooManyRequests, w.Code, "the victim's next guess is still refused")
	assert.Zero(t, hashes["guess-password-1"].Load())
	assert.Zero(t, hashes["short-pw-1"].Load(), "the free logins never hashed")
	assert.Zero(t, lim.loginIP.count(sourceKey(clientIP(&http.Request{RemoteAddr: rotator}))), "nothing counted against the rotating address")
}

// heldListener hands out each connection it accepts only when the test
// sends on release. A client that has sent its request and closed its end
// before that is read by the server as the request followed by the end of
// the connection, whatever the scheduling.
type heldListener struct {
	net.Listener
	release chan struct{}
	done    chan struct{} // closed when the test ends
}

func (l *heldListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	select {
	case <-l.release:
		return c, nil
	case <-l.done:
		_ = c.Close()
		return nil, net.ErrClosed
	}
}

// The same over a real socket: a client sends a login and closes its
// connection at once. The login is given back, and the table is as before.
//
// The logins go one at a time, each served before the next is sent: they
// all come from one address, which may have only DefaultHashPerIP requests
// with hash work in flight, and logins served at the same time would refuse
// each other at that bound, before the take of the per-account table. And
// each connection reaches the server only after its client has closed it:
// the server sees the client gone before the password check, as it does
// whenever the close arrives first, and not only when the scheduling of the
// test lets it.
func TestClosedConnectionLoginsDoNotMoveTheFailureTable(t *testing.T) {
	const k = 8
	s := newStack(t, func(o *Options, _ *stack) { o.RateLimitMaxKeys = k })
	lim := limitersOf(t, s.h)
	hashes := countHashesOf(t, "short-pw-1")
	cheap := strings.Repeat("x", 1025)
	addrOf := map[string]string{}
	for i := 1; i <= k; i++ {
		addr := fmt.Sprintf("junk-%d@example.com", i)
		addrOf[accountKey(addr)] = addr
		require.Equal(t, http.StatusUnauthorized, s.login(t, fmt.Sprintf("198.51.100.%d:1", i), addr, cheap).Code)
	}
	srv := httptest.NewUnstartedServer(s.h)
	held := &heldListener{Listener: srv.Listener, release: make(chan struct{}), done: make(chan struct{})}
	srv.Listener = held
	srv.Start()
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(held.done) }) // runs before srv.Close
	token, csrfCookie := getCSRF(t, s.h, nil, "/login")
	before, beforeCredits := failureTableKeys(lim.loginAccount)
	takenBefore := lim.loginAccount.pendingsTaken()

	const logins = 20
	for n := 0; n < logins; n++ {
		keys, _ := failureTableKeys(lim.loginAccount)
		addr := addrOf[keys[n%len(keys)]]
		body := url.Values{"email": {addr}, "password": {"short-pw-1"}, "gorilla.csrf.Token": {token}}.Encode()
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		require.NoError(t, err)
		fmt.Fprintf(c, "POST /login HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nCookie: %s=%s\r\n\r\n%s",
			srv.Listener.Addr().String(), len(body), csrfCookie.Name, csrfCookie.Value, body)
		require.NoError(t, c.Close()) // the client goes away at once
		select {
		case held.release <- struct{}{}:
		case <-time.After(10 * time.Second):
			t.Fatalf("the server did not accept login %d", n+1)
		}
		require.Eventually(t, func() bool {
			return lim.loginAccount.pendingsTaken() == takenBefore+n+1 && hashBoundOf(t, s.h).size() == 0
		}, 10*time.Second, time.Millisecond, "login %d did not get as far as the per-account table's take, or is still in flight", n+1)
	}
	// Every login must have got as far as the take of the per-account
	// table (otherwise the assertions below would hold for logins refused
	// earlier, or not served at all), and none may still be in flight.
	require.Eventually(t, func() bool {
		return lim.loginAccount.pendingsTaken() == takenBefore+logins && hashBoundOf(t, s.h).size() == 0
	}, 10*time.Second, 10*time.Millisecond, "the logins reached the per-account table's take: %d of %d",
		lim.loginAccount.pendingsTaken()-takenBefore, logins)
	require.Eventually(t, func() bool {
		for key := range addrOf {
			if lim.loginAccount.count(key) != 1 {
				return false
			}
		}
		return true
	}, 5*time.Second, 10*time.Millisecond, "the logins were given back")
	after, afterCredits := failureTableKeys(lim.loginAccount)
	assert.Equal(t, before, after, "closed-connection logins moved entries")
	assert.Equal(t, beforeCredits, afterCredits)
	for key := range addrOf {
		assert.LessOrEqual(t, lim.loginAccount.count(key), 1, "nothing was counted")
	}
	assert.Zero(t, hashes["short-pw-1"].Load())
}
