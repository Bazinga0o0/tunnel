package frontend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
)

// Passwords with these prefixes control the password-hash operations they
// reach (holdHashes): holdPrefix parks the operation inside its slot of the
// process-wide limit until the test releases it, panicPrefix makes it panic.
const (
	holdPrefix  = "hold-"
	panicPrefix = "panic-"
)

// hashHold parks the hash operations of passwords with holdPrefix.
type hashHold struct {
	entered chan string
	release chan struct{}
	once    sync.Once
}

// holdHashes installs the KDF hook for the rest of the test.
func holdHashes(t *testing.T) *hashHold {
	t.Helper()
	h := &hashHold{entered: make(chan string, 64), release: make(chan struct{})}
	restore := auth.SetKDFHookForTesting(func(password string) {
		switch {
		case strings.HasPrefix(password, holdPrefix):
			h.entered <- password
			<-h.release
		case strings.HasPrefix(password, panicPrefix):
			panic("injected KDF panic")
		}
	})
	t.Cleanup(func() {
		h.releaseAll()
		restore()
	})
	return h
}

func (h *hashHold) releaseAll() { h.once.Do(func() { close(h.release) }) }

// waitEntered blocks until n parked operations have started.
func (h *hashHold) waitEntered(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-h.entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d password hashes started", i, n)
		}
	}
}

// useHashLimits installs process-wide hash limits for one test.
func useHashLimits(t *testing.T, l auth.HashLimits) {
	t.Helper()
	auth.SetHashLimits(l)
	t.Cleanup(func() { auth.SetHashLimits(auth.HashLimits{}) })
}

// serveAll serves every request in its own goroutine and delivers the
// answers in the order they finish.
func serveAll(h http.Handler, reqs []*http.Request) <-chan *httptest.ResponseRecorder {
	out := make(chan *httptest.ResponseRecorder, len(reqs))
	for _, r := range reqs {
		go func(r *http.Request) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			out <- w
		}(r)
	}
	return out
}

// hashBoundOf returns the per-address bound of a handler built by New.
func hashBoundOf(t *testing.T, h http.Handler) *hashBound {
	t.Helper()
	return limitersOf(t, h).hashes
}

// One address keeps sending requests that hash, in each of the three ways
// a request can cause hash work. It holds at most two of the four process-wide slots; the
// rest of its requests are refused at once with 429, and a login from
// another address still gets a slot.
func TestOneAddressCannotHoldEveryHashSlot(t *testing.T) {
	const (
		attackerPeer  = "203.0.113.50:1000"
		bystanderPeer = "198.51.100.200:1000"
		requests      = 6
	)
	ways := []struct {
		name string
		// requests builds the attacker's requests; the users exist then and
		// the KDF hook is not installed yet.
		requests func(t *testing.T, s *stack) []*http.Request
		// held is the status each of the two parked requests ends with.
		held []int
	}{
		{
			name: "password change with a wrong current password",
			requests: func(t *testing.T, s *stack) []*http.Request {
				sc := doSignup(t, s.h, "attacker@example.com", "pw12345678")
				var reqs []*http.Request
				for i := 0; i < requests; i++ {
					reqs = append(reqs, newFormPost(t, s.h, sc, "/settings/password", url.Values{
						"current": {holdPrefix + "wrong-current"}, "new": {"new-password-1"}, "confirm": {"new-password-1"},
					}, attackerPeer))
				}
				return reqs
			},
			held: []int{http.StatusUnauthorized, http.StatusUnauthorized},
		},
		{
			name: "logins with the correct password",
			requests: func(t *testing.T, s *stack) []*http.Request {
				s.createUser(t, "attacker@example.com", holdPrefix+"attacker-pw")
				var reqs []*http.Request
				for i := 0; i < requests; i++ {
					reqs = append(reqs, newFormPost(t, s.h, nil, "/login", url.Values{
						"email": {"attacker@example.com"}, "password": {holdPrefix + "attacker-pw"},
					}, attackerPeer))
				}
				return reqs
			},
			held: []int{http.StatusSeeOther, http.StatusSeeOther},
		},
		{
			name: "password resets with one valid token",
			requests: func(t *testing.T, s *stack) []*http.Request {
				s.createUser(t, "attacker@example.com", "pw12345678")
				raw, _, _, err := s.reset.IssueWithAddress(context.Background(), "attacker@example.com")
				require.NoError(t, err)
				require.NotEmpty(t, raw)
				var reqs []*http.Request
				for i := 0; i < requests; i++ {
					reqs = append(reqs, newFormPost(t, s.h, nil, "/reset", url.Values{
						"token": {raw}, "new": {holdPrefix + "reset-pw"}, "confirm": {holdPrefix + "reset-pw"},
					}, attackerPeer))
				}
				return reqs
			},
			// One uses the link up, the other finds it used.
			held: []int{http.StatusSeeOther, http.StatusBadRequest},
		},
	}
	for _, way := range ways {
		t.Run(way.name, func(t *testing.T) {
			s := newStack(t, withMail)
			s.createUser(t, "bystander@example.com", "pw12345678")
			reqs := way.requests(t, s)

			// Four slots; a request that finds none waits half a second.
			useHashLimits(t, auth.HashLimits{MaxConcurrent: 4, MaxWait: 500 * time.Millisecond})
			hold := holdHashes(t)
			answers := serveAll(s.h, reqs)
			hold.waitEntered(t, 2)

			// The other four are refused at once, while the two are parked.
			for i := 0; i < requests-2; i++ {
				select {
				case w := <-answers:
					require.Equal(t, http.StatusTooManyRequests, w.Code, "refused request %d: %s", i+1, w.Body.String())
					assert.Contains(t, w.Body.String(), msgHashBusy)
					assert.Equal(t, "1", w.Header().Get("Retry-After"))
				case <-time.After(5 * time.Second):
					t.Fatalf("request over the bound did not come back at once (%d answered)", i)
				}
			}
			select {
			case pw := <-hold.entered:
				t.Fatalf("a third hash of the same address started (%s)", pw)
			default:
			}
			assert.Equal(t, 1, hashBoundOf(t, s.h).size(), "one address in flight")

			// Another address logs in: there is a free slot for it.
			w := s.login(t, bystanderPeer, "bystander@example.com", "pw12345678")
			require.Equal(t, http.StatusSeeOther, w.Code, "the login of another address: %s", w.Body.String())

			hold.releaseAll()
			var got []int
			for i := 0; i < 2; i++ {
				select {
				case w := <-answers:
					got = append(got, w.Code)
				case <-time.After(10 * time.Second):
					t.Fatal("a parked request did not finish")
				}
			}
			assert.ElementsMatch(t, way.held, got)
			assert.Zero(t, hashBoundOf(t, s.h).size(), "every slot of the address was given back")
		})
	}
}

// hashPath is one web path that hashes, with a way to send a request whose
// hash sees the given password.
type hashPath struct {
	name string
	send func(t *testing.T, password string) *httptest.ResponseRecorder
}

// hashPaths returns the web paths that hash a password, on one handler:
// login, sign-up, reset confirmation, settings password, admin re-entry
// (promote and demote) and admin-set password. Every request comes from
// peer.
func hashPaths(t *testing.T, e *adminTestEnv, s *stack, peer string) []hashPath {
	t.Helper()
	ctx := context.Background()
	sc := doSignup(t, s.h, "settings-user@example.com", "pw12345678")
	// A reset logs its account out: it gets an account of its own.
	s.createUser(t, "reset-user@example.com", "pw12345678")
	target := e.insertUser(t, "target@example.com", true)
	base := "/admin/users/" + itoa(target)
	adminPost := func(path string, form url.Values) *httptest.ResponseRecorder {
		token, csrfCookie := getCSRF(t, e.h, nil, "/login")
		form.Set("gorilla.csrf.Token", token)
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = peer
		req.AddCookie(csrfCookie)
		req.AddCookie(e.adminCookie)
		return serve(e.h, req)
	}
	signups := 0
	return []hashPath{
		{"login", func(t *testing.T, pw string) *httptest.ResponseRecorder {
			return postFormFrom(t, s.h, nil, "/login", url.Values{"email": {"nobody@example.com"}, "password": {pw}}, peer)
		}},
		{"signup", func(t *testing.T, pw string) *httptest.ResponseRecorder {
			signups++
			email := "new" + itoa(int64(signups)) + "@example.com"
			return postFormFrom(t, s.h, nil, "/signup", url.Values{"email": {email}, "password": {pw}}, peer)
		}},
		{"reset confirmation", func(t *testing.T, pw string) *httptest.ResponseRecorder {
			raw, _, _, err := s.reset.IssueWithAddress(ctx, "reset-user@example.com")
			require.NoError(t, err)
			return postFormFrom(t, s.h, nil, "/reset", url.Values{"token": {raw}, "new": {pw}, "confirm": {pw}}, peer)
		}},
		{"settings password", func(t *testing.T, pw string) *httptest.ResponseRecorder {
			return postFormFrom(t, s.h, sc, "/settings/password", url.Values{
				"current": {pw}, "new": {"new-password-1"}, "confirm": {"new-password-1"},
			}, peer)
		}},
		{"admin re-entry (promote)", func(t *testing.T, pw string) *httptest.ResponseRecorder {
			return adminPost(base+"/promote", url.Values{"current_password": {pw}})
		}},
		{"admin re-entry (demote)", func(t *testing.T, pw string) *httptest.ResponseRecorder {
			return adminPost(base+"/demote", url.Values{"current_password": {pw}})
		}},
		{"admin-set password", func(t *testing.T, pw string) *httptest.ResponseRecorder {
			// The admin's password is right; the hash that sees pw is the one
			// of the new password, the second hash of the same request.
			return adminPost(base+"/reset-password", url.Values{"current_password": {adminTestPassword}, "new_password": {pw}})
		}},
	}
}

// newHashPathEnv builds one handler with every service, mail and a logged-in
// admin, and returns it both as the admin tests see it and as a stack.
func newHashPathEnv(t *testing.T, configure ...func(*Options)) (*adminTestEnv, *stack) {
	t.Helper()
	s := newStack(t, withMail, withAudit, func(o *Options, _ *stack) {
		for _, c := range configure {
			c(o)
		}
	})
	e := &adminTestEnv{
		pool: s.pool, h: s.h, users: s.users, tokens: s.tokens, res: s.res,
		sessions: s.sess, reg: s.reg, audit: s.audit,
	}
	ctx := context.Background()
	e.adminID = s.createUser(t, "admin@example.com", adminTestPassword)
	require.NoError(t, s.users.MarkEmailVerified(ctx, e.adminID))
	require.NoError(t, s.users.Promote(ctx, e.adminID))
	e.adminCookie = e.login(t, e.adminID)
	return e, s
}

func TestHashBoundIsGivenBackOnEveryPath(t *testing.T) {
	const peer = "203.0.113.60:1000"
	e, s := newHashPathEnv(t)
	paths := hashPaths(t, e, s, peer)
	bound := hashBoundOf(t, e.h)

	t.Run("normal answers", func(t *testing.T) {
		for _, p := range paths {
			w := p.send(t, "some-password-123")
			assert.Less(t, w.Code, 500, "%s: %d %s", p.name, w.Code, w.Body.String())
			assert.Zero(t, bound.size(), p.name)
		}
	})
	t.Run("a panic in the hash", func(t *testing.T) {
		holdHashes(t)
		for _, p := range paths {
			w := p.send(t, panicPrefix+"password-123")
			assert.Equal(t, http.StatusInternalServerError, w.Code, p.name)
			assert.Zero(t, bound.size(), p.name)
		}
	})
	t.Run("no free hash slot", func(t *testing.T) {
		useHashLimits(t, auth.HashLimits{MaxConcurrent: 1, MaxWait: 50 * time.Millisecond})
		hold := holdHashes(t)
		go func() { _, _ = auth.HashPasswordContext(context.Background(), holdPrefix+"the-only-slot") }()
		hold.waitEntered(t, 1)
		for _, p := range paths {
			w := p.send(t, "some-password-123")
			assert.Equal(t, http.StatusServiceUnavailable, w.Code, p.name)
			assert.Zero(t, bound.size(), p.name)
		}
	})
}

func TestHashBoundAppliesToEveryPath(t *testing.T) {
	const peer = "203.0.113.70:1000"
	e, s := newHashPathEnv(t, func(o *Options) { o.HashPerIP = 1 })
	paths := hashPaths(t, e, s, peer)
	hold := holdHashes(t)

	// One login of the address is parked in its hash: the address has used
	// its one slot, and every path refuses it at once.
	parked := make(chan int, 1)
	go func() {
		parked <- postFormFrom(t, s.h, nil, "/login", url.Values{"email": {"nobody@example.com"}, "password": {holdPrefix + "x1"}}, peer).Code
	}()
	hold.waitEntered(t, 1)
	for _, p := range paths {
		w := p.send(t, "some-password-123")
		assert.Equal(t, http.StatusTooManyRequests, w.Code, p.name)
		assert.Contains(t, w.Body.String(), "at the same time", p.name)
		assert.Equal(t, "1", w.Header().Get("Retry-After"), p.name)
	}
	// Another address is not affected.
	w := postFormFrom(t, s.h, nil, "/login", url.Values{"email": {"nobody@example.com"}, "password": {"wrong-password"}}, "203.0.113.71:1000")
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	hold.releaseAll()
	assert.Equal(t, http.StatusUnauthorized, <-parked)
	assert.Zero(t, hashBoundOf(t, e.h).size())
}

func TestHashBoundOptions(t *testing.T) {
	assert.Equal(t, 2, newRateLimiters(Options{}).hashes.limit, "zero selects the default")
	assert.Equal(t, 5, newRateLimiters(Options{HashPerIP: 5}).hashes.limit)
	assert.LessOrEqual(t, newRateLimiters(Options{HashPerIP: -1}).hashes.limit, 0, "negative disables")
	assert.Equal(t, DefaultRateLimitMaxKeys, newRateLimiters(Options{}).hashes.maxKeys)
	assert.Equal(t, 7, newRateLimiters(Options{RateLimitMaxKeys: 7}).hashes.maxKeys)
}

func TestHashBound(t *testing.T) {
	t.Run("at most limit per key, keys are dropped at zero", func(t *testing.T) {
		b := newHashBound(2, 0)
		r1, ok := b.take("a")
		require.True(t, ok)
		r2, ok := b.take("a")
		require.True(t, ok)
		_, ok = b.take("a")
		require.False(t, ok, "a third slot for the same key")
		rb, ok := b.take("b")
		require.True(t, ok, "another key has its own slots")
		assert.Equal(t, 2, b.size())

		r1()
		r1() // a second call gives nothing back
		_, ok = b.take("a")
		require.True(t, ok, "the given-back slot is free again")
		_, ok = b.take("a")
		require.False(t, ok, "the double release did not free a second slot")
		r2()
		rb()
		assert.Equal(t, 1, b.size(), "b is gone, a holds one slot")
	})
	t.Run("a full table refuses a new key", func(t *testing.T) {
		b := newHashBound(2, 2)
		ra, _ := b.take("a")
		_, ok := b.take("b")
		require.True(t, ok)
		_, ok = b.take("c")
		require.False(t, ok, "the table is full")
		_, ok = b.take("a")
		require.True(t, ok, "a key in the table can take its second slot")
		ra()
		_, ok = b.take("c")
		require.False(t, ok, "a still holds a slot")
	})
	t.Run("no limit", func(t *testing.T) {
		b := newHashBound(0, 1)
		for i := 0; i < 5; i++ {
			release, ok := b.take("a")
			require.True(t, ok)
			defer release()
		}
		assert.Zero(t, b.size(), "nothing is recorded without a limit")
	})
	t.Run("concurrent takes and releases", func(t *testing.T) {
		b := newHashBound(2, 0)
		var wg sync.WaitGroup
		var mu sync.Mutex
		held, peak := 0, 0
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				release, ok := b.take("k")
				if !ok {
					return
				}
				mu.Lock()
				held++
				if held > peak {
					peak = held
				}
				mu.Unlock()
				time.Sleep(time.Millisecond)
				mu.Lock()
				held--
				mu.Unlock()
				release()
			}()
		}
		wg.Wait()
		assert.LessOrEqual(t, peak, 2)
		assert.Zero(t, b.size())
	})
}
