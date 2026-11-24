package frontend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/audit"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	"github.com/Bazinga0o0/tunnel/internal/server/passwordreset"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
	"github.com/Bazinga0o0/tunnel/internal/server/verifications"
)

// stack is a handler with every service wired to the test database, a fake
// clock for the rate limiters, and the services for direct checks.
type stack struct {
	pool   *pgxpool.Pool
	users  *users.Service
	tokens *tokens.Service
	res    *reservations.Service
	sess   *sessions.Service
	reg    *registry.Registry
	mailer *mail.TestMailer
	verif  *verifications.Service
	reset  *passwordreset.Service
	audit  *audit.Service
	clock  *fakeClock
	opts   Options
	h      http.Handler
}

// newStack builds a stack. mutate may change the options before the
// handler is built; withMail is one such function.
func newStack(t *testing.T, mutate ...func(*Options, *stack)) *stack {
	t.Helper()
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	s := &stack{pool: pool, clock: newFakeClock(), mailer: mail.NewTestMailer()}
	s.users = users.NewService(pool)
	s.tokens = tokens.NewService(pool)
	s.res = reservations.NewService(pool)
	s.sess = sessions.NewService(pool)
	s.reg = registry.New()
	s.verif = verifications.NewService(pool, s.users)
	s.reset = passwordreset.NewService(pool, s.users, s.sess)
	s.audit = audit.NewService(pool)
	s.opts = Options{
		Domain:       "tunnel.localhost",
		Users:        s.users,
		Tokens:       s.tokens,
		Reservations: s.res,
		Sessions:     s.sess,
		Registry:     s.reg,
		CSRFKey:      testCSRFKey,
		now:          s.clock.Now,
	}
	for _, m := range mutate {
		m(&s.opts, s)
	}
	s.h = New(s.opts)
	closeAtCleanup(t, s.h)
	return s
}

// withMail wires the mailer, email verification and password reset.
func withMail(o *Options, s *stack) {
	o.Mailer = s.mailer
	o.Verifications = s.verif
	o.PasswordReset = s.reset
	o.PublicBaseURL = "https://app.tunnel.localhost"
}

// withAudit wires the audit log.
func withAudit(o *Options, s *stack) { o.Audit = s.audit }

// post sends a form POST from the peer address with a CSRF token that the
// same peer fetched first, as the user with session cookie sc (nil: no
// session).
func (s *stack) post(t *testing.T, peer, path string, form url.Values, sc *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	return postFormFrom(t, s.h, sc, path, form, peer)
}

func (s *stack) login(t *testing.T, peer, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	return s.post(t, peer, "/login", url.Values{"email": {email}, "password": {password}}, nil)
}

func (s *stack) createUser(t *testing.T, email, password string) int64 {
	t.Helper()
	u, err := s.users.Create(context.Background(), email, password)
	require.NoError(t, err)
	return u.ID
}

func retryAfterSeconds(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	v := w.Header().Get("Retry-After")
	require.NotEmpty(t, v, "Retry-After must be set")
	n, err := strconv.Atoi(v)
	require.NoError(t, err)
	return n
}

func TestLoginRateLimitPerIP(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) { o.LoginFailuresPerIP = 3 })
	s.createUser(t, "known@example.com", "pw12345678")

	const peerA = "198.51.100.10:1000"
	for i := 0; i < 3; i++ {
		w := s.login(t, peerA, fmt.Sprintf("nobody%d@example.com", i), "wrong-password")
		require.Equal(t, http.StatusUnauthorized, w.Code, "failure %d", i+1)
	}

	// Over the limit even the right password is refused, before any check.
	w := s.login(t, peerA, "known@example.com", "pw12345678")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "Too many failed login attempts")
	assert.Contains(t, w.Body.String(), `action="/login"`, "the generic login page")
	assert.Positive(t, retryAfterSeconds(t, w))
	assert.Nil(t, findCookie(w, "tunneld_session"))

	// Headers do not move a client into another bucket.
	w = postFormFrom(t, s.h, nil, "/login", url.Values{"email": {"known@example.com"}, "password": {"pw12345678"}}, peerA,
		func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "203.0.113.200")
			r.Header.Set("X-Real-IP", "203.0.113.201")
			r.Header.Set("True-Client-IP", "203.0.113.202")
		})
	require.Equal(t, http.StatusTooManyRequests, w.Code, "X-Forwarded-For must not change the client")

	// Another client is not affected.
	w = s.login(t, "198.51.100.11:1000", "known@example.com", "pw12345678")
	require.Equal(t, http.StatusSeeOther, w.Code)

	// IPv6 clients are grouped by /64.
	for i := 0; i < 3; i++ {
		w = s.login(t, fmt.Sprintf("[2001:db8:1:2::%x]:443", i+1), "nobody@example.com", "wrong-password")
		require.Equal(t, http.StatusUnauthorized, w.Code)
	}
	w = s.login(t, "[2001:db8:1:2:ffff::1]:443", "known@example.com", "pw12345678")
	require.Equal(t, http.StatusTooManyRequests, w.Code, "same /64")
	w = s.login(t, "[2001:db8:1:3::1]:443", "known@example.com", "pw12345678")
	require.Equal(t, http.StatusSeeOther, w.Code, "another /64")

	// After the window the client may try again.
	s.clock.Advance(15*time.Minute + time.Second)
	w = s.login(t, peerA, "known@example.com", "pw12345678")
	require.Equal(t, http.StatusSeeOther, w.Code)
}

func TestLoginRateLimitPerAccount(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) { o.LoginFailuresPerAccount = 2 })
	s.createUser(t, "victim@example.com", "pw12345678")
	s.createUser(t, "other@example.com", "pw12345678")

	require.Equal(t, http.StatusUnauthorized, s.login(t, "198.51.100.20:1", "victim@example.com", "guess-1").Code)
	require.Equal(t, http.StatusUnauthorized, s.login(t, "198.51.100.21:1", "victim@example.com", "guess-2").Code)

	// The account is closed for logins from every client, whatever the case
	// of the address.
	for _, email := range []string{"victim@example.com", " VICTIM@example.com "} {
		w := s.login(t, "198.51.100.22:1", email, "pw12345678")
		require.Equal(t, http.StatusTooManyRequests, w.Code, email)
		assert.Contains(t, w.Body.String(), "Too many failed login attempts")
		assert.Positive(t, retryAfterSeconds(t, w))
	}
	// Other accounts are not.
	require.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.22:1", "other@example.com", "pw12345678").Code)

	// An address without an account is limited the same way, so the limit
	// tells nothing about which addresses exist.
	require.Equal(t, http.StatusUnauthorized, s.login(t, "198.51.100.23:1", "ghost@example.com", "x1").Code)
	require.Equal(t, http.StatusUnauthorized, s.login(t, "198.51.100.24:1", "ghost@example.com", "x2").Code)
	require.Equal(t, http.StatusTooManyRequests, s.login(t, "198.51.100.25:1", "ghost@example.com", "x3").Code)

	s.clock.Advance(15*time.Minute + time.Second)
	require.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.22:1", "victim@example.com", "pw12345678").Code)
}

func TestSuccessfulLoginsDoNotCount(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) {
		o.LoginFailuresPerIP = 2
		o.LoginFailuresPerAccount = 2
	})
	s.createUser(t, "often@example.com", "pw12345678")
	for i := 0; i < 4; i++ {
		require.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.30:1", "often@example.com", "pw12345678").Code, "login %d", i+1)
	}
	// A refused login (empty password) is no failed password check either.
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusBadRequest, s.login(t, "198.51.100.30:1", "often@example.com", "").Code)
	}
	require.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.30:1", "often@example.com", "pw12345678").Code)
}

func TestSignupRateLimitPerIP(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) { o.SignupsPerIP = 2 })
	const peerA = "198.51.100.40:1"
	signup := func(peer, email string) *httptest.ResponseRecorder {
		return s.post(t, peer, "/signup", url.Values{"email": {email}, "password": {"pw12345678"}}, nil)
	}
	exists := func(email string) bool {
		_, err := s.users.FindByEmail(context.Background(), email)
		if errors.Is(err, users.ErrNotFound) {
			return false
		}
		require.NoError(t, err)
		return true
	}

	// Attempts the form already refuses do not count.
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusBadRequest, signup(peerA, "not-an-address").Code)
	}
	require.Equal(t, http.StatusSeeOther, signup(peerA, "a1@example.com").Code)
	require.Equal(t, http.StatusSeeOther, signup(peerA, "a2@example.com").Code)

	w := signup(peerA, "a3@example.com")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "Too many sign-up attempts")
	assert.Contains(t, w.Body.String(), `action="/signup"`)
	assert.Positive(t, retryAfterSeconds(t, w))
	assert.False(t, exists("a3@example.com"), "a refused signup creates nothing")

	// The address of the client decides, not a header.
	w = postFormFrom(t, s.h, nil, "/signup", url.Values{"email": {"a3@example.com"}, "password": {"pw12345678"}}, peerA,
		func(r *http.Request) { r.Header.Set("X-Forwarded-For", "203.0.113.5") })
	require.Equal(t, http.StatusTooManyRequests, w.Code)

	require.Equal(t, http.StatusSeeOther, signup("198.51.100.41:1", "a3@example.com").Code)
	assert.True(t, exists("a3@example.com"))

	s.clock.Advance(time.Hour + time.Second)
	require.Equal(t, http.StatusSeeOther, signup(peerA, "a4@example.com").Code)
}

func TestResetRequestRateLimits(t *testing.T) {
	s := newStack(t, withMail)
	s.createUser(t, "reset-me@example.com", "pw12345678")
	forgot := func(peer, email string, extra ...func(*http.Request)) *httptest.ResponseRecorder {
		return postFormFrom(t, s.h, nil, "/forgot-password", url.Values{"email": {email}}, peer, extra...)
	}
	const generic = "If an account with that email exists"

	t.Run("3 per client and hour", func(t *testing.T) {
		const peer = "198.51.100.50:1"
		for i := 0; i < 3; i++ {
			w := forgot(peer, fmt.Sprintf("unknown%d@example.com", i))
			require.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), generic)
		}
		w := forgot(peer, "reset-me@example.com")
		require.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), generic, "the generic page")
		assert.Positive(t, retryAfterSeconds(t, w))
		assert.Empty(t, s.mailer.Sent(), "no mail over the limit")

		// Headers do not help.
		for i := 0; i < 2; i++ {
			w = forgot(peer, "unknown@example.com", func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i+1))
			})
			require.Equal(t, http.StatusTooManyRequests, w.Code)
		}
	})
	t.Run("3 per account and hour", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			w := forgot(fmt.Sprintf("198.51.100.%d:1", 60+i), "reset-me@example.com")
			require.Equal(t, http.StatusOK, w.Code)
		}
		require.Len(t, s.mailer.Sent(), 3)
		w := forgot("198.51.100.70:1", "RESET-ME@example.com")
		require.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), generic)
		require.Len(t, s.mailer.Sent(), 3, "no fourth mail")
	})
	t.Run("IPv6 clients are grouped by /64", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			require.Equal(t, http.StatusOK, forgot(fmt.Sprintf("[2001:db8:5:6::%x]:1", i+1), "v6@example.com").Code)
		}
		require.Equal(t, http.StatusTooManyRequests, forgot("[2001:db8:5:6::ff]:1", "v6b@example.com").Code)
		require.Equal(t, http.StatusOK, forgot("[2001:db8:5:7::1]:1", "v6b@example.com").Code)
	})
	t.Run("after the window", func(t *testing.T) {
		s.clock.Advance(time.Hour + time.Second)
		require.Equal(t, http.StatusOK, forgot("198.51.100.50:1", "reset-me@example.com").Code)
		require.Len(t, s.mailer.Sent(), 4)
	})
}

func TestSignupAnswersTheSameWhetherOrNotTheAddressExists(t *testing.T) {
	s := newStack(t, withMail)
	s.createUser(t, "taken@example.com", "original-pw1")

	fresh := s.post(t, "198.51.100.80:1", "/signup", url.Values{"email": {"new@example.com"}, "password": {"pw12345678"}}, nil)
	taken := s.post(t, "198.51.100.81:1", "/signup", url.Values{"email": {"Taken@Example.com"}, "password": {"other-pw123"}}, nil)

	require.Equal(t, http.StatusSeeOther, fresh.Code)
	assert.Equal(t, fresh.Code, taken.Code)
	assert.Equal(t, "/login?signup=1", fresh.Header().Get("Location"))
	assert.Equal(t, fresh.Header().Get("Location"), taken.Header().Get("Location"))
	assert.Equal(t, fresh.Body.String(), taken.Body.String())
	for _, w := range []*httptest.ResponseRecorder{fresh, taken} {
		assert.Nil(t, findCookie(w, "tunneld_session"), "signup does not log in")
	}

	// The new account exists and can log in.
	require.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.82:1", "new@example.com", "pw12345678").Code)

	// The existing account is unchanged.
	_, err := s.users.Authenticate(context.Background(), "taken@example.com", "original-pw1")
	require.NoError(t, err)
	_, err = s.users.Authenticate(context.Background(), "taken@example.com", "other-pw123")
	require.ErrorIs(t, err, users.ErrInvalidCredentials)

	sent := s.mailer.Sent()
	require.Len(t, sent, 2)
	byTo := map[string]mail.Message{}
	for _, m := range sent {
		byTo[m.To] = m
	}
	require.Contains(t, byTo, "new@example.com")
	assert.Contains(t, byTo["new@example.com"].Subject, "Verify")
	notice, ok := byTo["taken@example.com"]
	require.True(t, ok, "the owner of the existing account is told, at the stored address: %v", sent)
	assert.Contains(t, notice.Subject, "Sign-up attempt")
	assert.Contains(t, notice.TextBody, "already")
	assert.Contains(t, notice.TextBody, "https://app.tunnel.localhost/forgot-password")
	assert.NotContains(t, notice.TextBody, "token=", "the notice carries no token")
}

func TestSignupWithTakenAddressSpendsOneDummyVerification(t *testing.T) {
	var calls []string
	s := newStack(t, func(o *Options, _ *stack) {
		o.dummyVerify = func(_ context.Context, password string) error {
			calls = append(calls, password)
			return nil
		}
	})
	s.createUser(t, "owner@example.com", "pw12345678")

	// A new account pays for its password hash in users.Create.
	require.Equal(t, http.StatusSeeOther, s.post(t, "198.51.100.97:1", "/signup",
		url.Values{"email": {"brand-new@example.com"}, "password": {"pw12345678"}}, nil).Code)
	assert.Empty(t, calls, "no dummy verification for a new account")

	// A taken address costs no hash in users.Create; the handler spends one
	// verification of the typed password instead.
	require.Equal(t, http.StatusSeeOther, s.post(t, "198.51.100.98:1", "/signup",
		url.Values{"email": {"Owner@example.com"}, "password": {"typed-password"}}, nil).Code)
	assert.Equal(t, []string{"typed-password"}, calls)
}

func TestSignupFieldErrors(t *testing.T) {
	s := newStack(t)
	cases := []struct {
		email, password, want string
	}{
		{"not-an-address", "pw12345678", "valid email address"},
		{"Name <a@example.com>", "pw12345678", "valid email address"},
		{"a@example.com\r\nBcc: x@example.com", "pw12345678", "valid email address"},
		{"short@example.com", "äääääää", "at least 8 characters"}, // 7 characters, 14 bytes
	}
	for _, c := range cases {
		w := s.post(t, "198.51.100.90:1", "/signup", url.Values{"email": {c.email}, "password": {c.password}}, nil)
		require.Equal(t, http.StatusBadRequest, w.Code, c.email)
		assert.Contains(t, w.Body.String(), c.want, c.email)
	}
	n, err := s.users.CountAll(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n)

	// Eight characters are enough, however many bytes they take.
	w := s.post(t, "198.51.100.90:1", "/signup", url.Values{"email": {"umlaut@example.com"}, "password": {"ääääääää"}}, nil)
	require.Equal(t, http.StatusSeeOther, w.Code)
}

func TestResetMailGoesToTheStoredAddress(t *testing.T) {
	s := newStack(t, withMail)
	s.createUser(t, "mixed@example.com", "pw12345678")
	w := postFormFrom(t, s.h, nil, "/forgot-password", url.Values{"email": {"MIXED@Example.COM"}}, "198.51.100.95:1")
	require.Equal(t, http.StatusOK, w.Code)
	sent := s.mailer.Sent()
	require.Len(t, sent, 1)
	assert.Equal(t, "mixed@example.com", sent[0].To, "never the spelling the client typed")
}

// limitersOf returns the rate limiters of a handler built by New.
func limitersOf(t *testing.T, h http.Handler) *rateLimiters {
	t.Helper()
	fh, ok := h.(*frontendHandler)
	require.True(t, ok, "handler built by New")
	return fh.limiters
}

// A full table of failed logins per account refuses nobody and does not let
// a cheap flood push a locked account out: it makes room by failures. A
// flood of new typed addresses with one failure each, several times the
// table, pushes out other junk while the account at its limit keeps its
// count (its next guess is still refused, without a hash). While the table
// is full of live entries, also when all of them are at their limit, a new
// address is served like any other: the right password logs in, a wrong one
// gets the 401 after a hash, the same for an existing and a missing address.
func TestFullLoginFailureTableKeepsLockedAccountsAndRefusesNobody(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) { o.RateLimitMaxKeys = 4 }) // 10 failures per account
	s.createUser(t, "victim@example.com", "pw12345678")
	s.createUser(t, "owner@example.com", "pw12345678")
	s.createUser(t, "bystander@example.com", "pw12345678")
	sc := doSignup(t, s.h, "signed-in@example.com", "pw12345678") // its login leaves no entry
	lim := limitersOf(t, s.h)
	var logs bytes.Buffer
	prevLog := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prevLog) })

	// A password over the length limit is refused without a hash but counts
	// as a failure: that is what makes a flood cheap.
	cheap := strings.Repeat("x", 1025)
	for i := 0; i < 10; i++ {
		require.Equal(t, http.StatusUnauthorized, s.login(t, "198.51.100.110:1", "victim@example.com", cheap).Code)
	}
	hashes := countHashesOf(t, "guess-password-1", "probe-password-1", "pw12345678")
	w := s.login(t, "198.51.100.111:1", "victim@example.com", "guess-password-1")
	require.Equal(t, http.StatusTooManyRequests, w.Code, "the victim is at its limit")

	// The flood: one wrong password each for new typed addresses from other
	// client addresses, three times the table. Nobody is refused.
	for i := 0; i < 12; i++ {
		w := s.login(t, fmt.Sprintf("198.51.100.%d:1", 130+i), fmt.Sprintf("flood-%d@example.com", i), cheap)
		require.Equal(t, http.StatusUnauthorized, w.Code, "flood %d", i)
	}
	assert.Equal(t, 4, lim.loginAccount.size(), "the table is full")
	assert.Equal(t, 10, lim.loginAccount.count(accountKey("victim@example.com")), "the victim kept its count")
	w = s.login(t, "198.51.100.112:1", "victim@example.com", "guess-password-1")
	require.Equal(t, http.StatusTooManyRequests, w.Code, "the victim's next guess is still refused")
	assert.Zero(t, hashes["guess-password-1"].Load(), "no hash for a refused guess")
	assert.Equal(t, 1, strings.Count(logs.String(), "pushed out"), "one log line for the live entries pushed out:\n%s", logs.String())

	// A new address while the table is full of live entries: a wrong
	// password gets the 401 after a hash, the same for an existing and a
	// missing address (nothing tells them apart); the right one logs in.
	existing := s.login(t, "198.51.100.113:1", "bystander@example.com", "probe-password-1")
	missing := s.login(t, "198.51.100.114:1", "ghost@example.com", "probe-password-1")
	for _, x := range []*httptest.ResponseRecorder{existing, missing} {
		require.Equal(t, http.StatusUnauthorized, x.Code)
		assert.Contains(t, x.Body.String(), msgBadCredentials)
	}
	assert.EqualValues(t, 2, hashes["probe-password-1"].Load(), "both were hashed")
	assert.True(t, samePage(existing.Body.String(), missing.Body.String()),
		"the answer says nothing about the address:\n%s\n%s", existing.Body.String(), missing.Body.String())
	assert.Equal(t, cookieNames(missing), cookieNames(existing))
	assert.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.115:1", "owner@example.com", "pw12345678").Code)
	w = s.changePassword(t, "198.51.100.116:1", &sc, "pw12345678", "new-password-1")
	assert.Equal(t, http.StatusSeeOther, w.Code, "the settings page works too")

	// The table full of entries that are all at their limit: still nobody
	// is refused.
	for i := 0; i < 4; i++ {
		peer := fmt.Sprintf("198.51.100.%d:1", 150+i)
		for j := 0; j < 10; j++ {
			require.Equal(t, http.StatusUnauthorized, s.login(t, peer, fmt.Sprintf("wall-%d@example.com", i), cheap).Code)
		}
	}
	for _, k := range []string{"wall-0", "wall-1", "wall-2", "wall-3"} {
		require.Equal(t, 10, lim.loginAccount.count(accountKey(k+"@example.com")), k)
	}
	before := hashes["probe-password-1"].Load()
	w = s.login(t, "198.51.100.117:1", "ghost-2@example.com", "probe-password-1")
	require.Equal(t, http.StatusUnauthorized, w.Code, "a wrong password: the 401 after a hash")
	assert.Equal(t, before+1, hashes["probe-password-1"].Load())
	assert.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.118:1", "owner@example.com", "pw12345678").Code,
		"the right password logs in")
}

func TestAddressesThatFailValidationAreLimitedPerAccount(t *testing.T) {
	s := newStack(t, withMail, func(o *Options, _ *stack) { o.LoginFailuresPerAccount = 2 })
	lim := limitersOf(t, s.h)

	// An account created before addresses were validated can have a stored
	// address that fails today's check. Its logins are limited per address
	// like any other.
	const legacy = "Legacy User <legacy@example.com>"
	require.Equal(t, http.StatusUnauthorized, s.login(t, "198.51.100.120:1", legacy, "guess-1").Code)
	require.Equal(t, http.StatusUnauthorized, s.login(t, "198.51.100.121:1", legacy, "guess-2").Code)
	w := s.login(t, "198.51.100.122:1", legacy, "guess-3")
	require.Equal(t, http.StatusTooManyRequests, w.Code, "the address is at its limit, whatever its form")
	assert.Equal(t, 2, lim.loginAccount.count(accountKey(legacy)))

	// A reset request for such a string gets the generic answer and nothing
	// else, but the typed-address limit applies to it like to any string.
	for i := 0; i < 3; i++ {
		w = postFormFrom(t, s.h, nil, "/forgot-password", url.Values{"email": {"not-an-address"}}, fmt.Sprintf("198.51.100.%d:1", 123+i))
		require.Equal(t, http.StatusOK, w.Code)
	}
	w = postFormFrom(t, s.h, nil, "/forgot-password", url.Values{"email": {"not-an-address"}}, "198.51.100.127:1")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, 3, lim.resetAccount.count(accountKey("not-an-address")))
	assert.Zero(t, lim.resetStored.size(), "nothing was looked up or issued")
	assert.Empty(t, s.mailer.Sent())
}

// failingMailer refuses every message.
type failingMailer struct{}

func (failingMailer) Send(context.Context, mail.Message) error { return errors.New("smtp down") }

func TestLogLinesQuoteAddresses(t *testing.T) {
	s := newStack(t, withMail, func(o *Options, _ *stack) { o.Mailer = failingMailer{} })
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(prev)

	w := s.post(t, "198.51.100.96:1", "/signup", url.Values{"email": {"quoted@example.com"}, "password": {"pw12345678"}}, nil)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Contains(t, logged.String(), `"quoted@example.com"`)
}

func TestServiceFailureMapping(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
	}{
		{"no hash slot", fmt.Errorf("verify password: %w", auth.ErrBusy), http.StatusServiceUnavailable},
		{"deadlock", fmt.Errorf("update: %w", &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}), http.StatusServiceUnavailable},
		{"serialisation failure", &pgconn.PgError{Code: "40001", Message: "could not serialize access"}, http.StatusServiceUnavailable},
		{"unique violation", &pgconn.PgError{Code: "23505", Message: "duplicate key value"}, http.StatusInternalServerError},
		{"anything else", errors.New("dial tcp: password=hunter2"), http.StatusInternalServerError},
	}
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(prev)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			freshServiceFailureLog(t) // each case is the first of its burst
			w := httptest.NewRecorder()
			status, msg := serviceFailure(w, "test op", c.err)
			assert.Equal(t, c.status, status)
			if status == http.StatusServiceUnavailable {
				assert.Equal(t, "5", w.Header().Get("Retry-After"))
				assert.Contains(t, msg, "try again")
			} else {
				assert.Empty(t, w.Header().Get("Retry-After"))
			}
			assert.NotContains(t, msg, c.err.Error(), "the client never sees the error")
			assert.Contains(t, logged.String(), c.err.Error(), "the log does")
		})
	}
}
