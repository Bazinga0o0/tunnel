package frontend

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/audit"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
)

func TestAuditHelper(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	auditSvc := audit.NewService(pool)
	uid := dbtest.InsertUser(t, pool, "audited@example.com")
	opts := Options{Audit: auditSvc}

	request := func(remoteAddr string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		r.RemoteAddr = remoteAddr
		return r
	}
	// rowCount counts all audit rows, with or without an actor.
	rowCount := func() int {
		t.Helper()
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&n))
		return n
	}

	t.Run("writes actor, action, metadata and the peer address", func(t *testing.T) {
		r := request("203.0.113.7:54321")
		// Headers a client controls must not end up as the audit IP.
		r.Header.Set("X-Forwarded-For", "198.51.100.99")
		r.Header.Set("X-Real-IP", "198.51.100.98")

		opts.audit(r, &uid, "token.create", map[string]any{"token_id": 7, "name": "laptop"})

		entries, err := auditSvc.ListByUser(ctx, uid, 10)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		e := entries[0]
		require.NotNil(t, e.UserID)
		assert.Equal(t, uid, *e.UserID)
		assert.Equal(t, "token.create", e.Action)
		assert.Equal(t, map[string]any{"token_id": float64(7), "name": "laptop"}, e.Metadata)
		assert.Equal(t, netip.MustParseAddr("203.0.113.7"), e.IP)
	})

	t.Run("an event without an actor is stored with a NULL user", func(t *testing.T) {
		before := rowCount()
		opts.audit(request("203.0.113.8:1"), nil, "auth.login.failure", map[string]any{"reason": "bad password"})
		require.Equal(t, before+1, rowCount())

		var action string
		var userID *int64
		var ip *netip.Addr
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT action, user_id, ip FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&action, &userID, &ip))
		assert.Equal(t, "auth.login.failure", action)
		assert.Nil(t, userID)
		require.NotNil(t, ip)
		assert.Equal(t, "203.0.113.8", ip.String())
	})

	t.Run("peer address forms", func(t *testing.T) {
		lastIP := func() *netip.Addr {
			t.Helper()
			var ip *netip.Addr
			require.NoError(t, pool.QueryRow(ctx, `SELECT ip FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&ip))
			return ip
		}

		opts.audit(request("[2001:db8::1]:443"), &uid, "auth.logout", nil)
		require.NotNil(t, lastIP())
		assert.Equal(t, "2001:db8::1", lastIP().String())

		// An IPv4 peer on a dual-stack listener.
		opts.audit(request("[::ffff:192.0.2.5]:443"), &uid, "auth.logout", nil)
		require.NotNil(t, lastIP())
		assert.Equal(t, "192.0.2.5", lastIP().String())

		// A link-local peer carries a zone the inet column cannot hold.
		opts.audit(request("[fe80::1%eth0]:443"), &uid, "auth.logout", nil)
		require.NotNil(t, lastIP())
		assert.Equal(t, "fe80::1", lastIP().String())

		// An address without a port, as chi's RealIP middleware leaves it.
		opts.audit(request("203.0.113.10"), &uid, "auth.logout", nil)
		require.NotNil(t, lastIP())
		assert.Equal(t, "203.0.113.10", lastIP().String())
		opts.audit(request("::ffff:192.0.2.6"), &uid, "auth.logout", nil)
		require.NotNil(t, lastIP())
		assert.Equal(t, "192.0.2.6", lastIP().String())

		// Not an address at all: the entry is written without one.
		before := rowCount()
		opts.audit(request("not-an-address"), &uid, "auth.logout", nil)
		require.Equal(t, before+1, rowCount(), "an unparsable peer address must not lose the entry")
		assert.Nil(t, lastIP())
	})

	t.Run("a request whose context is over is still audited", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		before := rowCount()
		opts.audit(request("203.0.113.9:1").WithContext(cancelled), &uid, "auth.logout", nil)
		assert.Equal(t, before+1, rowCount())
	})

	t.Run("does nothing without an audit service", func(t *testing.T) {
		before := rowCount()
		require.NotPanics(t, func() {
			Options{}.audit(request("203.0.113.7:1"), &uid, "auth.logout", map[string]any{"k": "v"})
		})
		assert.Equal(t, before, rowCount())
	})

	t.Run("a write error is logged and not returned", func(t *testing.T) {
		var logged bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&logged)
		defer log.SetOutput(prev)

		before := rowCount()
		// A channel cannot be encoded as JSON: the write fails.
		require.NotPanics(t, func() {
			opts.audit(request("203.0.113.7:1"), &uid, "token.revoke", map[string]any{"bad": make(chan int)})
		})
		assert.Equal(t, before, rowCount())
		assert.Contains(t, logged.String(), "token.revoke", "the failed action is named in the log")
	})
}
