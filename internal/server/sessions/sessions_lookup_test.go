package sessions

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
)

// setDisabled flips users.disabled_at directly, without users.Disable
// (which also deletes sessions), so the tests see the lookup query alone.
func setDisabled(t *testing.T, pool *pgxpool.Pool, userID int64, disabled bool) {
	t.Helper()
	q := `UPDATE users SET disabled_at = NULL WHERE id = $1`
	if disabled {
		q = `UPDATE users SET disabled_at = now() WHERE id = $1`
	}
	tag, err := pool.Exec(context.Background(), q, userID)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
}

func TestLookupRejectsSessionOfDisabledUser(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	uid := dbtest.InsertUser(t, pool, "disabled-sess@example.com")
	other := dbtest.InsertUser(t, pool, "active-sess@example.com")

	svc := NewService(pool)
	raw, _, err := svc.Create(ctx, uid, "ua", netip.Addr{}, time.Hour)
	require.NoError(t, err)
	rawOther, _, err := svc.Create(ctx, other, "ua", netip.Addr{}, time.Hour)
	require.NoError(t, err)

	_, err = svc.Lookup(ctx, raw)
	require.NoError(t, err)

	setDisabled(t, pool, uid, true)

	_, err = svc.Lookup(ctx, raw)
	require.ErrorIs(t, err, ErrInvalidSession, "session of a disabled user must not resolve")

	got, err := svc.Lookup(ctx, rawOther)
	require.NoError(t, err)
	assert.Equal(t, other, got.UserID)

	// The row is still there; only the lookup refuses it.
	setDisabled(t, pool, uid, false)
	got, err = svc.Lookup(ctx, raw)
	require.NoError(t, err)
	assert.Equal(t, uid, got.UserID)
}

func TestCreateTruncatesStoredUserAgent(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	uid := dbtest.InsertUser(t, pool, "ua@example.com")
	svc := NewService(pool)

	stored := func(ua string) string {
		t.Helper()
		_, row, err := svc.Create(ctx, uid, ua, netip.Addr{}, time.Hour)
		require.NoError(t, err)
		// Read back what the database holds, not what Create echoed.
		var got *string
		require.NoError(t, pool.QueryRow(ctx, `SELECT user_agent FROM sessions WHERE id = $1`, row.ID).Scan(&got))
		if got == nil {
			return ""
		}
		return *got
	}

	t.Run("short value is stored as is", func(t *testing.T) {
		assert.Equal(t, "Mozilla/5.0 (X11; Linux x86_64)", stored("Mozilla/5.0 (X11; Linux x86_64)"))
	})
	t.Run("exactly 256 bytes is stored as is", func(t *testing.T) {
		ua := strings.Repeat("a", 256)
		assert.Equal(t, ua, stored(ua))
	})
	t.Run("257 bytes is cut to 256", func(t *testing.T) {
		ua := strings.Repeat("a", 256) + "b"
		assert.Equal(t, strings.Repeat("a", 256), stored(ua))
	})
	t.Run("64 KiB is cut to 256", func(t *testing.T) {
		got := stored(strings.Repeat("x", 64*1024))
		assert.Len(t, got, 256)
	})
	t.Run("cut never splits a multi-byte character", func(t *testing.T) {
		// 255 ASCII bytes followed by two-byte runes: byte 256 would be the
		// first half of "ä".
		ua := strings.Repeat("a", 255) + strings.Repeat("ä", 10)
		got := stored(ua)
		assert.Equal(t, strings.Repeat("a", 255), got)
		assert.True(t, utf8.ValidString(got))
	})
	t.Run("empty value stays NULL", func(t *testing.T) {
		_, row, err := svc.Create(ctx, uid, "", netip.Addr{}, time.Hour)
		require.NoError(t, err)
		assert.False(t, row.UserAgent.Valid)
	})
	t.Run("bytes that are not UTF-8 do not break the login", func(t *testing.T) {
		// A header may carry any byte above 0x7f; the column is text.
		got := stored("Mozilla\xff\xfe/5.0 caf\xe9")
		assert.Equal(t, "Mozilla/5.0 caf", got)
	})
	t.Run("a NUL byte does not break the login", func(t *testing.T) {
		// The text column takes no NUL.
		assert.Equal(t, "Mozilla/5.0", stored("Mozi\x00lla/5.0\x00"))
	})

	assert.Equal(t, 256, DefaultMaxUserAgentBytes)
	t.Run("option: zero selects the default", func(t *testing.T) {
		svc = NewServiceWithOptions(pool, Options{})
		assert.Len(t, stored(strings.Repeat("x", 1000)), 256)
	})
	t.Run("option: a positive value is used", func(t *testing.T) {
		svc = NewServiceWithOptions(pool, Options{MaxUserAgentBytes: 10})
		assert.Equal(t, "0123456789", stored("0123456789abcdef"))
		assert.Equal(t, "aaaaaaaaa", stored("aaaaaaaaaä"), "nine bytes: the tenth would split the umlaut")
	})
	t.Run("option: a negative value switches the cut off", func(t *testing.T) {
		svc = NewServiceWithOptions(pool, Options{MaxUserAgentBytes: -1})
		assert.Len(t, stored(strings.Repeat("x", 1000)), 1000)
	})
}
