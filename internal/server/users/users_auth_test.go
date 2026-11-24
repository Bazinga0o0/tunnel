package users

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
)

// kdfSpy counts a service's calls into the password KDF and passes them on
// to the real functions unless a hook is set.
type kdfSpy struct {
	hashes, verifies, dummies atomic.Int32
	lastDummyPassword         string
	beforeHash                func() // runs before the real hash
	afterVerify               func() // runs after the real verify, before its result is returned
	fail                      error  // when set, every KDF entry point returns it
}

func spyOn(svc *Service) *kdfSpy {
	spy := &kdfSpy{}
	hash, verify, dummy := svc.hash, svc.verify, svc.dummyVerify
	svc.hash = func(ctx context.Context, password string) (string, error) {
		spy.hashes.Add(1)
		if spy.fail != nil {
			return "", spy.fail
		}
		if spy.beforeHash != nil {
			spy.beforeHash()
		}
		return hash(ctx, password)
	}
	svc.verify = func(ctx context.Context, stored, password string) (bool, error) {
		spy.verifies.Add(1)
		if spy.fail != nil {
			return false, spy.fail
		}
		ok, err := verify(ctx, stored, password)
		if spy.afterVerify != nil {
			spy.afterVerify()
		}
		return ok, err
	}
	svc.dummyVerify = func(ctx context.Context, password string) error {
		spy.dummies.Add(1)
		spy.lastDummyPassword = password
		if spy.fail != nil {
			return spy.fail
		}
		return dummy(ctx, password)
	}
	return spy
}

// --- email validation ------------------------------------------------------

func TestValidateEmail(t *testing.T) {
	valid := []string{
		"a@b.example.com",
		"Alice@Example.com",
		"first.last+tag@sub.example.org",
		"o'brien@example.ie",
		"50%off@example.com",
		"user@localhost",
		"üser@exämple.de",
		strings.Repeat("a", 64) + "@" + strings.Repeat("b", 185) + ".com", // 254 bytes
	}
	require.Len(t, valid[len(valid)-1], 254)
	for _, email := range valid {
		assert.NoError(t, ValidateEmail(email), "%q", email)
	}

	invalid := map[string]string{
		"empty":                   "",
		"no at sign":              "not-an-address",
		"no local part":           "@example.com",
		"no domain":               "user@",
		"display name":            "Alice <alice@example.com>",
		"angle brackets":          "<alice@example.com>",
		"quoted display name":     `"Alice" <alice@example.com>`,
		"comment":                 "alice@example.com (Alice)",
		"two addresses":           "a@example.com, b@example.com",
		"leading space":           " alice@example.com",
		"trailing space":          "alice@example.com ",
		"inner space":             "ali ce@example.com",
		"quoted local part":       `"ali ce"@example.com`,
		"line feed":               "alice@example.com\n",
		"carriage return":         "alice@example.com\r",
		"header injection":        "alice@example.com\r\nBcc: victim@example.com",
		"tab":                     "alice\t@example.com",
		"NUL":                     "alice\x00@example.com",
		"escape":                  "alice\x1b[31m@example.com",
		"DEL":                     "alice\x7f@example.com",
		"C1 control":              "alice\u0085@example.com",
		"invalid UTF-8":           "alice\xff@example.com",
		"255 bytes":               strings.Repeat("a", 64) + "@" + strings.Repeat("b", 186) + ".com",
		"very long":               strings.Repeat("a", 10000) + "@example.com",
		"mailto scheme":           "mailto:alice@example.com",
		"group syntax":            "team: alice@example.com;",
		"double at":               "alice@@example.com",
		"trailing dot local part": "alice.@example.com",
	}
	for name, email := range invalid {
		assert.ErrorIs(t, ValidateEmail(email), ErrInvalidEmail, "%s: %q", name, email)
	}
}

// --- password policy --------------------------------------------------------

func TestValidatePassword(t *testing.T) {
	assert.Equal(t, 8, MinPasswordLength)
	assert.Equal(t, 12, MinAdminPasswordLength)
	assert.Equal(t, 1024, MaxPasswordBytes)

	// Validation needs no database.
	t.Run("defaults", func(t *testing.T) {
		for name, svc := range map[string]*Service{
			"NewService":                       NewService(nil),
			"NewServiceWithOptions zero value": NewServiceWithOptions(nil, Options{}),
		} {
			assert.ErrorIs(t, svc.ValidatePassword(""), ErrPasswordTooShort, name)
			assert.ErrorIs(t, svc.ValidatePassword("1234567"), ErrPasswordTooShort, name)
			assert.ErrorIs(t, svc.ValidatePassword("äääääää"), ErrPasswordTooShort, "%s: 7 characters in 14 bytes", name)
			assert.NoError(t, svc.ValidatePassword("12345678"), name)
			assert.NoError(t, svc.ValidatePassword("ääääääää"), name)
			assert.NoError(t, svc.ValidatePassword(strings.Repeat("x", 1024)), name)
			assert.ErrorIs(t, svc.ValidatePassword(strings.Repeat("x", 1025)), ErrPasswordTooLong, name)
			assert.ErrorIs(t, svc.ValidatePassword(strings.Repeat("ä", 513)), ErrPasswordTooLong, "%s: 513 characters in 1026 bytes", name)
			assert.NoError(t, svc.ValidatePassword(strings.Repeat("ä", 512)), name)

			assert.ErrorIs(t, svc.ValidateAdminPassword("elevenchars"), ErrPasswordTooShort, name)
			assert.ErrorIs(t, svc.ValidateAdminPassword("ääääää"), ErrPasswordTooShort, "%s: 6 characters in 12 bytes", name)
			assert.NoError(t, svc.ValidateAdminPassword("twelve chars"), name)
			assert.NoError(t, svc.ValidateAdminPassword(strings.Repeat("x", 1024)), name)
			assert.ErrorIs(t, svc.ValidateAdminPassword(strings.Repeat("x", 1025)), ErrPasswordTooLong, name)

			// The text names the rule, for the error page.
			assert.EqualError(t, svc.ValidatePassword("short"), "password is too short: must be at least 8 characters", name)
			assert.EqualError(t, svc.ValidateAdminPassword("short"), "password is too short: must be at least 12 characters", name)
			assert.EqualError(t, svc.ValidatePassword(strings.Repeat("x", 1025)), "password is too long: must be at most 1024 bytes", name)
		}
	})

	t.Run("positive values are used", func(t *testing.T) {
		svc := NewServiceWithOptions(nil, Options{MinPasswordLength: 10, MinAdminPasswordLength: 20, MaxPasswordBytes: 30})
		assert.ErrorIs(t, svc.ValidatePassword("ninechars"), ErrPasswordTooShort)
		assert.EqualError(t, svc.ValidatePassword("ninechars"), "password is too short: must be at least 10 characters")
		assert.NoError(t, svc.ValidatePassword("ten chars!"))
		assert.ErrorIs(t, svc.ValidateAdminPassword(strings.Repeat("x", 19)), ErrPasswordTooShort)
		assert.NoError(t, svc.ValidateAdminPassword(strings.Repeat("x", 20)))
		assert.NoError(t, svc.ValidatePassword(strings.Repeat("x", 30)))
		assert.ErrorIs(t, svc.ValidatePassword(strings.Repeat("x", 31)), ErrPasswordTooLong)
	})

	t.Run("negative values switch the rules off", func(t *testing.T) {
		svc := NewServiceWithOptions(nil, Options{MinPasswordLength: -1, MinAdminPasswordLength: -1, MaxPasswordBytes: -1})
		assert.NoError(t, svc.ValidatePassword(""))
		assert.NoError(t, svc.ValidateAdminPassword("x"))
		assert.NoError(t, svc.ValidatePassword(strings.Repeat("x", 5000)))
		assert.False(t, svc.tooLong(strings.Repeat("x", 5000)))
	})
}

// --- Hinweis: LIKE escaping --------------------------------------------------

func TestEscapeLike(t *testing.T) {
	cases := map[string]string{
		"":                "",
		"plain":           "plain",
		"a_b":             `a\_b`,
		"100%":            `100\%`,
		`back\slash`:      `back\\slash`,
		`\`:               `\\`,
		`%_\`:             `\%\_\\`,
		`\%`:              `\\\%`,
		"a@b.example.com": "a@b.example.com",
		"ünï_cödé%":       `ünï\_cödé\%`,
		`__%%\\`:          `\_\_\%\%\\\\`,
		"no'quote\"s":     "no'quote\"s",
	}
	for in, want := range cases {
		assert.Equal(t, want, escapeLike(in), "%q", in)
	}
}

// --- Create -----------------------------------------------------------------

func TestCreateValidatesBeforeItHashes(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	t.Run("an invalid address is rejected before any work", func(t *testing.T) {
		svc := NewService(pool)
		spy := spyOn(svc)
		for _, email := range []string{
			"",
			"Alice <alice@example.com>",
			"alice@example.com\r\nBcc: victim@example.com",
			" alice@example.com",
			strings.Repeat("a", 300) + "@example.com",
		} {
			u, err := svc.Create(ctx, email, "pw12345678")
			require.ErrorIs(t, err, ErrInvalidEmail, "%q", email)
			assert.Nil(t, u)
		}
		assert.EqualValues(t, 0, spy.hashes.Load(), "no hash for a rejected address")
		n, err := svc.CountAll(ctx)
		require.NoError(t, err)
		assert.EqualValues(t, 0, n, "nothing stored")
	})

	t.Run("a taken address costs no hash", func(t *testing.T) {
		svc := NewService(pool)
		spy := spyOn(svc)
		_, err := svc.Create(ctx, "taken@example.com", "pw12345678")
		require.NoError(t, err)
		require.EqualValues(t, 1, spy.hashes.Load())

		for _, email := range []string{"taken@example.com", "TAKEN@Example.COM"} {
			u, err := svc.Create(ctx, email, "another-pw-1")
			require.ErrorIs(t, err, ErrEmailTaken, "%q", email)
			assert.Nil(t, u)
		}
		assert.EqualValues(t, 1, spy.hashes.Load(), "a taken address must not cost a hash")
	})

	t.Run("the unique constraint still decides a race", func(t *testing.T) {
		// The address is free when Create looks and taken when it inserts.
		svc := NewService(pool)
		spy := spyOn(svc)
		spy.beforeHash = func() { dbtest.InsertUser(t, pool, "raced@example.com") }

		u, err := svc.Create(ctx, "raced@example.com", "pw12345678")
		require.ErrorIs(t, err, ErrEmailTaken)
		assert.Nil(t, u)
	})

	t.Run("a password set by an operator needs twelve characters, a sign-up eight", func(t *testing.T) {
		svc := NewService(pool)
		spy := spyOn(svc)

		// Eleven characters: enough for a sign-up, not when somebody else
		// sets the password.
		u, err := svc.CreateWithAdminPassword(ctx, "operator-made@example.com", "elevenchars")
		require.ErrorIs(t, err, ErrPasswordTooShort)
		assert.Contains(t, err.Error(), "at least 12 characters")
		assert.Nil(t, u)
		assert.EqualValues(t, 0, spy.hashes.Load())
		_, err = svc.FindByEmail(ctx, "operator-made@example.com")
		require.ErrorIs(t, err, ErrNotFound)

		u, err = svc.CreateWithAdminPassword(ctx, "operator-made@example.com", "twelve chars")
		require.NoError(t, err)
		ok, err := svc.VerifyPassword(ctx, u.ID, "twelve chars")
		require.NoError(t, err)
		assert.True(t, ok)

		// Everything else is as in Create.
		_, err = svc.CreateWithAdminPassword(ctx, "OPERATOR-MADE@example.com", "twelve chars")
		require.ErrorIs(t, err, ErrEmailTaken)
		_, err = svc.CreateWithAdminPassword(ctx, "Operator <op@example.com>", "twelve chars")
		require.ErrorIs(t, err, ErrInvalidEmail)
		_, err = svc.CreateWithAdminPassword(ctx, "operator-long@example.com", strings.Repeat("x", 1025))
		require.ErrorIs(t, err, ErrPasswordTooLong)

		// The sign-up rule is unchanged.
		_, err = svc.Create(ctx, "signup-eleven@example.com", "elevenchars")
		require.NoError(t, err)
		_, err = svc.Create(ctx, "signup-eight@example.com", "8 chars!")
		require.NoError(t, err)
		_, err = svc.Create(ctx, "signup-seven@example.com", "7 chars")
		require.ErrorIs(t, err, ErrPasswordTooShort)
	})

	t.Run("an overlong password is rejected without hashing", func(t *testing.T) {
		svc := NewService(pool)
		u, err := svc.Create(ctx, "long-pw@example.com", strings.Repeat("x", 1024))
		require.NoError(t, err, "1024 bytes is the longest accepted password")

		spy := spyOn(svc)
		tooLong := strings.Repeat("x", 1025)
		_, err = svc.Create(ctx, "long-pw-2@example.com", tooLong)
		require.ErrorIs(t, err, ErrPasswordTooLong)
		require.ErrorIs(t, svc.ChangePassword(ctx, u.ID, tooLong), ErrPasswordTooLong)
		require.ErrorIs(t, svc.SetPassword(ctx, u.ID, tooLong), ErrPasswordTooLong)
		assert.EqualValues(t, 0, spy.hashes.Load())

		ok, err := svc.VerifyPassword(ctx, u.ID, tooLong)
		require.NoError(t, err)
		assert.False(t, ok)
		assert.EqualValues(t, 0, spy.verifies.Load(), "an overlong password is not run through the KDF")

		ok, err = svc.VerifyPassword(ctx, u.ID, strings.Repeat("x", 1024))
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("a busy KDF is reported as auth.ErrBusy", func(t *testing.T) {
		svc := NewService(pool)
		u, err := svc.Create(ctx, "busy@example.com", "pw12345678")
		require.NoError(t, err)

		spy := spyOn(svc)
		spy.fail = auth.ErrBusy

		_, err = svc.Create(ctx, "busy-new@example.com", "pw12345678")
		require.ErrorIs(t, err, auth.ErrBusy)
		_, err = svc.FindByEmail(ctx, "busy-new@example.com")
		require.ErrorIs(t, err, ErrNotFound, "no account when the hash did not run")

		require.ErrorIs(t, svc.ChangePassword(ctx, u.ID, "new-password-1"), auth.ErrBusy)
		require.ErrorIs(t, svc.SetPassword(ctx, u.ID, "new-password-1"), auth.ErrBusy)
		_, err = svc.VerifyPassword(ctx, u.ID, "pw12345678")
		require.ErrorIs(t, err, auth.ErrBusy)

		// Login: busy for a known and for an unknown address, never "wrong
		// password".
		_, err = svc.Authenticate(ctx, "busy@example.com", "pw12345678")
		require.ErrorIs(t, err, auth.ErrBusy)
		assert.NotErrorIs(t, err, ErrInvalidCredentials)
		_, err = svc.Authenticate(ctx, "nobody@example.com", "pw12345678")
		require.ErrorIs(t, err, auth.ErrBusy)
		assert.NotErrorIs(t, err, ErrInvalidCredentials)
	})
}

// --- login -------------------------------------------------------------------

func TestAuthenticate(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	created, err := NewService(pool).Create(ctx, "Login@Example.com", "correct horse")
	require.NoError(t, err)

	t.Run("right password", func(t *testing.T) {
		svc := NewService(pool)
		u, err := svc.Authenticate(ctx, "Login@Example.com", "correct horse")
		require.NoError(t, err)
		require.NotNil(t, u)
		assert.Equal(t, created.ID, u.ID)
		assert.Equal(t, "Login@Example.com", u.Email, "the stored spelling")

		// The address is matched case-insensitively.
		u, err = svc.Authenticate(ctx, "login@example.com", "correct horse")
		require.NoError(t, err)
		assert.Equal(t, created.ID, u.ID)
		assert.Equal(t, "Login@Example.com", u.Email)
	})

	t.Run("wrong password and unknown address are the same error", func(t *testing.T) {
		svc := NewService(pool)
		u, err := svc.Authenticate(ctx, "login@example.com", "wrong horse")
		require.ErrorIs(t, err, ErrInvalidCredentials)
		assert.Nil(t, u)

		u, err = svc.Authenticate(ctx, "nobody@example.com", "correct horse")
		require.ErrorIs(t, err, ErrInvalidCredentials)
		assert.Nil(t, u)
	})

	t.Run("an unknown address runs the dummy hash", func(t *testing.T) {
		svc := NewService(pool)
		spy := spyOn(svc)

		// Known address: one verification against the stored hash, no dummy.
		_, err := svc.Authenticate(ctx, "login@example.com", "wrong horse")
		require.ErrorIs(t, err, ErrInvalidCredentials)
		assert.EqualValues(t, 1, spy.verifies.Load())
		assert.EqualValues(t, 0, spy.dummies.Load())

		// Unknown address: one verification against the dummy hash, with
		// the password that was sent. Both cases cost one KDF run.
		_, err = svc.Authenticate(ctx, "unknown@example.com", "attacker guess")
		require.ErrorIs(t, err, ErrInvalidCredentials)
		assert.EqualValues(t, 1, spy.verifies.Load(), "no stored hash to verify against")
		assert.EqualValues(t, 1, spy.dummies.Load(), "dummy verification must run")
		assert.Equal(t, "attacker guess", spy.lastDummyPassword)

		// An address that cannot belong to an account still costs the same.
		_, err = svc.Authenticate(ctx, "not an address", "attacker guess")
		require.ErrorIs(t, err, ErrInvalidCredentials)
		assert.EqualValues(t, 2, spy.dummies.Load())
	})

	t.Run("an account whose stored hash cannot be read looks like an unknown address", func(t *testing.T) {
		svc := NewService(pool)
		// InsertUser stores a placeholder that is no argon2id hash.
		id := dbtest.InsertUser(t, pool, "broken-hash@example.com")
		spy := spyOn(svc)
		var logged bytes.Buffer
		svc.logger = slog.New(slog.NewTextHandler(&logged, nil))

		u, err := svc.Authenticate(ctx, "broken-hash@example.com", "whatever password")
		require.ErrorIs(t, err, ErrInvalidCredentials)
		assert.NotErrorIs(t, err, auth.ErrMalformedHash)
		assert.Nil(t, u)
		assert.EqualValues(t, 1, spy.dummies.Load(), "one KDF run, as for an unknown address")
		assert.Equal(t, "whatever password", spy.lastDummyPassword)

		// The operator learns which account is broken, and nothing else.
		line := logged.String()
		assert.Contains(t, line, fmt.Sprintf("user_id=%d", id))
		assert.NotContains(t, line, "broken-hash@example.com")
		assert.NotContains(t, line, "test-placeholder-not-a-hash")
		assert.NotContains(t, line, "whatever password")

		// No slot for the dummy run: busy, as for every other account.
		spy.fail = auth.ErrBusy
		_, err = svc.Authenticate(ctx, "broken-hash@example.com", "whatever password")
		require.ErrorIs(t, err, auth.ErrBusy)
	})

	t.Run("degenerate input is refused without work", func(t *testing.T) {
		svc := NewService(pool)
		spy := spyOn(svc)

		// These are refused the same way whether or not the account exists,
		// so they tell an attacker nothing and need no KDF run.
		cases := map[string][2]string{
			"empty password, known":      {"login@example.com", ""},
			"empty password, unknown":    {"nobody@example.com", ""},
			"empty address":              {"", "correct horse"},
			"overlong password, known":   {"login@example.com", strings.Repeat("x", 1025)},
			"overlong password, unknown": {"nobody@example.com", strings.Repeat("x", 1025)},
			"address is not UTF-8":       {"login\xff@example.com", "correct horse"},
			"address with NUL":           {"login@example.com\x00", "correct horse"},
		}
		for name, c := range cases {
			u, err := svc.Authenticate(ctx, c[0], c[1])
			require.ErrorIs(t, err, ErrInvalidCredentials, name)
			assert.Nil(t, u, name)
		}
		assert.EqualValues(t, 0, spy.verifies.Load())
		assert.EqualValues(t, 0, spy.dummies.Load())
	})

	t.Run("disabled account", func(t *testing.T) {
		svc := NewService(pool)
		u, err := svc.Create(ctx, "disabled@example.com", "correct horse")
		require.NoError(t, err)
		setFlags(t, pool, u.ID, false, true)
		spy := spyOn(svc)

		got, err := svc.Authenticate(ctx, "disabled@example.com", "correct horse")
		require.ErrorIs(t, err, ErrAccountDisabled)
		assert.Nil(t, got)
		assert.EqualValues(t, 1, spy.verifies.Load(), "a disabled account costs the same KDF run")

		// A wrong password on a disabled account is just a wrong password:
		// the caller must not learn the account state without the password.
		_, err = svc.Authenticate(ctx, "disabled@example.com", "wrong horse")
		require.ErrorIs(t, err, ErrInvalidCredentials)
		assert.NotErrorIs(t, err, ErrAccountDisabled)
	})

	t.Run("changes made while the password was checked are seen", func(t *testing.T) {
		svc := NewService(pool)
		u, err := svc.Create(ctx, "overlap@example.com", "correct horse")
		require.NoError(t, err)
		spy := spyOn(svc)

		// The account is disabled while the (slow) password check runs.
		// The account state from before the check must not be used.
		spy.afterVerify = func() { setFlags(t, pool, u.ID, false, true) }
		_, err = svc.Authenticate(ctx, "overlap@example.com", "correct horse")
		require.ErrorIs(t, err, ErrAccountDisabled)

		// The address is verified during the check: the account that comes
		// back is the one read after it.
		setFlags(t, pool, u.ID, false, false)
		spy.afterVerify = func() { require.NoError(t, svc.MarkEmailVerified(ctx, u.ID)) }
		got, err := svc.Authenticate(ctx, "overlap@example.com", "correct horse")
		require.NoError(t, err)
		assert.True(t, got.EmailVerifiedAt.Valid, "Authenticate returns the account as it is now")

		// The password is replaced while the old one is being checked.
		spy.afterVerify = func() {
			_, err := pool.Exec(ctx, `UPDATE users SET password_hash = 'replaced' WHERE id = $1`, u.ID)
			require.NoError(t, err)
		}
		_, err = svc.Authenticate(ctx, "overlap@example.com", "correct horse")
		require.ErrorIs(t, err, ErrInvalidCredentials)

		// The account is deleted while the password is being checked.
		u2, err := svc.Create(ctx, "overlap-2@example.com", "correct horse")
		require.NoError(t, err)
		spy.afterVerify = func() {
			_, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, u2.ID)
			require.NoError(t, err)
		}
		_, err = svc.Authenticate(ctx, "overlap-2@example.com", "correct horse")
		require.ErrorIs(t, err, ErrInvalidCredentials)
	})
}
