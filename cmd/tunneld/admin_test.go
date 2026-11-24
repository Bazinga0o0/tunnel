package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// adminCLITest is a config file pointing at the test database, and the
// services to look at what the commands did.
type adminCLITest struct {
	cfgPath string
	pool    *pgxpool.Pool
	users   *users.Service
	tokens  *tokens.Service
	res     *reservations.Service
}

func newAdminCLITest(t *testing.T) *adminCLITest {
	t.Helper()
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)

	c := &adminCLITest{
		cfgPath: filepath.Join(t.TempDir(), "tunneld.yaml"),
		pool:    pool,
		users:   users.NewService(pool),
		tokens:  tokens.NewService(pool),
		res:     reservations.NewService(pool),
	}
	c.writeConfig(t, "", "")
	return c
}

// writeConfig writes the config the commands read: auth.signup set to
// signup (empty: not set, which is open), and extra, YAML with top-level
// keys the base config does not set, appended.
func (c *adminCLITest) writeConfig(t *testing.T, signup, extra string) {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	signupLine := ""
	if signup != "" {
		signupLine = fmt.Sprintf("  signup: %q\n", signup)
	}
	// The listen addresses are never bound: admin commands only talk to the
	// database.
	cfg := fmt.Sprintf(`domain: tunnel.test
listen:
  tunnel_addr: "127.0.0.1:0"
  http_addr: "127.0.0.1:0"
tls:
  self_signed_hosts: ["tunnel.test"]
database:
  url: %q
auth:
  csrf_key: %q
%sudp:
  enabled: true
  port_range:
    low: 30000
    high: 40000
%s`, os.Getenv("TUNNELD_TEST_DATABASE_URL"), key, signupLine, extra)
	require.NoError(t, os.WriteFile(c.cfgPath, []byte(cfg), 0o600))
}

// cliRun is the outcome of one admin command.
type cliRun struct {
	out    string
	errOut string
	err    error
}

// cliOptions replace the terminal for one run.
type cliOptions struct {
	stdin    string
	terminal []string // lines the terminal returns; nil: stdin is no terminal
}

// run runs `tunneld admin <args...> --config <cfg>` with the given stdin.
func (c *adminCLITest) run(t *testing.T, o cliOptions, args ...string) cliRun {
	t.Helper()
	var out, errOut bytes.Buffer

	prevIn, prevOut, prevErr := adminStdin, adminStdout, adminStderr
	prevIsTerm, prevReadTerm := stdinIsTerminal, readTerminalPassword
	defer func() {
		adminStdin, adminStdout, adminStderr = prevIn, prevOut, prevErr
		stdinIsTerminal, readTerminalPassword = prevIsTerm, prevReadTerm
	}()
	adminStdin = strings.NewReader(o.stdin)
	adminStdout, adminStderr = &out, &errOut
	lines := o.terminal
	stdinIsTerminal = func() bool { return o.terminal != nil }
	readTerminalPassword = func() ([]byte, error) {
		if len(lines) == 0 {
			return nil, errors.New("test terminal: no more input")
		}
		l := lines[0]
		lines = lines[1:]
		return []byte(l), nil
	}

	full := append([]string{args[0], "--config", c.cfgPath}, args[1:]...)
	err := runAdmin(full)
	return cliRun{out: out.String(), errOut: errOut.String(), err: err}
}

// mustRun runs a command that must succeed.
func (c *adminCLITest) mustRun(t *testing.T, o cliOptions, args ...string) cliRun {
	t.Helper()
	r := c.run(t, o, args...)
	require.NoError(t, r.err, "admin %v; stderr: %s", args, r.errOut)
	return r
}

func (c *adminCLITest) userExists(t *testing.T, email string) bool {
	t.Helper()
	_, err := c.users.FindByEmail(context.Background(), email)
	if errors.Is(err, users.ErrNotFound) {
		return false
	}
	require.NoError(t, err)
	return true
}

func (c *adminCLITest) passwordWorks(t *testing.T, email, password string) bool {
	t.Helper()
	u, err := c.users.FindByEmail(context.Background(), email)
	require.NoError(t, err)
	ok, err := c.users.VerifyPassword(context.Background(), u.ID, password)
	require.NoError(t, err)
	return ok
}

// cliAuditRow is one audit_log row written by a command.
type cliAuditRow struct {
	actor    *int64
	metadata map[string]any
}

func (c *adminCLITest) auditRows(t *testing.T, action string) []cliAuditRow {
	t.Helper()
	rows, err := c.pool.Query(context.Background(),
		`SELECT user_id, metadata FROM audit_log WHERE action = $1 ORDER BY id`, action)
	require.NoError(t, err)
	defer rows.Close()
	var out []cliAuditRow
	for rows.Next() {
		var r cliAuditRow
		var raw []byte
		require.NoError(t, rows.Scan(&r.actor, &raw))
		if len(raw) > 0 {
			require.NoError(t, json.Unmarshal(raw, &r.metadata))
		}
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

func (c *adminCLITest) auditCount(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, c.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log`).Scan(&n))
	return n
}

// ---- password input ----

func TestAdminCLICreateUserPasswordSources(t *testing.T) {
	c := newAdminCLITest(t)
	dir := t.TempDir()
	writeFile := func(name, content string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
		return p
	}

	// --password-file, LF and CRLF line endings.
	c.mustRun(t, cliOptions{}, "create-user", "--email", "file@example.com",
		"--password-file", writeFile("pw1", "file-password-123\n"))
	assert.True(t, c.passwordWorks(t, "file@example.com", "file-password-123"))
	c.mustRun(t, cliOptions{}, "create-user", "--email", "crlf@example.com",
		"--password-file", writeFile("pw2", "crlf-password-123\r\n"))
	assert.True(t, c.passwordWorks(t, "crlf@example.com", "crlf-password-123"))

	// --password-stdin.
	c.mustRun(t, cliOptions{stdin: "stdin-password-123\n"}, "create-user", "--email", "stdin@example.com", "--password-stdin")
	assert.True(t, c.passwordWorks(t, "stdin@example.com", "stdin-password-123"))

	// Default on a pipe: password and confirmation as two lines, read through
	// one reader (with a reader per line the confirmation found nothing).
	r := c.mustRun(t, cliOptions{stdin: "piped-password-12\npiped-password-12\n"}, "create-user", "--email", "pipe@example.com")
	assert.True(t, c.passwordWorks(t, "pipe@example.com", "piped-password-12"))
	assert.Contains(t, r.errOut, "Password: ")
	assert.Contains(t, r.errOut, "Confirm:")
	// The last line may lack its newline.
	c.mustRun(t, cliOptions{stdin: "piped-password-13\npiped-password-13"}, "create-user", "--email", "pipe2@example.com")
	assert.True(t, c.passwordWorks(t, "pipe2@example.com", "piped-password-13"))

	// Default on a terminal: prompted twice without echo.
	c.mustRun(t, cliOptions{terminal: []string{"terminal-password-1", "terminal-password-1"}},
		"create-user", "--email", "tty@example.com")
	assert.True(t, c.passwordWorks(t, "tty@example.com", "terminal-password-1"))
}

func TestAdminCLICreateUserRefusesBadPasswordInput(t *testing.T) {
	c := newAdminCLITest(t)
	dir := t.TempDir()
	twoLines := filepath.Join(dir, "two-lines")
	require.NoError(t, os.WriteFile(twoLines, []byte("first-line-password\nsecond-line\n"), 0o600))
	good := filepath.Join(dir, "good")
	require.NoError(t, os.WriteFile(good, []byte("a-good-password-1\n"), 0o600))

	for _, tc := range []struct {
		name string
		o    cliOptions
		args []string
		want string
	}{
		{"the old --password flag", cliOptions{}, []string{"--password", "flag-password-123"}, "flag provided but not defined: -password"},
		{"both sources", cliOptions{stdin: "x"}, []string{"--password-file", good, "--password-stdin"}, "not both"},
		{"two lines in the file", cliOptions{}, []string{"--password-file", twoLines}, "one line"},
		{"missing file", cliOptions{}, []string{"--password-file", filepath.Join(dir, "absent")}, "password file"},
		{"empty stdin", cliOptions{stdin: ""}, []string{"--password-stdin"}, "must not be empty"},
		{"mismatch on a pipe", cliOptions{stdin: "piped-password-12\nother-password-12\n"}, nil, "do not match"},
		{"one line on a pipe", cliOptions{stdin: "piped-password-12\n"}, nil, "confirmation"},
		{"mismatch on a terminal", cliOptions{terminal: []string{"terminal-password-1", "terminal-password-2"}}, nil, "do not match"},
		{"--password-stdin on a terminal", cliOptions{stdin: "typed-password-12\n", terminal: []string{}}, []string{"--password-stdin"}, "prompted without echo"},
		{"eleven characters", cliOptions{stdin: "eleven-char\n"}, []string{"--password-stdin"}, "at least 12 characters"},
		{"eleven characters, 22 bytes", cliOptions{stdin: "ääääääääääá\n"}, []string{"--password-stdin"}, "at least 12 characters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"create-user", "--email", "refused@example.com"}, tc.args...)
			r := c.run(t, tc.o, args...)
			require.Error(t, r.err)
			assert.Contains(t, r.err.Error()+r.errOut, tc.want)
			assert.False(t, c.userExists(t, "refused@example.com"), "no account is created")
		})
	}
	assert.Zero(t, c.auditCount(t), "nothing was created, nothing is audited")
}

func TestAdminCLICreateAdmin(t *testing.T) {
	c := newAdminCLITest(t)
	ctx := context.Background()

	// A new account has no verified address; promotion needs the flag.
	r := c.run(t, cliOptions{stdin: "admin-password-12\n"}, "create-admin", "--email", "boss@example.com", "--password-stdin")
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "--allow-unverified")
	assert.False(t, c.userExists(t, "boss@example.com"), "nothing is created without the flag")

	r = c.run(t, cliOptions{stdin: "short-pw-11\n"}, "create-admin", "--email", "boss@example.com", "--password-stdin", "--allow-unverified")
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "at least 12 characters")
	assert.False(t, c.userExists(t, "boss@example.com"))

	c.mustRun(t, cliOptions{stdin: "admin-password-12\n"}, "create-admin", "--email", "boss@example.com", "--password-stdin", "--allow-unverified")
	u, err := c.users.FindByEmail(ctx, "boss@example.com")
	require.NoError(t, err)
	assert.True(t, u.IsAdmin)
	assert.True(t, c.passwordWorks(t, "boss@example.com", "admin-password-12"))
}

func TestAdminCLICreateAdminReportsAnAccountThatWasNotPromoted(t *testing.T) {
	c := newAdminCLITest(t)
	ctx := context.Background()

	// Make the promotion fail. The trigger name starts with
	// dbtest_fail_delete_ so that dbtest.Pool removes it should this test be
	// killed before its cleanup.
	_, err := c.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION admin_cli_test_no_promote() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN
			IF NEW.is_admin AND NOT OLD.is_admin THEN RAISE EXCEPTION 'injected promote failure'; END IF;
			RETURN NEW;
		END $$`)
	require.NoError(t, err)
	_, err = c.pool.Exec(ctx, `CREATE TRIGGER dbtest_fail_delete_admin_cli_promote BEFORE UPDATE ON users
		FOR EACH ROW EXECUTE FUNCTION admin_cli_test_no_promote()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = c.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS dbtest_fail_delete_admin_cli_promote ON users`)
		_, _ = c.pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS admin_cli_test_no_promote()`)
	})

	r := c.run(t, cliOptions{stdin: "admin-password-12\n"}, "create-admin", "--email", "half@example.com", "--password-stdin", "--allow-unverified")
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "was created but not promoted")
	assert.Contains(t, r.err.Error(), "half@example.com")
	u, err := c.users.FindByEmail(ctx, "half@example.com")
	require.NoError(t, err, "the account exists")
	assert.False(t, u.IsAdmin)

	rows := c.auditRows(t, "cli.create-admin")
	require.Len(t, rows, 1, "the created account is audited")
	assert.Equal(t, float64(u.ID), rows[0].metadata["target_user_id"])
	assert.Equal(t, false, rows[0].metadata["promoted"])
}

// ---- promotion needs a verified address ----

func TestAdminCLIPromoteUserNeedsAVerifiedAddress(t *testing.T) {
	c := newAdminCLITest(t)
	ctx := context.Background()
	unverified := dbtest.InsertUser(t, c.pool, "unverified@example.com")
	verified := dbtest.InsertUser(t, c.pool, "verified@example.com")
	require.NoError(t, c.users.MarkEmailVerified(ctx, verified))

	r := c.run(t, cliOptions{}, "promote-user", "--email", "unverified@example.com")
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "not verified")
	u, err := c.users.FindByID(ctx, unverified)
	require.NoError(t, err)
	assert.False(t, u.IsAdmin)
	assert.Empty(t, c.auditRows(t, "cli.promote-user"))

	c.mustRun(t, cliOptions{}, "promote-user", "--email", "unverified@example.com", "--allow-unverified")
	u, err = c.users.FindByID(ctx, unverified)
	require.NoError(t, err)
	assert.True(t, u.IsAdmin)

	c.mustRun(t, cliOptions{}, "promote-user", "--email", "verified@example.com")
	u, err = c.users.FindByID(ctx, verified)
	require.NoError(t, err)
	assert.True(t, u.IsAdmin)
}

// ---- disable, enable, list tokens ----

func TestAdminCLIDisableAndEnableUser(t *testing.T) {
	c := newAdminCLITest(t)
	ctx := context.Background()
	target := dbtest.InsertUser(t, c.pool, "target@example.com")
	raw, _, err := c.tokens.Issue(ctx, target, "laptop")
	require.NoError(t, err)

	r := c.mustRun(t, cliOptions{}, "disable-user", "--email", "target@example.com")
	u, err := c.users.FindByID(ctx, target)
	require.NoError(t, err)
	assert.True(t, u.DisabledAt.Valid)
	_, err = c.tokens.Verify(ctx, raw)
	assert.ErrorIs(t, err, tokens.ErrInvalidToken, "the user's tokens stop working")
	assert.Contains(t, r.errOut, "closes the open tunnels of this account within 30s", "the operator learns when open tunnels end")

	r = c.mustRun(t, cliOptions{}, "enable-user", "--email", "target@example.com")
	u, err = c.users.FindByID(ctx, target)
	require.NoError(t, err)
	assert.False(t, u.DisabledAt.Valid)
	_, err = c.tokens.Verify(ctx, raw)
	assert.NoError(t, err, "the token that was not revoked works again")
	// The operator is told so, and how to list and revoke the tokens.
	assert.Contains(t, r.errOut, "API tokens of this account that were not revoked work again")
	assert.Contains(t, r.errOut, "tunneld admin list-tokens --config "+c.cfgPath+" --email target@example.com")
	assert.Contains(t, r.errOut, "tunneld admin revoke-token --config "+c.cfgPath+" --id")
	assert.Contains(t, r.errOut, "Revoke all API tokens")
	assert.NotContains(t, r.out, "work again", "the note goes to stderr, the JSON stays clean")

	// Enabling an account that is not disabled changes nothing: no note.
	r = c.mustRun(t, cliOptions{}, "enable-user", "--email", "target@example.com")
	assert.NotContains(t, r.errOut, "work again")

	// The last active admin cannot be disabled.
	admin := dbtest.InsertUser(t, c.pool, "only-admin@example.com")
	require.NoError(t, c.users.Promote(ctx, admin))
	r = c.run(t, cliOptions{}, "disable-user", "--email", "only-admin@example.com")
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "would leave no active admin")
	u, err = c.users.FindByID(ctx, admin)
	require.NoError(t, err)
	assert.False(t, u.DisabledAt.Valid)
}

// The notes after a disable, a token revoke and a grant say what happens to
// the tunnels that are open on the running server: the server's periodic
// check closes those of a disabled account or a revoked token within
// tunnel.revalidate_interval, unless the check is switched off; a tunnel of
// another user on a granted name or port is not closed by it.
func TestAdminCLINotesAboutOpenTunnels(t *testing.T) {
	ctx := context.Background()

	t.Run("revalidation on (default 30s)", func(t *testing.T) {
		c := newAdminCLITest(t)
		target := dbtest.InsertUser(t, c.pool, "target@example.com")
		dbtest.InsertUser(t, c.pool, "owner@example.com")
		_, tok, err := c.tokens.Issue(ctx, target, "laptop")
		require.NoError(t, err)

		r := c.mustRun(t, cliOptions{}, "revoke-token", "--id", fmt.Sprint(tok.ID))
		assert.Contains(t, r.errOut, "the running server closes the open tunnels of this token within 30s")
		assert.Contains(t, r.errOut, "tunnel.revalidate_interval")
		assert.Contains(t, r.errOut, "Connections page", "how to close them at once")
		assert.NotContains(t, r.errOut, "stay connected")

		r = c.mustRun(t, cliOptions{}, "disable-user", "--email", "target@example.com")
		assert.Contains(t, r.errOut, "the running server closes the open tunnels of this account within 30s")
		assert.NotContains(t, r.errOut, "stay connected")

		r = c.mustRun(t, cliOptions{}, "reserve-subdomain", "--email", "owner@example.com", "--subdomain", "granted")
		assert.Contains(t, r.errOut, "another user has a tunnel open on this subdomain")
		assert.Contains(t, r.errOut, "closes only the tunnels of disabled accounts and revoked tokens")
		assert.Contains(t, r.errOut, "Connections page")
	})

	t.Run("configured interval", func(t *testing.T) {
		c := newAdminCLITest(t)
		c.appendConfig(t, "tunnel:\n  revalidate_interval: 2m\n")
		dbtest.InsertUser(t, c.pool, "target@example.com")
		r := c.mustRun(t, cliOptions{}, "disable-user", "--email", "target@example.com")
		assert.Contains(t, r.errOut, "of this account within 2m0s")
	})

	t.Run("revalidation switched off", func(t *testing.T) {
		c := newAdminCLITest(t)
		c.appendConfig(t, "tunnel:\n  revalidate_interval: -1s\n")
		target := dbtest.InsertUser(t, c.pool, "target@example.com")
		_, tok, err := c.tokens.Issue(ctx, target, "laptop")
		require.NoError(t, err)

		r := c.mustRun(t, cliOptions{}, "revoke-token", "--id", fmt.Sprint(tok.ID))
		assert.Contains(t, r.errOut, "tunnel.revalidate_interval is switched off")
		assert.Contains(t, r.errOut, "tunnels of this token that are open on the running server stay connected until they end")
		assert.Contains(t, r.errOut, "Connections page")

		r = c.mustRun(t, cliOptions{}, "disable-user", "--email", "target@example.com")
		assert.Contains(t, r.errOut, "tunnels of this account that are open on the running server stay connected until they end")
	})
}

func TestAdminCLIListTokens(t *testing.T) {
	c := newAdminCLITest(t)
	ctx := context.Background()
	owner := dbtest.InsertUser(t, c.pool, "owner@example.com")
	other := dbtest.InsertUser(t, c.pool, "other@example.com")
	raw1, t1, err := c.tokens.Issue(ctx, owner, "laptop")
	require.NoError(t, err)
	_, t2, err := c.tokens.Issue(ctx, owner, "ci")
	require.NoError(t, err)
	_, gone, err := c.tokens.Issue(ctx, owner, "old")
	require.NoError(t, err)
	_, err = c.tokens.RevokeAny(ctx, gone.ID)
	require.NoError(t, err)
	_, _, err = c.tokens.Issue(ctx, other, "theirs")
	require.NoError(t, err)

	r := c.mustRun(t, cliOptions{}, "list-tokens", "--email", "owner@example.com")
	var rows []map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.out), &rows))
	require.Len(t, rows, 2, "the active tokens of that user")
	ids := map[float64]string{}
	for _, row := range rows {
		ids[row["id"].(float64)] = row["name"].(string)
		assert.NotEmpty(t, row["token_prefix"])
		assert.NotContains(t, row, "token")
	}
	assert.Equal(t, map[float64]string{float64(t1.ID): "laptop", float64(t2.ID): "ci"}, ids)
	assert.NotContains(t, r.out, raw1, "the raw token is never shown again")

	r = c.run(t, cliOptions{}, "list-tokens", "--email", "nobody@example.com")
	require.Error(t, r.err)

	// revoke-token with an ID that does not exist: an error, nothing audited.
	r = c.run(t, cliOptions{}, "revoke-token", "--id", "999999")
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "no token with id 999999")
	assert.Empty(t, c.auditRows(t, "cli.revoke-token"))
}

func TestAdminCLIPasswordFileModeWarning(t *testing.T) {
	assert.Contains(t, passwordFileModeWarning(0o644, "linux"), "chmod 600")
	assert.Contains(t, passwordFileModeWarning(0o640, "linux"), "group or others")
	assert.Contains(t, passwordFileModeWarning(0o604, "darwin"), "0604")
	assert.Empty(t, passwordFileModeWarning(0o600, "linux"))
	assert.Empty(t, passwordFileModeWarning(0o400, "linux"))
	assert.Empty(t, passwordFileModeWarning(0o666, "windows"), "the bits say nothing about a Windows ACL")
}

func TestAdminCLIListCommandsDoNotMigrate(t *testing.T) {
	c := newAdminCLITest(t)
	dbtest.InsertUser(t, c.pool, "someone@example.com")

	calls := 0
	prev := adminMigrate
	adminMigrate = func(ctx context.Context, pool *pgxpool.Pool) error {
		calls++
		return prev(ctx, pool)
	}
	defer func() { adminMigrate = prev }()

	c.mustRun(t, cliOptions{}, "list-users")
	c.mustRun(t, cliOptions{}, "list-tokens", "--email", "someone@example.com")
	c.mustRun(t, cliOptions{}, "list-reservations")
	c.mustRun(t, cliOptions{}, "list-udp-ports")
	assert.Zero(t, calls, "read-only commands leave the schema alone")

	c.mustRun(t, cliOptions{}, "mark-verified", "--email", "someone@example.com")
	assert.Equal(t, 1, calls, "a command that changes state still migrates")
}

// ---- Approval: a grant approves the account it is given to ----

func TestAdminCLIReserveSubdomainApprovesAPendingAccount(t *testing.T) {
	c := newAdminCLITest(t)
	ctx := context.Background()
	id := dbtest.InsertUser(t, c.pool, "pending@example.com")

	c.mustRun(t, cliOptions{}, "reserve-subdomain", "--email", "pending@example.com", "--subdomain", "granted")
	u, err := c.users.FindByID(ctx, id)
	require.NoError(t, err)
	assert.True(t, users.IsApproved(u), "the account can use what it was given")
	rows := c.auditRows(t, "cli.approve-user")
	require.Len(t, rows, 1, "the approval has its own audit entry")
	assert.Nil(t, rows[0].actor)
	assert.Equal(t, float64(id), rows[0].metadata["target_user_id"])
	assert.Equal(t, "pending@example.com", rows[0].metadata["target_email"])
	assert.Equal(t, "reserve-subdomain", rows[0].metadata["via"])

	// The account is approved now: a second grant approves nothing.
	c.mustRun(t, cliOptions{}, "reserve-subdomain", "--email", "pending@example.com", "--subdomain", "second")
	assert.Len(t, c.auditRows(t, "cli.approve-user"), 1)
}

// In open mode no account waits: reject-user refuses every account and
// deletes nothing, not even one with approved_at NULL.
func TestAdminCLIRejectUserIsRefusedInOpenMode(t *testing.T) {
	c := newAdminCLITest(t)
	dbtest.InsertUser(t, c.pool, "never-approved@example.com")

	r := c.run(t, cliOptions{}, "reject-user", "--email", "never-approved@example.com")
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "auth.signup is open")
	assert.Contains(t, r.err.Error(), "nothing was deleted")
	assert.True(t, c.userExists(t, "never-approved@example.com"), "the account stays")
	assert.Empty(t, c.auditRows(t, "cli.reject-user"))
}

// The CLI runs in its own process and can run between switching the config
// to approval or closed and the server's first start in that mode, before
// the server has approved the accounts in use. Such an account must not
// show up as waiting, and reject-user must not delete it with its tokens.
func TestAdminCLIApprovalLeavesAccountsInUseAlone(t *testing.T) {
	for _, mode := range []string{"approval", "closed"} {
		t.Run(mode, func(t *testing.T) {
			c := newAdminCLITest(t)
			ctx := context.Background()
			holder := dbtest.InsertUser(t, c.pool, "holder@example.com")
			_, err := c.pool.Exec(ctx, `INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, revoked_at)
				VALUES ($1, 'old', '\x03', 'cccccccc', now())`, holder)
			require.NoError(t, err)
			waiting := dbtest.InsertUser(t, c.pool, "waiting@example.com")
			c.writeConfig(t, mode, "")

			// list-pending changes nothing (no migration, no approval) and
			// still leaves the holder out.
			r := c.mustRun(t, cliOptions{}, "list-pending")
			var listed []map[string]any
			require.NoError(t, json.Unmarshal([]byte(r.out), &listed))
			require.Len(t, listed, 1, "only the account that is not in use waits: %s", r.out)
			assert.Equal(t, "waiting@example.com", listed[0]["email"])
			u, err := c.users.FindByID(ctx, holder)
			require.NoError(t, err)
			require.False(t, users.IsApproved(u), "a list command approves nobody")

			// A command that changes state approves the accounts in use
			// first, as the server does at start; reject-user then refuses.
			r = c.run(t, cliOptions{}, "reject-user", "--email", "holder@example.com")
			require.Error(t, r.err)
			assert.Contains(t, r.err.Error(), "does not wait for approval (it is approved, an admin, disabled, or in use)")
			assert.Contains(t, r.errOut, "1 account(s) in use")
			u, err = c.users.FindByID(ctx, holder)
			require.NoError(t, err, "the account stays")
			assert.True(t, users.IsApproved(u), "the account in use is approved")
			assert.Equal(t, 1, countTokens(t, c.pool, holder), "its token stays")
			assert.Empty(t, c.auditRows(t, "cli.reject-user"))

			// The account that waits is rejected; the next command finds
			// nothing more to approve and says nothing about it.
			r = c.mustRun(t, cliOptions{}, "reject-user", "--email", "waiting@example.com")
			assert.NotContains(t, r.errOut, "account(s) in use")
			_, err = c.users.FindByID(ctx, waiting)
			assert.ErrorIs(t, err, users.ErrNotFound)
			assert.Len(t, c.auditRows(t, "cli.reject-user"), 1)
		})
	}
}

func countTokens(t *testing.T, pool *pgxpool.Pool, userID int64) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), `SELECT count(*) FROM api_tokens WHERE user_id = $1`, userID).Scan(&n))
	return n
}

// approve-user mails the owner only where the mail means something: in
// approval and closed mode, and not to a disabled account.
func TestAdminCLIApproveUserMailsOnlyWhereItMatters(t *testing.T) {
	c := newAdminCLITest(t)
	ctx := context.Background()
	tm := mail.NewTestMailer()
	prev := adminMailer
	adminMailer = func(*config.Config) mail.Mailer { return tm }
	t.Cleanup(func() { adminMailer = prev })
	const mailConfig = `mail:
  from: "noreply@tunnel.test"
  smtp:
    host: "smtp.tunnel.test"
    port: 2525
frontend:
  public_base_url: "https://app.tunnel.test"
`
	dbtest.InsertUser(t, c.pool, "open@example.com")
	disabled := dbtest.InsertUser(t, c.pool, "disabled@example.com")
	_, err := c.pool.Exec(ctx, `UPDATE users SET disabled_at = now() WHERE id = $1`, disabled)
	require.NoError(t, err)
	dbtest.InsertUser(t, c.pool, "waiting@example.com")

	c.writeConfig(t, "", mailConfig)
	c.mustRun(t, cliOptions{}, "approve-user", "--email", "open@example.com")
	c.writeConfig(t, "approval", mailConfig)
	c.mustRun(t, cliOptions{}, "approve-user", "--email", "disabled@example.com")
	c.mustRun(t, cliOptions{}, "approve-user", "--email", "waiting@example.com")

	for _, email := range []string{"open@example.com", "disabled@example.com", "waiting@example.com"} {
		u, err := c.users.FindByEmail(ctx, email)
		require.NoError(t, err)
		assert.True(t, users.IsApproved(u), "%s is approved", email)
	}
	assert.Len(t, c.auditRows(t, "cli.approve-user"), 3, "every approval is logged")
	sent := tm.Sent()
	require.Len(t, sent, 1, "no mail in open mode, none to a disabled account")
	assert.Equal(t, "waiting@example.com", sent[0].To)
	assert.Contains(t, sent[0].TextBody, "https://app.tunnel.test/login")
}

// ---- reservation commands ----

func TestAdminCLIReservationCommands(t *testing.T) {
	c := newAdminCLITest(t)
	ctx := context.Background()
	owner := dbtest.InsertUser(t, c.pool, "owner@example.com")
	dbtest.InsertUser(t, c.pool, "second@example.com")

	// Normalised, and through the grant path: the per-user limit of Reserve
	// (10) does not apply.
	for i := 0; i < reservations.DefaultMaxSubdomainsPerUser; i++ {
		require.NoError(t, c.res.GrantSubdomain(ctx, fmt.Sprintf("granted-%02d", i), owner))
	}
	r := c.mustRun(t, cliOptions{}, "reserve-subdomain", "--email", "owner@example.com", "--subdomain", "MyApp")
	assert.Contains(t, r.out, `"subdomain": "myapp"`)
	assert.Contains(t, r.errOut, "another user has a tunnel open on this subdomain", "the CLI cannot evict; it says so")
	got, reserved, err := c.res.Owner(ctx, "myapp")
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, owner, got)

	for _, tc := range []struct{ name, want string }{
		{"admin", "reserved for system use"},
		{"../../users/7/promote?x=", "invalid subdomain"},
		{"a.b", "invalid subdomain"},
		{"MYAPP", "already reserved"},
	} {
		r := c.run(t, cliOptions{}, "reserve-subdomain", "--email", "second@example.com", "--subdomain", tc.name)
		require.Error(t, r.err, tc.name)
		assert.Contains(t, r.err.Error(), tc.want, tc.name)
		for _, raw := range []string{"duplicate", "SQLSTATE", "23505"} {
			assert.NotContains(t, r.err.Error(), raw, tc.name)
		}
	}

	// release-subdomain finds the normal form, and a stored name that fails
	// the check exactly as written.
	c.mustRun(t, cliOptions{}, "release-subdomain", "--subdomain", "MyApp")
	_, reserved, err = c.res.Owner(ctx, "myapp")
	require.NoError(t, err)
	assert.False(t, reserved)
	_, err = c.pool.Exec(ctx, `INSERT INTO reserved_subdomains (subdomain, user_id) VALUES ('bad/name', $1)`, owner)
	require.NoError(t, err)
	c.mustRun(t, cliOptions{}, "release-subdomain", "--subdomain", "bad/name")
	_, reserved, err = c.res.Owner(ctx, "bad/name")
	require.NoError(t, err)
	assert.False(t, reserved)

	// UDP ports: strict parsing and the configured range (30000 to 40000).
	for _, tc := range []struct{ port, want string }{
		{"29999", "outside the configured"},
		{"40001", "outside the configured"},
		{"0x7530", "invalid port"},
		{"65536", "invalid port"},
		{"4294997296", "invalid port"},
		{"0", "invalid port"},
	} {
		r := c.run(t, cliOptions{}, "reserve-udp-port", "--email", "owner@example.com", "--port", tc.port)
		require.Error(t, r.err, tc.port)
		assert.Contains(t, r.err.Error(), tc.want, tc.port)
	}
	var n int
	require.NoError(t, c.pool.QueryRow(ctx, `SELECT count(*) FROM reserved_udp_ports`).Scan(&n))
	assert.Zero(t, n)

	r = c.mustRun(t, cliOptions{}, "reserve-udp-port", "--email", "owner@example.com", "--port", "30000")
	assert.Contains(t, r.errOut, "another user has a tunnel open on this UDP port")
	got, reserved, err = c.res.OwnerUDPPort(ctx, 30000)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, owner, got)
	r = c.run(t, cliOptions{}, "reserve-udp-port", "--email", "second@example.com", "--port", "30000")
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "already reserved")

	c.mustRun(t, cliOptions{}, "release-udp-port", "--port", "30000")
	_, reserved, err = c.res.OwnerUDPPort(ctx, 30000)
	require.NoError(t, err)
	assert.False(t, reserved)
}

// queryCounter is a pgx tracer that counts the queries of a pool.
type queryCounter struct{ n atomic.Int32 }

func (q *queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	q.n.Add(1)
	return ctx
}

func (q *queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// countAdminQueries makes the admin commands of the test open their pool
// with a tracer that counts the queries.
func countAdminQueries(t *testing.T) *queryCounter {
	t.Helper()
	counter := &queryCounter{}
	prev := adminOpenPool
	adminOpenPool = func(ctx context.Context, url string) (*pgxpool.Pool, error) {
		cfg, err := pgxpool.ParseConfig(url)
		if err != nil {
			return nil, err
		}
		cfg.ConnConfig.Tracer = counter
		return pgxpool.NewWithConfig(ctx, cfg)
	}
	t.Cleanup(func() { adminOpenPool = prev })
	return counter
}

// list-udp-ports without --email reads every reservation with one query,
// however many accounts there are, and prints what it printed before: the
// rows ordered by user id, then port.
func TestAdminCLIListUDPPortsUsesOneQuery(t *testing.T) {
	c := newAdminCLITest(t)
	ctx := context.Background()
	first := dbtest.InsertUser(t, c.pool, "first@example.com")
	_, err := c.pool.Exec(ctx, `INSERT INTO users (email, password_hash)
		SELECT 'filler-' || g || '@example.com', 'test-placeholder-not-a-hash' FROM generate_series(1, 50) g`)
	require.NoError(t, err)
	last := dbtest.InsertUser(t, c.pool, "last@example.com")
	// The ports of the later account are the lower ones, so that the order
	// by user id differs from the order by port.
	for _, g := range []struct {
		port int
		user int64
	}{{30010, first}, {30002, first}, {30001, last}} {
		require.NoError(t, c.res.GrantUDPPort(ctx, g.port, g.user))
	}

	queries := countAdminQueries(t)
	r := c.mustRun(t, cliOptions{}, "list-udp-ports")
	assert.LessOrEqual(t, queries.n.Load(), int32(2), "one query for all reservations, not one per account")

	var rows []map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.out), &rows))
	type row struct {
		port, user float64
	}
	var got []row
	for _, m := range rows {
		assert.ElementsMatch(t, []string{"port", "user_id", "created_at"}, keysOf(m), "the fields of a row")
		assert.NotEmpty(t, m["created_at"])
		got = append(got, row{m["port"].(float64), m["user_id"].(float64)})
	}
	assert.Equal(t, []row{{30002, float64(first)}, {30010, float64(first)}, {30001, float64(last)}}, got)

	// No reservation: an empty list, not null.
	_, err = c.pool.Exec(ctx, `DELETE FROM reserved_udp_ports`)
	require.NoError(t, err)
	r = c.mustRun(t, cliOptions{}, "list-udp-ports")
	assert.Equal(t, "[]\n", r.out)
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---- every command that changes state writes cli.<command> ----

func TestAdminCLIStateChangingCommandsAreAudited(t *testing.T) {
	c := newAdminCLITest(t)
	ctx := context.Background()
	u1 := dbtest.InsertUser(t, c.pool, "one@example.com")
	require.NoError(t, c.users.MarkEmailVerified(ctx, u1))
	u2 := dbtest.InsertUser(t, c.pool, "two@example.com")
	require.NoError(t, c.users.MarkEmailVerified(ctx, u2))
	require.NoError(t, c.users.Promote(ctx, u2))

	stdin := cliOptions{stdin: "a-good-password-1\n"}
	steps := []struct {
		command string
		o       cliOptions
		args    []string
		want    map[string]any // metadata entries that must be there
	}{
		{"create-user", stdin, []string{"--email", "new@example.com", "--password-stdin"}, map[string]any{"target_email": "new@example.com"}},
		{"create-admin", stdin, []string{"--email", "boss@example.com", "--password-stdin", "--allow-unverified"}, map[string]any{"target_email": "boss@example.com", "promoted": true}},
		{"mark-verified", cliOptions{}, []string{"--email", "new@example.com"}, map[string]any{"target_email": "new@example.com"}},
		{"issue-token", cliOptions{}, []string{"--email", "one@example.com", "--name", "laptop"}, map[string]any{"target_user_id": float64(u1), "name": "laptop"}},
		{"reserve-subdomain", cliOptions{}, []string{"--email", "one@example.com", "--subdomain", "Audited"}, map[string]any{"target_user_id": float64(u1), "subdomain": "audited"}},
		{"release-subdomain", cliOptions{}, []string{"--subdomain", "audited"}, map[string]any{"target_user_id": float64(u1), "subdomain": "audited"}},
		{"reserve-udp-port", cliOptions{}, []string{"--email", "one@example.com", "--port", "31000"}, map[string]any{"target_user_id": float64(u1), "port": float64(31000)}},
		{"release-udp-port", cliOptions{}, []string{"--port", "31000"}, map[string]any{"target_user_id": float64(u1), "port": float64(31000)}},
		{"promote-user", cliOptions{}, []string{"--email", "one@example.com"}, map[string]any{"target_user_id": float64(u1)}},
		{"demote-user", cliOptions{}, []string{"--email", "one@example.com"}, map[string]any{"target_user_id": float64(u1)}},
		{"disable-user", cliOptions{}, []string{"--email", "one@example.com"}, map[string]any{"target_user_id": float64(u1)}},
		{"enable-user", cliOptions{}, []string{"--email", "one@example.com"}, map[string]any{"target_user_id": float64(u1)}},
	}
	for _, s := range steps {
		c.mustRun(t, s.o, append([]string{s.command}, s.args...)...)
		rows := c.auditRows(t, "cli."+s.command)
		require.Len(t, rows, 1, "audit rows for %s", s.command)
		assert.Nil(t, rows[0].actor, "%s: the CLI has no actor", s.command)
		assert.Contains(t, rows[0].metadata, "target_user_id", "%s: the account the action is about", s.command)
		for k, v := range s.want {
			assert.Equal(t, v, rows[0].metadata[k], "%s: metadata %s", s.command, k)
		}
	}

	// revoke-token: the token issued above.
	list, err := c.tokens.ListActiveByUser(ctx, u1)
	require.NoError(t, err)
	require.Len(t, list, 1)
	c.mustRun(t, cliOptions{}, "revoke-token", "--id", fmt.Sprint(list[0].ID))
	rows := c.auditRows(t, "cli.revoke-token")
	require.Len(t, rows, 1)
	assert.Nil(t, rows[0].actor)
	assert.Equal(t, float64(list[0].ID), rows[0].metadata["token_id"])
	assert.Equal(t, float64(u1), rows[0].metadata["target_user_id"])

	// No secret in any entry.
	var all []string
	r, err := c.pool.Query(ctx, `SELECT metadata::text FROM audit_log`)
	require.NoError(t, err)
	for r.Next() {
		var s string
		require.NoError(t, r.Scan(&s))
		all = append(all, s)
	}
	r.Close()
	joined := strings.Join(all, "\n")
	assert.NotContains(t, joined, "a-good-password-1")
	assert.NotContains(t, joined, tokens.TokenPrefix, "no raw token")

	// Read-only commands write nothing.
	before := c.auditCount(t)
	c.mustRun(t, cliOptions{}, "list-users")
	c.mustRun(t, cliOptions{}, "list-tokens", "--email", "one@example.com")
	c.mustRun(t, cliOptions{}, "list-reservations")
	c.mustRun(t, cliOptions{}, "list-udp-ports")
	assert.Equal(t, before, c.auditCount(t))
}
