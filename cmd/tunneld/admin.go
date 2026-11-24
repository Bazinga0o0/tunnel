package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/term"

	"github.com/Bazinga0o0/tunnel/internal/server/audit"
	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/db"
	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	mailtemplates "github.com/Bazinga0o0/tunnel/internal/server/mail/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// The process streams, the terminal and the schema migration of the admin
// commands. They are variables so that tests can replace them.
var (
	adminStdin  io.Reader = os.Stdin
	adminStdout io.Writer = os.Stdout
	adminStderr io.Writer = os.Stderr

	// stdinIsTerminal reports whether standard input is an interactive
	// terminal; readTerminalPassword reads one line from it without echo.
	stdinIsTerminal      = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	readTerminalPassword = func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) }

	// adminMigrate brings the schema up to date. Only commands that change
	// state call it.
	adminMigrate = db.MigrateUp

	// adminOpenPool opens the database pool of a command.
	adminOpenPool = db.Open

	// adminMailer returns the mailer of a command that sends mail.
	adminMailer = func(cfg *config.Config) mail.Mailer { return mail.NewSMTPMailer(smtpConfig(cfg)) }
)

// adminSubcommands is the list shown when no subcommand is given.
const adminSubcommands = "create-user|list-users|mark-verified|disable-user|enable-user|issue-token|list-tokens|revoke-token|" +
	"reserve-subdomain|release-subdomain|list-reservations|reserve-udp-port|release-udp-port|list-udp-ports|" +
	"gen-csrf-key|send-test-email|promote-user|demote-user|create-admin|approve-user|reject-user|list-pending"

// runAdmin dispatches `tunneld admin <subcommand> ...`.
func runAdmin(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("admin: subcommand required (%s)", adminSubcommands)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create-user":
		return adminCreateUser(rest)
	case "list-users":
		return adminListUsers(rest)
	case "mark-verified":
		return adminMarkVerified(rest)
	case "disable-user":
		return adminDisableUser(rest)
	case "enable-user":
		return adminEnableUser(rest)
	case "issue-token":
		return adminIssueToken(rest)
	case "list-tokens":
		return adminListTokens(rest)
	case "revoke-token":
		return adminRevokeToken(rest)
	case "reserve-subdomain":
		return adminReserveSubdomain(rest)
	case "release-subdomain":
		return adminReleaseSubdomain(rest)
	case "list-reservations":
		return adminListReservations(rest)
	case "reserve-udp-port":
		return adminReserveUDPPort(rest)
	case "release-udp-port":
		return adminReleaseUDPPort(rest)
	case "list-udp-ports":
		return adminListUDPPorts(rest)
	case "gen-csrf-key":
		return adminGenCSRFKey(rest)
	case "send-test-email":
		return adminSendTestEmail(rest)
	case "promote-user":
		return adminPromoteUser(rest)
	case "demote-user":
		return adminDemoteUser(rest)
	case "create-admin":
		return adminCreateAdmin(rest)
	case "approve-user":
		return adminApproveUser(rest)
	case "reject-user":
		return adminRejectUser(rest)
	case "list-pending":
		return adminListPending(rest)
	default:
		return fmt.Errorf("unknown admin subcommand: %q", sub)
	}
}

// newFlagSet returns a flag set whose usage and errors go to adminStderr.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(adminStderr)
	return fs
}

// adminEnv is what a command that talks to the database works with.
type adminEnv struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    *config.Config
	pool   *pgxpool.Pool
}

// Close ends the context and closes the pool.
func (e *adminEnv) Close() {
	e.cancel()
	e.pool.Close()
}

// The account services are built with the limits of the config, through the
// same functions as the server's (wiring.go).
func (e *adminEnv) userService() *users.Service {
	return users.NewServiceWithOptions(e.pool, userOptions(e.cfg))
}

func (e *adminEnv) tokenService() *tokens.Service {
	return tokens.NewServiceWithOptions(e.pool, tokenOptions(e.cfg))
}

func (e *adminEnv) reservationService() *reservations.Service {
	return reservations.NewServiceWithOptions(e.pool, reservationOptions(e.cfg))
}

// loadAdminConfig loads the config and prints its warnings on stderr.
func loadAdminConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintln(adminStderr, "warning:", w)
	}
	return cfg, nil
}

// openAdmin loads the config at cfgPath and opens a DB pool. With migrate
// set it first brings the schema up to date (idempotent) and then, in
// approval and closed mode, approves the accounts that are in use, as the
// server does at start (approveExistingIfRequired): a command that runs
// between switching the config and the server's first start in that mode
// must not take an admin or a token owner for an account that waits.
// Read-only commands pass false and leave the schema and the accounts
// alone. The caller closes the result.
func openAdmin(cfgPath string, migrate bool) (*adminEnv, error) {
	cfg, err := loadAdminConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	if cfg.Database.URL == "" {
		return nil, errors.New("admin commands require database.url to be configured")
	}
	// As at the server's start: no reservation takes the subdomain of a
	// registered service.
	for _, s := range cfg.Services {
		reservations.AddSystemReserved(s.Subdomain)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pool, err := adminOpenPool(ctx, cfg.Database.URL)
	if err != nil {
		cancel()
		return nil, err
	}
	env := &adminEnv{ctx: ctx, cancel: cancel, cfg: cfg, pool: pool}
	if migrate {
		if err := adminMigrate(ctx, pool); err != nil {
			env.Close()
			return nil, err
		}
		n, err := approveExistingIfRequired(ctx, cfg, env.userService(), nil)
		if err != nil {
			env.Close()
			return nil, err
		}
		if n > 0 {
			fmt.Fprintf(adminStderr, "Note: auth.signup is %s in this config; %d account(s) in use (admins, holders "+
				"of an API token or a reservation) were approved, as the server does at start.\n", cfg.Auth.SignupMode(), n)
		}
	}
	return env, nil
}

// cliAudit writes the audit entry of a command that changed state: action
// "cli.<command>", no actor (nobody is logged in) and no IP address.
// metadata must not hold secrets. A failed write is reported on stderr; the
// change has happened and is not undone.
func cliAudit(env *adminEnv, command string, metadata map[string]any) {
	if err := audit.NewService(env.pool).Log(env.ctx, nil, "cli."+command, metadata, netip.Addr{}); err != nil {
		fmt.Fprintf(adminStderr, "warning: %s: the audit log entry could not be written: %v\n", command, err)
	}
}

// approveFor approves the account u for command, which gives it something
// only an approved account can use (a token, a reservation, the admin role)
// or has just created it. An account that waited for approval gets its own
// audit entry, cli.approve-user with "via": command, as soon as the approval
// is stored, whatever becomes of the rest of the command. An approved
// account is left alone.
func approveFor(env *adminEnv, userSvc *users.Service, u *sqlcgen.User, command string) error {
	if users.IsApproved(u) {
		return nil
	}
	if err := userSvc.Approve(env.ctx, u.ID); err != nil {
		return err
	}
	cliAudit(env, "approve-user", map[string]any{"target_user_id": u.ID, "target_email": u.Email, "via": command})
	return nil
}

// openTunnelsNote tells the operator what becomes of the tunnels of a
// disabled account or a revoked token (what is "account" or "token") that
// are open on the running server. This process cannot reach them; the server
// closes them at its periodic check (tunnel.revalidate_interval, taken from
// this config), unless the check is switched off there.
func openTunnelsNote(cfg *config.Config, what string) string {
	if every := cfg.Tunnel.RevalidateEvery(); every > 0 {
		return fmt.Sprintf("Note: the running server closes the open tunnels of this %s within %s "+
			"(tunnel.revalidate_interval); no new ones can be opened. "+
			"To close them at once, use the Connections page of the admin panel.", what, every)
	}
	return fmt.Sprintf("Note: tunnel.revalidate_interval is switched off in this config, so the tunnels of this %s "+
		"that are open on the running server stay connected until they end; no new ones can be opened. "+
		"Close them on the Connections page of the admin panel.", what)
}

// grantTunnelNote is the note after a grant: the panel closes another user's
// tunnel on a granted name or port, this process cannot, and the server's
// periodic check does not either.
const grantTunnelNote = "Note: if another user has a tunnel open on this %s on the running server, it stays " +
	"connected until it ends; the server's periodic check closes only the tunnels of disabled accounts and " +
	"revoked tokens. Close it on the Connections page of the admin panel."

func writeJSON(v any) error {
	enc := json.NewEncoder(adminStdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func tsOrEmpty(t time.Time, valid bool) string {
	if !valid {
		return ""
	}
	return t.Format(time.RFC3339)
}

// maxPasswordInput bounds what is read as a password from a file or a pipe.
// The users service refuses anything longer than users.MaxPasswordBytes
// anyway; the bound only keeps a wrong file from being read whole.
const maxPasswordInput = 4096

// addPasswordFlags adds --password-file and --password-stdin to fs.
func addPasswordFlags(fs *flag.FlagSet) (file *string, stdin *bool) {
	file = fs.String("password-file", "", "read the password from this file (one line)")
	stdin = fs.Bool("password-stdin", false, "read the password from standard input (one line)")
	return file, stdin
}

// readNewPassword returns the password for a new account:
//   - with passwordFile: the file's content without its line ending;
//   - with passwordStdin: standard input without its line ending;
//   - otherwise, on a terminal: entered twice, without echo;
//   - otherwise (a pipe): two lines, the password and its confirmation, read
//     through one reader.
//
// The password never appears on the command line. An empty password is an
// error; the length rules are the users service's.
func readNewPassword(passwordFile string, passwordStdin bool) (string, error) {
	var (
		pw  string
		err error
	)
	switch {
	case passwordFile != "" && passwordStdin:
		return "", errors.New("use --password-file or --password-stdin, not both")
	case passwordFile != "":
		var f *os.File
		f, err = os.Open(passwordFile)
		if err != nil {
			return "", fmt.Errorf("password file: %w", err)
		}
		defer f.Close()
		if fi, serr := f.Stat(); serr == nil {
			if w := passwordFileModeWarning(fi.Mode(), runtime.GOOS); w != "" {
				fmt.Fprintln(adminStderr, w)
			}
		}
		pw, err = readPasswordInput(f, "password file")
	case passwordStdin:
		// On a terminal the typed password would be echoed; the prompt
		// (no flag) reads it without echo.
		if stdinIsTerminal() {
			return "", errors.New("--password-stdin reads a pipe or a file, and standard input is a terminal " +
				"(the password would be echoed); leave out --password-stdin to be prompted without echo")
		}
		pw, err = readPasswordInput(adminStdin, "standard input")
	case stdinIsTerminal():
		pw, err = readConfirmedPassword(func() (string, error) {
			b, err := readTerminalPassword()
			fmt.Fprintln(adminStderr)
			return string(b), err
		})
	default:
		// One reader for both lines: a reader per line would buffer the
		// confirmation in the first one and find nothing for the second.
		br := bufio.NewReader(io.LimitReader(adminStdin, 2*(maxPasswordInput+2)))
		pw, err = readConfirmedPassword(func() (string, error) { return readPasswordLine(br) })
	}
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", errors.New("password must not be empty")
	}
	return pw, nil
}

// passwordFileModeWarning returns a warning when a password file can be read
// by its group or by others, and "" otherwise. On Windows the permission
// bits do not describe the file's ACL, so it says nothing there. The file is
// used anyway; the warning only tells the operator to tighten it.
func passwordFileModeWarning(mode os.FileMode, goos string) string {
	if goos == "windows" || mode.Perm()&0o077 == 0 {
		return ""
	}
	return fmt.Sprintf("warning: the password file is accessible to group or others (mode %04o); "+
		"restrict it to its owner (chmod 600)", mode.Perm())
}

// readConfirmedPassword prompts for the password and its confirmation and
// reads each with next.
func readConfirmedPassword(next func() (string, error)) (string, error) {
	fmt.Fprint(adminStderr, "Password: ")
	first, err := next()
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	fmt.Fprint(adminStderr, "Confirm:  ")
	second, err := next()
	if err != nil {
		return "", fmt.Errorf("read password confirmation: %w", err)
	}
	if first != second {
		return "", errors.New("passwords do not match")
	}
	return first, nil
}

// readPasswordLine reads one line from br without its line ending. The last
// line of the input may lack the newline.
func readPasswordLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	return strings.TrimSuffix(line, "\r"), nil
}

// readPasswordInput reads a password that is the whole of r (a file or
// standard input): at most maxPasswordInput bytes, one line, the line ending
// removed. what names the source in errors.
func readPasswordInput(r io.Reader, what string) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxPasswordInput+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", what, err)
	}
	if len(b) > maxPasswordInput {
		return "", fmt.Errorf("%s is too long", what)
	}
	s := strings.TrimSuffix(string(b), "\n")
	s = strings.TrimSuffix(s, "\r")
	if strings.ContainsAny(s, "\r\n") {
		return "", fmt.Errorf("%s must hold the password on one line", what)
	}
	return s, nil
}

// adminCreateUser: tunneld admin create-user --config PATH --email EMAIL [--password-file PATH | --password-stdin]
//
// The password is one an operator sets, so the rule for admin-set passwords
// applies (12 characters).
func adminCreateUser(args []string) error {
	fs := newFlagSet("admin create-user")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "user email")
	pwFile, pwStdin := addPasswordFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" {
		return fmt.Errorf("create-user: --config and --email are required")
	}

	pw, err := readNewPassword(*pwFile, *pwStdin)
	if err != nil {
		return err
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	userSvc := env.userService()
	u, err := userSvc.CreateWithAdminPassword(env.ctx, *email, pw)
	if err != nil {
		return err
	}
	// An account the operator creates does not wait for approval.
	if err := approveFor(env, userSvc, u, "create-user"); err != nil {
		// The account exists now; the entry and the message say so.
		cliAudit(env, "create-user", map[string]any{"target_user_id": u.ID, "target_email": u.Email, "approved": false})
		return fmt.Errorf("create-user: the account %s (id %d) was created but not approved: %w", u.Email, u.ID, err)
	}
	cliAudit(env, "create-user", map[string]any{"target_user_id": u.ID, "target_email": u.Email, "approved": true})
	return writeJSON(map[string]any{
		"id":         u.ID,
		"email":      u.Email,
		"created_at": tsOrEmpty(u.CreatedAt.Time, u.CreatedAt.Valid),
	})
}

// adminListUsers: tunneld admin list-users --config PATH
func adminListUsers(args []string) error {
	fs := newFlagSet("admin list-users")
	cfgPath := fs.String("config", "", "path to YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("list-users: --config is required")
	}

	env, err := openAdmin(*cfgPath, false)
	if err != nil {
		return err
	}
	defer env.Close()

	userSvc := env.userService()
	rows, err := userSvc.List(env.ctx)
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{
			"id":          r.ID,
			"email":       r.Email,
			"created_at":  tsOrEmpty(r.CreatedAt.Time, r.CreatedAt.Valid),
			"disabled_at": tsOrEmpty(r.DisabledAt.Time, r.DisabledAt.Valid),
		})
	}
	return writeJSON(out)
}

// adminMarkVerified: tunneld admin mark-verified --config PATH --email EMAIL
//
// Developer bypass for the /verify email link. Sets email_verified_at = now()
// for the target user so they can create tokens / reservations without
// needing to click an actual verification email.
func adminMarkVerified(args []string) error {
	fs := newFlagSet("admin mark-verified")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "user email")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" {
		return fmt.Errorf("mark-verified: --config and --email are required")
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	userSvc := env.userService()
	u, err := userSvc.FindByEmail(env.ctx, *email)
	if err != nil {
		return err
	}
	if err := userSvc.MarkEmailVerified(env.ctx, u.ID); err != nil {
		return err
	}
	cliAudit(env, "mark-verified", map[string]any{"target_user_id": u.ID, "target_email": u.Email})
	return writeJSON(map[string]any{
		"id":       u.ID,
		"email":    u.Email,
		"verified": true,
	})
}

// adminDisableUser: tunneld admin disable-user --config PATH --email EMAIL
//
// Disables the account: its web sessions and open password resets are
// deleted and its API tokens stop verifying. The last active admin cannot be
// disabled. Tunnels that are open on the running server are out of reach of
// this process; the output says so.
func adminDisableUser(args []string) error {
	fs := newFlagSet("admin disable-user")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "user email")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" {
		return fmt.Errorf("disable-user: --config and --email are required")
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	userSvc := env.userService()
	u, err := userSvc.FindByEmail(env.ctx, *email)
	if err != nil {
		return err
	}
	if err := userSvc.Disable(env.ctx, nil, u.ID); err != nil {
		if errors.Is(err, users.ErrLastAdmin) {
			return fmt.Errorf("disable-user: %w — promote another user to admin first", err)
		}
		return err
	}
	cliAudit(env, "disable-user", map[string]any{"target_user_id": u.ID, "target_email": u.Email})
	fmt.Fprintln(adminStderr, openTunnelsNote(env.cfg, "account"))
	return writeJSON(map[string]any{
		"id":       u.ID,
		"email":    u.Email,
		"disabled": true,
	})
}

// enabledTokensNote tells the operator, after an account was enabled again,
// that its API tokens that were not revoked work again (a disable stops
// them only while it lasts), and how to list and revoke them.
func enabledTokensNote(cfgPath, email string) string {
	return fmt.Sprintf("Note: the API tokens of this account that were not revoked work again, "+
		"including any created while the account was compromised. List them with "+
		"`tunneld admin list-tokens --config %s --email %s` and revoke one with "+
		"`tunneld admin revoke-token --config %s --id ID`, or use \"Revoke all API tokens\" "+
		"on the account's page in the admin panel.", cfgPath, email, cfgPath)
}

// adminEnableUser: tunneld admin enable-user --config PATH --email EMAIL
//
// When the account was disabled, the note on stderr says that its API
// tokens that were not revoked work again.
func adminEnableUser(args []string) error {
	fs := newFlagSet("admin enable-user")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "user email")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" {
		return fmt.Errorf("enable-user: --config and --email are required")
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	userSvc := env.userService()
	u, err := userSvc.FindByEmail(env.ctx, *email)
	if err != nil {
		return err
	}
	if err := userSvc.Enable(env.ctx, u.ID); err != nil {
		return err
	}
	cliAudit(env, "enable-user", map[string]any{"target_user_id": u.ID, "target_email": u.Email})
	if u.DisabledAt.Valid {
		fmt.Fprintln(adminStderr, enabledTokensNote(*cfgPath, u.Email))
	}
	return writeJSON(map[string]any{
		"id":       u.ID,
		"email":    u.Email,
		"disabled": false,
	})
}

// adminIssueToken: tunneld admin issue-token --config PATH --email EMAIL --name NAME
func adminIssueToken(args []string) error {
	fs := newFlagSet("admin issue-token")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "email of token owner")
	name := fs.String("name", "", "human-readable token label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" || *name == "" {
		return fmt.Errorf("issue-token: --config, --email, and --name are required")
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	userSvc := env.userService()
	u, err := userSvc.FindByEmail(env.ctx, *email)
	if err != nil {
		return err
	}
	// A token always belongs to an approved account: the operator who issues
	// one approves the account, before the token exists.
	if err := approveFor(env, userSvc, u, "issue-token"); err != nil {
		return fmt.Errorf("issue-token: approve %s: %w", u.Email, err)
	}

	tokSvc := env.tokenService()
	raw, row, err := tokSvc.Issue(env.ctx, u.ID, *name)
	if err != nil {
		return err
	}
	cliAudit(env, "issue-token", map[string]any{"target_user_id": u.ID, "target_email": u.Email, "token_id": row.ID, "name": row.Name})

	fmt.Fprintln(adminStderr, "WARNING: this token will NOT be shown again — store it securely now.")
	return writeJSON(map[string]any{
		"id":           row.ID,
		"user_id":      row.UserID,
		"name":         row.Name,
		"token":        raw,
		"token_prefix": row.TokenPrefix,
		"created_at":   tsOrEmpty(row.CreatedAt.Time, row.CreatedAt.Valid),
	})
}

// adminListTokens: tunneld admin list-tokens --config PATH --email EMAIL
//
// Lists the user's tokens that are not revoked (expired ones included), with
// the IDs revoke-token takes. The token itself is never shown.
func adminListTokens(args []string) error {
	fs := newFlagSet("admin list-tokens")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "email of the token owner")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" {
		return fmt.Errorf("list-tokens: --config and --email are required")
	}

	env, err := openAdmin(*cfgPath, false)
	if err != nil {
		return err
	}
	defer env.Close()

	u, err := env.userService().FindByEmail(env.ctx, *email)
	if err != nil {
		return err
	}
	list, err := env.tokenService().ListActiveByUser(env.ctx, u.ID)
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(list))
	for _, t := range list {
		out = append(out, map[string]any{
			"id":           t.ID,
			"user_id":      t.UserID,
			"name":         t.Name,
			"token_prefix": t.TokenPrefix,
			"created_at":   tsOrEmpty(t.CreatedAt.Time, t.CreatedAt.Valid),
			"last_used_at": tsOrEmpty(t.LastUsedAt.Time, t.LastUsedAt.Valid),
			"expires_at":   tsOrEmpty(t.ExpiresAt.Time, t.ExpiresAt.Valid),
		})
	}
	return writeJSON(out)
}

// adminRevokeToken: tunneld admin revoke-token --config PATH --id TOKEN_ID
func adminRevokeToken(args []string) error {
	fs := newFlagSet("admin revoke-token")
	cfgPath := fs.String("config", "", "path to YAML config")
	id := fs.Int64("id", 0, "token id to revoke (see list-tokens)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *id == 0 {
		return fmt.Errorf("revoke-token: --config and --id are required")
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	tokSvc := env.tokenService()
	tok, err := tokSvc.FindByID(env.ctx, *id)
	if err != nil {
		if errors.Is(err, tokens.ErrInvalidToken) {
			return fmt.Errorf("revoke-token: no token with id %d", *id)
		}
		return err
	}
	changed, err := tokSvc.RevokeAny(env.ctx, *id)
	if err != nil {
		return err
	}
	if changed {
		cliAudit(env, "revoke-token", map[string]any{"token_id": tok.ID, "target_user_id": tok.UserID, "name": tok.Name})
		fmt.Fprintln(adminStderr, openTunnelsNote(env.cfg, "token"))
	}
	return writeJSON(map[string]any{
		"id":              tok.ID,
		"user_id":         tok.UserID,
		"revoked":         true,
		"already_revoked": !changed,
	})
}

// reservationErrorText is the fixed text a reservation command shows for an
// error of the reservations service; no database text is shown.
func reservationErrorText(err error) string {
	switch {
	case errors.Is(err, reservations.ErrInvalidSubdomain):
		return "invalid subdomain: use 3 to 63 lower-case letters, digits and inner hyphens"
	case errors.Is(err, reservations.ErrSystemReserved):
		return "the subdomain is reserved for system use"
	case errors.Is(err, reservations.ErrAlreadyReserved):
		return "already reserved"
	case errors.Is(err, reservations.ErrInvalidPort):
		return "invalid port: use a number from 1 to 65535"
	default:
		return "the reservation could not be stored"
	}
}

// parsePortFlag parses a port as an operator types it: decimal digits only,
// 1 to 65535.
func parsePortFlag(s string) (int, error) {
	p, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || p == 0 {
		return 0, errors.New("invalid port: use a number from 1 to 65535")
	}
	return int(p), nil
}

// adminReserveSubdomain: tunneld admin reserve-subdomain --config PATH --email EMAIL --subdomain SD
//
// This is an operator's grant: the name is normalised and checked like
// every subdomain, and the per-user limit of self-service reservations does
// not apply.
func adminReserveSubdomain(args []string) error {
	fs := newFlagSet("admin reserve-subdomain")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "email of reservation owner")
	subdomain := fs.String("subdomain", "", "subdomain to reserve")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" || *subdomain == "" {
		return fmt.Errorf("reserve-subdomain: --config, --email, and --subdomain are required")
	}
	name, err := reservations.NormalizeSubdomain(*subdomain)
	if err != nil {
		return fmt.Errorf("reserve-subdomain: %s", reservationErrorText(err))
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	userSvc := env.userService()
	u, err := userSvc.FindByEmail(env.ctx, *email)
	if err != nil {
		return err
	}
	// A reservation is of use only to an approved account.
	if err := approveFor(env, userSvc, u, "reserve-subdomain"); err != nil {
		return fmt.Errorf("reserve-subdomain: approve %s: %w", u.Email, err)
	}
	if err := env.reservationService().GrantSubdomain(env.ctx, name, u.ID); err != nil {
		return fmt.Errorf("reserve-subdomain: %s", reservationErrorText(err))
	}
	cliAudit(env, "reserve-subdomain", map[string]any{"target_user_id": u.ID, "target_email": u.Email, "subdomain": name})
	fmt.Fprintf(adminStderr, grantTunnelNote+"\n", "subdomain")
	return writeJSON(map[string]any{
		"subdomain": name,
		"user_id":   u.ID,
		"email":     u.Email,
	})
}

// adminReleaseSubdomain: tunneld admin release-subdomain --config PATH --subdomain SD
//
// The name is looked up as written first, so that a name stored before
// names were checked can be released, then in its normal form.
func adminReleaseSubdomain(args []string) error {
	fs := newFlagSet("admin release-subdomain")
	cfgPath := fs.String("config", "", "path to YAML config")
	subdomain := fs.String("subdomain", "", "subdomain to release")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *subdomain == "" {
		return fmt.Errorf("release-subdomain: --config and --subdomain are required")
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	resSvc := env.reservationService()
	name := *subdomain
	owner, reserved, err := resSvc.Owner(env.ctx, name)
	if err == nil && !reserved {
		if normal, nerr := reservations.NormalizeSubdomain(name); nerr == nil && normal != name {
			name = normal
			owner, reserved, err = resSvc.Owner(env.ctx, name)
		}
	}
	if err != nil {
		return errors.New("release-subdomain: the reservation could not be read")
	}
	if !reserved {
		return writeJSON(map[string]any{
			"subdomain": *subdomain,
			"released":  false,
			"reason":    "not reserved",
		})
	}
	if err := resSvc.RevokeSubdomain(env.ctx, name); err != nil {
		return errors.New("release-subdomain: the reservation could not be removed")
	}
	cliAudit(env, "release-subdomain", map[string]any{"target_user_id": owner, "subdomain": name})
	return writeJSON(map[string]any{
		"subdomain": name,
		"user_id":   owner,
		"released":  true,
	})
}

// adminListReservations: tunneld admin list-reservations --config PATH [--email EMAIL]
func adminListReservations(args []string) error {
	fs := newFlagSet("admin list-reservations")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "optional: filter by owner email")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("list-reservations: --config is required")
	}

	env, err := openAdmin(*cfgPath, false)
	if err != nil {
		return err
	}
	defer env.Close()

	resSvc := env.reservationService()

	var rows []reservationRow
	if *email != "" {
		userSvc := env.userService()
		u, err := userSvc.FindByEmail(env.ctx, *email)
		if err != nil {
			return err
		}
		list, err := resSvc.ListByUser(env.ctx, u.ID)
		if err != nil {
			return err
		}
		for _, r := range list {
			rows = append(rows, reservationRow{
				Subdomain: r.Subdomain,
				UserID:    r.UserID,
				CreatedAt: tsOrEmpty(r.CreatedAt.Time, r.CreatedAt.Valid),
			})
		}
	} else {
		list, err := resSvc.ListAll(env.ctx)
		if err != nil {
			return err
		}
		for _, r := range list {
			rows = append(rows, reservationRow{
				Subdomain: r.Subdomain,
				UserID:    r.UserID,
				CreatedAt: tsOrEmpty(r.CreatedAt.Time, r.CreatedAt.Valid),
			})
		}
	}
	if rows == nil {
		rows = []reservationRow{}
	}
	return writeJSON(rows)
}

// adminGenCSRFKey: tunneld admin gen-csrf-key
//
// Prints a fresh base64-encoded 32-byte random key, suitable for pasting into
// auth.csrf_key in the YAML config. No config/DB access required.
func adminGenCSRFKey(args []string) error {
	fs := newFlagSet("admin gen-csrf-key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("rand: %w", err)
	}
	fmt.Fprintln(adminStdout, base64.StdEncoding.EncodeToString(buf))
	return nil
}

// adminSendTestEmail: tunneld admin send-test-email --config PATH --to EMAIL
//
// Dispatches a smoke-test message through the SMTP transport configured under
// mail.smtp.*. Useful for validating SMTP credentials before relying on them
// for signup / password-reset flows.
func adminSendTestEmail(args []string) error {
	fs := newFlagSet("admin send-test-email")
	cfgPath := fs.String("config", "", "path to YAML config")
	to := fs.String("to", "", "recipient email address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *to == "" {
		return fmt.Errorf("send-test-email: --config and --to are required")
	}

	cfg, err := loadAdminConfig(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Mail.SMTP.Host == "" {
		return errors.New("send-test-email: mail.smtp.host is not configured")
	}
	if cfg.Mail.From == "" {
		return errors.New("send-test-email: mail.from is not configured")
	}

	// The same transport as the server's, mail.smtp.allow_plaintext included.
	mailer := mail.NewSMTPMailer(smtpConfig(cfg))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := mailer.Send(ctx, mail.Message{
		To:       *to,
		Subject:  "tunneld test email",
		TextBody: "If you received this, your SMTP configuration works.\n\n— tunneld admin send-test-email\n",
	}); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return writeJSON(map[string]any{
		"to":   *to,
		"from": cfg.Mail.From,
		"sent": true,
	})
}

// adminPromoteUser: tunneld admin promote-user --config PATH --email EMAIL [--allow-unverified]
//
// An account whose email address is not verified is promoted only with
// --allow-unverified.
func adminPromoteUser(args []string) error {
	fs := newFlagSet("admin promote-user")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "user email")
	allowUnverified := fs.Bool("allow-unverified", false, "promote even though the email address is not verified")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" {
		return fmt.Errorf("promote-user: --config and --email are required")
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	userSvc := env.userService()
	u, err := userSvc.FindByEmail(env.ctx, *email)
	if err != nil {
		return err
	}
	verified := u.EmailVerifiedAt.Valid
	if !verified && !*allowUnverified {
		return fmt.Errorf("promote-user: the email address of %s is not verified; verify it first (mark-verified) or pass --allow-unverified", u.Email)
	}
	// An admin never waits for approval.
	if err := approveFor(env, userSvc, u, "promote-user"); err != nil {
		return fmt.Errorf("promote-user: approve %s: %w", u.Email, err)
	}
	if err := userSvc.Promote(env.ctx, u.ID); err != nil {
		return err
	}
	cliAudit(env, "promote-user", map[string]any{"target_user_id": u.ID, "target_email": u.Email, "email_verified": verified})
	return writeJSON(map[string]any{
		"id":       u.ID,
		"email":    u.Email,
		"is_admin": true,
	})
}

// adminDemoteUser: tunneld admin demote-user --config PATH --email EMAIL
func adminDemoteUser(args []string) error {
	fs := newFlagSet("admin demote-user")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "user email")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" {
		return fmt.Errorf("demote-user: --config and --email are required")
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	userSvc := env.userService()
	u, err := userSvc.FindByEmail(env.ctx, *email)
	if err != nil {
		return err
	}
	if err := userSvc.Demote(env.ctx, u.ID); err != nil {
		if errors.Is(err, users.ErrLastAdmin) {
			return fmt.Errorf("demote-user: %w — promote another user to admin first", err)
		}
		return err
	}
	cliAudit(env, "demote-user", map[string]any{"target_user_id": u.ID, "target_email": u.Email})
	return writeJSON(map[string]any{
		"id":       u.ID,
		"email":    u.Email,
		"is_admin": false,
	})
}

// adminCreateAdmin: tunneld admin create-admin --config PATH --email EMAIL --allow-unverified [--password-file PATH | --password-stdin]
//
// Creates a new user and immediately promotes them to admin in a single
// call. A new account has no verified email address, and promotion needs one
// unless the operator says otherwise, so --allow-unverified is required; it
// is checked before anything is read or created.
func adminCreateAdmin(args []string) error {
	fs := newFlagSet("admin create-admin")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "admin email")
	pwFile, pwStdin := addPasswordFlags(fs)
	allowUnverified := fs.Bool("allow-unverified", false, "promote although the new account's email address is not verified (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" {
		return fmt.Errorf("create-admin: --config and --email are required")
	}
	if !*allowUnverified {
		return errors.New("create-admin: a new account has no verified email address and promotion needs one; " +
			"pass --allow-unverified to create the admin anyway, or create the account with create-user, " +
			"verify the address and run promote-user")
	}

	pw, err := readNewPassword(*pwFile, *pwStdin)
	if err != nil {
		return err
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	userSvc := env.userService()
	u, err := userSvc.CreateWithAdminPassword(env.ctx, *email, pw)
	if err != nil {
		return err
	}
	// As in promote-user, the account is approved first: an admin never
	// waits for approval. promote-user repairs a failure of either step.
	err = approveFor(env, userSvc, u, "create-admin")
	if err == nil {
		err = userSvc.Promote(env.ctx, u.ID)
	}
	if err != nil {
		// The account exists now; the entry and the message say so.
		cliAudit(env, "create-admin", map[string]any{"target_user_id": u.ID, "target_email": u.Email,
			"email_verified": false, "promoted": false})
		return fmt.Errorf("create-admin: the account %s (id %d) was created but not promoted: %w; "+
			"run promote-user --allow-unverified for it", u.Email, u.ID, err)
	}
	cliAudit(env, "create-admin", map[string]any{"target_user_id": u.ID, "target_email": u.Email,
		"email_verified": false, "promoted": true})
	return writeJSON(map[string]any{
		"id":         u.ID,
		"email":      u.Email,
		"is_admin":   true,
		"created_at": tsOrEmpty(u.CreatedAt.Time, u.CreatedAt.Valid),
	})
}

// adminApproveUser: tunneld admin approve-user --config PATH --email EMAIL
//
// Approves an account that waits for approval (auth.signup approval or
// closed). When the config sets up mail (mail.smtp.host, and
// frontend.public_base_url for the link), the owner gets a mail that says
// so; a mail that cannot be sent is reported on stderr, the approval
// stands. An approved account is left as it is: no entry, no mail.
//
// It works in open mode too, so that accounts can be approved before the
// switch; there the approval changes nothing the owner would notice, and
// no mail is sent. A disabled account gets no mail either: it cannot log
// in.
func adminApproveUser(args []string) error {
	fs := newFlagSet("admin approve-user")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "user email")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" {
		return fmt.Errorf("approve-user: --config and --email are required")
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	userSvc := env.userService()
	u, err := userSvc.FindByEmail(env.ctx, *email)
	if err != nil {
		return err
	}
	wasPending := !users.IsApproved(u)
	if wasPending {
		if err := userSvc.Approve(env.ctx, u.ID); err != nil {
			return fmt.Errorf("approve-user: %w", err)
		}
		cliAudit(env, "approve-user", map[string]any{"target_user_id": u.ID, "target_email": u.Email})
		if approvalRequired(env.cfg) && !u.DisabledAt.Valid {
			mailApproved(env, u.Email)
		}
	}
	return writeJSON(map[string]any{
		"id":               u.ID,
		"email":            u.Email,
		"approved":         true,
		"already_approved": !wasPending,
	})
}

// mailApproved sends the owner of an account that was just approved the
// mail that says so, when the config sets up mail as the server needs it:
// mail.smtp.host for the transport, frontend.public_base_url for the login
// link. A failure is reported on stderr.
func mailApproved(env *adminEnv, to string) {
	cfg := env.cfg
	if cfg.Mail.SMTP.Host == "" || cfg.Frontend.PublicBaseURL == "" {
		return
	}
	text, html, err := mailtemplates.AccountApproved(cfg.Frontend.PublicBaseURL + "/login")
	if err == nil {
		err = adminMailer(cfg).Send(env.ctx, mail.Message{
			To:       to,
			Subject:  mailtemplates.AccountApprovedSubject,
			TextBody: text,
			HTMLBody: html,
		})
	}
	if err != nil {
		fmt.Fprintf(adminStderr, "warning: approve-user: the mail to the owner could not be sent: %v\n", err)
	}
}

// adminRejectUser: tunneld admin reject-user --config PATH --email EMAIL
//
// Rejects an account that waits for approval: it is deleted, with its
// sessions and everything else that belongs to it. Refused are approved
// accounts, admins, disabled accounts and accounts in use (an API token of
// any state or a reservation; openAdmin has approved those already), and
// every account while auth.signup is open in the config: then no account
// waits, the accounts simply have no approval.
func adminRejectUser(args []string) error {
	fs := newFlagSet("admin reject-user")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "user email")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" {
		return fmt.Errorf("reject-user: --config and --email are required")
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()
	if !approvalRequired(env.cfg) {
		return errors.New("reject-user: auth.signup is open in this config, so no account waits for approval; nothing was deleted")
	}

	userSvc := env.userService()
	u, err := userSvc.FindByEmail(env.ctx, *email)
	if err != nil {
		return err
	}
	if err := userSvc.DeletePending(env.ctx, u.ID); err != nil {
		if errors.Is(err, users.ErrNotPending) {
			return fmt.Errorf("reject-user: %s does not wait for approval (it is approved, an admin, disabled, or in use); "+
				"nothing was deleted", u.Email)
		}
		return err
	}
	cliAudit(env, "reject-user", map[string]any{"target_user_id": u.ID, "target_email": u.Email})
	return writeJSON(map[string]any{
		"id":      u.ID,
		"email":   u.Email,
		"deleted": true,
	})
}

// adminListPending: tunneld admin list-pending --config PATH
//
// Lists the accounts that wait for approval, oldest first: not approved, no
// admin, not disabled, not in use (users.Service.ListPending).
func adminListPending(args []string) error {
	fs := newFlagSet("admin list-pending")
	cfgPath := fs.String("config", "", "path to YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("list-pending: --config is required")
	}

	env, err := openAdmin(*cfgPath, false)
	if err != nil {
		return err
	}
	defer env.Close()

	rows, err := env.userService().ListPending(env.ctx)
	if err != nil {
		return err
	}
	if !approvalRequired(env.cfg) {
		fmt.Fprintln(adminStderr, "Note: auth.signup is open in this config, so these accounts can be used "+
			"although they have no approval; they would wait if approval were switched on.")
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{
			"id":             r.ID,
			"email":          r.Email,
			"email_verified": r.EmailVerifiedAt.Valid,
			"created_at":     tsOrEmpty(r.CreatedAt.Time, r.CreatedAt.Valid),
		})
	}
	return writeJSON(out)
}

type reservationRow struct {
	Subdomain string `json:"subdomain"`
	UserID    int64  `json:"user_id"`
	CreatedAt string `json:"created_at"`
}

type udpPortRow struct {
	Port      int32  `json:"port"`
	UserID    int64  `json:"user_id"`
	CreatedAt string `json:"created_at"`
}

// adminReserveUDPPort: tunneld admin reserve-udp-port --config PATH --email EMAIL --port PORT
//
// This is an operator's grant. The port must be a decimal number from 1 to
// 65535 and, when the config sets udp.port_range, lie inside it.
func adminReserveUDPPort(args []string) error {
	fs := newFlagSet("admin reserve-udp-port")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "email of reservation owner")
	portFlag := fs.String("port", "", "UDP port to reserve (1-65535, inside udp.port_range)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *email == "" || *portFlag == "" {
		return fmt.Errorf("reserve-udp-port: --config, --email, and --port are required")
	}
	port, err := parsePortFlag(*portFlag)
	if err != nil {
		return fmt.Errorf("reserve-udp-port: %w", err)
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	if rng := env.cfg.UDP.PortRange; (rng.Low != 0 || rng.High != 0) && (port < rng.Low || port > rng.High) {
		return fmt.Errorf("reserve-udp-port: port %d is outside the configured udp.port_range (%d to %d)", port, rng.Low, rng.High)
	}

	userSvc := env.userService()
	u, err := userSvc.FindByEmail(env.ctx, *email)
	if err != nil {
		return err
	}
	// A reservation is of use only to an approved account.
	if err := approveFor(env, userSvc, u, "reserve-udp-port"); err != nil {
		return fmt.Errorf("reserve-udp-port: approve %s: %w", u.Email, err)
	}
	if err := env.reservationService().GrantUDPPort(env.ctx, port, u.ID); err != nil {
		return fmt.Errorf("reserve-udp-port: %s", reservationErrorText(err))
	}
	cliAudit(env, "reserve-udp-port", map[string]any{"target_user_id": u.ID, "target_email": u.Email, "port": port})
	fmt.Fprintf(adminStderr, grantTunnelNote+"\n", "UDP port")
	return writeJSON(map[string]any{
		"port":    port,
		"user_id": u.ID,
		"email":   u.Email,
	})
}

// adminReleaseUDPPort: tunneld admin release-udp-port --config PATH --port PORT
func adminReleaseUDPPort(args []string) error {
	fs := newFlagSet("admin release-udp-port")
	cfgPath := fs.String("config", "", "path to YAML config")
	portFlag := fs.String("port", "", "UDP port to release (1-65535)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *portFlag == "" {
		return fmt.Errorf("release-udp-port: --config and --port are required")
	}
	port, err := parsePortFlag(*portFlag)
	if err != nil {
		return fmt.Errorf("release-udp-port: %w", err)
	}

	env, err := openAdmin(*cfgPath, true)
	if err != nil {
		return err
	}
	defer env.Close()

	resSvc := env.reservationService()
	owner, reserved, err := resSvc.OwnerUDPPort(env.ctx, port)
	if err != nil {
		return errors.New("release-udp-port: the reservation could not be read")
	}
	if !reserved {
		return writeJSON(map[string]any{
			"port":     port,
			"released": false,
			"reason":   "not reserved",
		})
	}
	if err := resSvc.RevokeUDPPort(env.ctx, port); err != nil {
		return errors.New("release-udp-port: the reservation could not be removed")
	}
	cliAudit(env, "release-udp-port", map[string]any{"target_user_id": owner, "port": port})
	return writeJSON(map[string]any{
		"port":     port,
		"user_id":  owner,
		"released": true,
	})
}

// adminListUDPPorts: tunneld admin list-udp-ports --config PATH [--email EMAIL]
func adminListUDPPorts(args []string) error {
	fs := newFlagSet("admin list-udp-ports")
	cfgPath := fs.String("config", "", "path to YAML config")
	email := fs.String("email", "", "optional: filter by owner email")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("list-udp-ports: --config is required")
	}

	env, err := openAdmin(*cfgPath, false)
	if err != nil {
		return err
	}
	defer env.Close()

	resSvc := env.reservationService()

	var rows []udpPortRow
	if *email != "" {
		userSvc := env.userService()
		u, err := userSvc.FindByEmail(env.ctx, *email)
		if err != nil {
			return err
		}
		list, err := resSvc.ListUDPPortsByUser(env.ctx, u.ID)
		if err != nil {
			return err
		}
		for _, r := range list {
			rows = append(rows, udpPortRow{
				Port:      r.Port,
				UserID:    r.UserID,
				CreatedAt: tsOrEmpty(r.CreatedAt.Time, r.CreatedAt.Valid),
			})
		}
	} else {
		// One query for every reservation, however many accounts there are.
		list, err := resSvc.ListAllUDPPorts(env.ctx)
		if err != nil {
			return err
		}
		for _, r := range list {
			rows = append(rows, udpPortRow{
				Port:      r.Port,
				UserID:    r.UserID,
				CreatedAt: tsOrEmpty(r.CreatedAt.Time, r.CreatedAt.Valid),
			})
		}
		// The order the command has always printed: by owner, then port (the
		// query returns them by port).
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].UserID < rows[j].UserID })
	}
	if rows == nil {
		rows = []udpPortRow{}
	}
	return writeJSON(rows)
}
