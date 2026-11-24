package frontend

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/gorilla/csrf"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	mailtemplates "github.com/Bazinga0o0/tunnel/internal/server/mail/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

const sessionTTL = 30 * 24 * time.Hour

// Texts of the login and sign-up pages.
const (
	msgLoginRequired  = "email and password required"
	msgBadCredentials = "invalid email or password"
	msgTooManyLogins  = "Too many failed login attempts. Please try again later."
	// msgTooManyLoginsAccount answers Options.LoginsPerAccount. That limit
	// counts successful logins only, so only an address with an account can
	// reach it; below it, it answers nothing that tells an account from a
	// missing address.
	msgTooManyLoginsAccount = "Too many logins for this email address. Please try again later."
	msgTooManySignups       = "Too many sign-up attempts from your network. Please try again later."
	msgInvalidEmail         = "Enter a valid email address, for example name@example.com."
)

func loginPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderPage(w, templates.LoginPage(templates.LoginData{
			CSRFToken:       csrf.Token(r),
			CSPNonce:        CSPNonceFromContext(r.Context()),
			ResetSucceeded:  r.URL.Query().Get("reset") == "1",
			PasswordChanged: r.URL.Query().Get("changed") == "1",
			SignupDone:      r.URL.Query().Get("signup") == "1",
			SignupOpen:      opts.signupOpen(),
		}))
	}
}

// loginSubmit checks email and password with users.Authenticate, which
// takes the same time for an unknown address as for a known one.
//
// The request first takes one of the client's slots for hash work
// (Options.HashPerIP); without a free one it is answered 429 at once.
//
// Failed logins are limited per client and per typed address
// (Options.LoginFailuresPerIP, LoginFailuresPerAccount). The attempt is
// counted before the password is checked, so that parallel attempts cannot
// pass the limit together; an attempt that succeeds, or that the server
// could not decide (no free hash slot, database error), is given back. Over
// a limit the answer is 429 and no password is checked.
//
// Successful logins of an address count against Options.LoginsPerAccount;
// wrong passwords, unknown addresses and logins the server could not decide
// do not. When the address has reached that limit, a login is answered 429
// too, before any hash. That check counts nothing, so attempts in flight
// hold no place in the count. A login is recorded right after its password
// matched and before its session is created: of logins that hashed at the
// same time only as many as the limit has room for get a session, the
// others get the same 429. A login whose session cannot be stored is given
// back.
func loginSubmit(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		email := strings.TrimSpace(r.PostFormValue("email"))
		password := r.PostFormValue("password")
		render := func(status int, msg string) {
			renderPageStatus(w, status, templates.LoginPage(templates.LoginData{
				ErrMsg:     msg,
				CSRFToken:  csrf.Token(r),
				CSPNonce:   CSPNonceFromContext(r.Context()),
				SignupOpen: opts.signupOpen(),
			}))
		}
		if email == "" || password == "" {
			render(http.StatusBadRequest, msgLoginRequired)
			return
		}
		release, ok := opts.takeHashSlot(w, r)
		if !ok {
			render(http.StatusTooManyRequests, msgHashBusy)
			return
		}
		defer release()

		lim := opts.limiters
		ipKey := sourceKey(clientIP(r))
		ipStamp, retry, ok := lim.loginIP.take(ipKey)
		if !ok {
			setRetryAfter(w, retry)
			render(http.StatusTooManyRequests, msgTooManyLogins)
			return
		}
		// Every typed address gets an account key, valid or not: an account
		// created before addresses were validated can have a stored address
		// that fails today's check. A full table never refuses: it makes
		// room by failures (rateLimiter, evictingByFailures), so junk keys
		// lock nobody out. The place taken here is pending: only confirm
		// below (a wrong password) makes it a failure that changes the
		// table; every other outcome gives it back without a trace. Pushing
		// out e failures of one account costs at least
		// e·(rate_limit_max_keys-1) counted failed logins of other keys.
		acctKey := opts.keyOf(email)
		acctStamp, retry, ok := lim.loginAccount.take(acctKey)
		if !ok {
			lim.loginIP.giveBack(ipKey, ipStamp)
			setRetryAfter(w, retry)
			render(http.StatusTooManyRequests, msgTooManyLogins)
			return
		}
		giveBack := func() {
			lim.loginIP.giveBack(ipKey, ipStamp)
			lim.loginAccount.giveBack(acctKey, acctStamp)
		}
		// Successful logins of the address are limited too. This only
		// looks: the login is counted once its password has matched, so
		// that wrong passwords, also those still in their hash, hold no
		// place.
		if retry, ok := lim.logins.check(acctKey); !ok {
			giveBack()
			setRetryAfter(w, retry)
			render(http.StatusTooManyRequests, msgTooManyLoginsAccount)
			return
		}

		u, err := opts.Users.Authenticate(r.Context(), email, password)
		if err != nil {
			// A disabled account gets the same answer as a wrong password:
			// the difference must not tell anybody that the account exists.
			if errors.Is(err, users.ErrInvalidCredentials) || errors.Is(err, users.ErrAccountDisabled) {
				reason := "invalid_credentials"
				if errors.Is(err, users.ErrAccountDisabled) {
					reason = "account_disabled"
				}
				// The failure is final: only now does it count in the
				// failure table's order and credit (confirm).
				lim.loginAccount.confirm(acctKey, acctStamp)
				opts.auditOutsider(r, "auth.login.failure", map[string]any{"reason": reason})
				render(http.StatusUnauthorized, msgBadCredentials)
				return
			}
			giveBack()
			status, msg := serviceFailure(w, "login", err)
			render(status, msg)
			return
		}
		giveBack()

		// The password matched: record the login before its session exists.
		// Logins that hashed at the same time have all passed the check
		// above; only as many as the limit has room for get a session.
		loginStamp, retry, ok := lim.logins.take(acctKey)
		if !ok {
			setRetryAfter(w, retry)
			render(http.StatusTooManyRequests, msgTooManyLoginsAccount)
			return
		}
		if err := startSession(w, r, opts, u.ID); err != nil {
			lim.logins.giveBack(acctKey, loginStamp)
			status, msg := serviceFailure(w, "login: create session", err)
			render(status, msg)
			return
		}
		opts.audit(r, &u.ID, "auth.login.success", nil)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

// signupOpen reports whether people can sign up themselves: in every mode
// but "closed", where only an admin creates accounts.
func (o Options) signupOpen() bool {
	return o.SignupMode != "closed"
}

// signupClosed answers a sign-up request while sign-up is closed: 404 with
// a short page that says so.
func signupClosed(w http.ResponseWriter, r *http.Request) {
	renderPageStatus(w, http.StatusNotFound, templates.SignupClosedPage(CSPNonceFromContext(r.Context())))
}

// honeypotField is the name of the sign-up form's field that people do not
// see (SignupPage). A request that fills it comes from a bot.
const honeypotField = templates.HoneypotField

func signupPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !opts.signupOpen() {
			signupClosed(w, r)
			return
		}
		renderPage(w, templates.SignupPage(templates.SignupData{
			CSRFToken: csrf.Token(r),
			CSPNonce:  CSPNonceFromContext(r.Context()),
		}))
	}
}

// signupSubmit creates an account. Its answer is the same whether or not
// the address already has an account: a redirect to the login page, no
// session. For a new account the owner gets the verification mail; for an
// existing one the owner gets a mail saying that somebody tried to sign up
// with the address, and the handler spends the time of the password hash a
// new account costs, so that the answer takes as long.
//
// While sign-up is closed (Options.SignupMode "closed") every request gets
// 404. A request that fills the honeypot field (honeypotField) gets the
// answer of a sign-up, and nothing else happens: no account, no mail, no
// hash work, nothing counted against the limits; only an audit row.
//
// Address and password are checked first (field errors, 400); only an
// attempt that passes takes one of the client's slots for hash work
// (Options.HashPerIP, 429 at once without one) and counts against
// Options.SignupsPerIP, checked before the password is hashed.
func signupSubmit(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !opts.signupOpen() {
			signupClosed(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.PostFormValue(honeypotField) != "" {
			opts.auditOutsider(r, "auth.signup.honeypot", nil)
			http.Redirect(w, r, "/login?signup=1", http.StatusSeeOther)
			return
		}
		email := strings.TrimSpace(r.PostFormValue("email"))
		password := r.PostFormValue("password")
		render := func(status int, data templates.SignupData) {
			data.Email = email
			data.CSRFToken = csrf.Token(r)
			data.CSPNonce = CSPNonceFromContext(r.Context())
			renderPageStatus(w, status, templates.SignupPage(data))
		}
		if users.ValidateEmail(email) != nil {
			render(http.StatusBadRequest, templates.SignupData{EmailErr: msgInvalidEmail})
			return
		}
		if err := opts.Users.ValidatePassword(password); err != nil {
			render(http.StatusBadRequest, templates.SignupData{PasswordErr: err.Error()})
			return
		}
		release, ok := opts.takeHashSlot(w, r)
		if !ok {
			render(http.StatusTooManyRequests, templates.SignupData{ErrMsg: msgHashBusy})
			return
		}
		defer release()

		ipKey := sourceKey(clientIP(r))
		stamp, retry, ok := opts.limiters.signupIP.take(ipKey)
		if !ok {
			setRetryAfter(w, retry)
			render(http.StatusTooManyRequests, templates.SignupData{ErrMsg: msgTooManySignups})
			return
		}
		fail := func(op string, err error) {
			opts.limiters.signupIP.giveBack(ipKey, stamp)
			status, msg := serviceFailure(w, op, err)
			render(status, templates.SignupData{ErrMsg: msg})
		}

		u, err := opts.Users.Create(r.Context(), email, password)
		switch {
		case err == nil:
			opts.audit(r, &u.ID, "auth.signup", nil)
			if signupMailEnabled(opts) {
				sendVerificationMail(r, opts, "signup", u.ID, u.Email)
			}
		case errors.Is(err, users.ErrEmailTaken):
			dummyVerify := auth.DummyVerify
			if opts.dummyVerify != nil {
				dummyVerify = opts.dummyVerify
			}
			if derr := dummyVerify(r.Context(), password); derr != nil {
				fail("signup", derr)
				return
			}
			if signupMailEnabled(opts) {
				sendSignupAttemptNotice(r, opts, email)
			}
		case errors.Is(err, users.ErrInvalidEmail):
			render(http.StatusBadRequest, templates.SignupData{EmailErr: msgInvalidEmail})
			return
		case errors.Is(err, users.ErrPasswordTooShort), errors.Is(err, users.ErrPasswordTooLong):
			render(http.StatusBadRequest, templates.SignupData{PasswordErr: err.Error()})
			return
		default:
			fail("signup", err)
			return
		}
		http.Redirect(w, r, "/login?signup=1", http.StatusSeeOther)
	}
}

// signupMailEnabled reports whether sign-up sends mail. Both mails of a
// sign-up, the verification and the notice for a taken address, depend on
// the same settings, so that the two cases cannot be told apart by whether
// a mail goes out.
func signupMailEnabled(opts Options) bool {
	return opts.Verifications != nil && opts.Mailer != nil && opts.PublicBaseURL != ""
}

// sendVerificationMail issues a verification link for userID and queues a
// mail with it to the address to. Failures are logged and never fail the
// request: the account exists and the user can ask for another mail. The
// mail itself goes out in the background (mailQueue).
func sendVerificationMail(r *http.Request, opts Options, op string, userID int64, to string) {
	raw, err := opts.Verifications.Issue(r.Context(), userID)
	if err != nil {
		log.Printf("frontend: %s: issue verification for user %d: %v", op, userID, err)
		return
	}
	link := opts.PublicBaseURL + "/verify?token=" + url.QueryEscape(raw)
	text, html, err := mailtemplates.VerifyEmail(link)
	if err != nil {
		log.Printf("frontend: %s: render verification email: %v", op, err)
		return
	}
	opts.mails.send(mail.Message{
		To:       to,
		Subject:  "Verify your email",
		TextBody: text,
		HTMLBody: html,
	})
}

// sendSignupAttemptNotice tells the owner of the account with the address
// email that somebody tried to sign up with it. The mail goes to the
// address stored for the account, never to the spelling that was typed. It
// carries no token.
func sendSignupAttemptNotice(r *http.Request, opts Options, email string) {
	u, err := opts.Users.FindByEmail(r.Context(), email)
	if err != nil {
		log.Printf("frontend: signup: look up existing account: %v", err)
		return
	}
	text := "Someone tried to create a tunnel account with this email address (" + u.Email + "). " +
		"An account with this address already exists, so nothing was changed.\n\n" +
		"If it was you, log in at " + opts.PublicBaseURL + "/login.\n" +
		"If you forgot your password, you can reset it at " + opts.PublicBaseURL + "/forgot-password.\n\n" +
		"If it was not you, you can ignore this message.\n"
	opts.mails.send(mail.Message{
		To:       u.Email,
		Subject:  "Sign-up attempt with your email address",
		TextBody: text,
	})
}

func logoutSubmit(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if raw, ok := readSessionCookie(r, opts.CSRFSecure); ok {
			row, err := opts.Sessions.Lookup(r.Context(), raw)
			switch {
			case err == nil:
				if err := opts.Sessions.Delete(r.Context(), row.ID); err != nil {
					log.Printf("frontend: logout: delete session: %v", err)
				} else {
					opts.audit(r, &row.UserID, "auth.logout", nil)
				}
			case !errors.Is(err, sessions.ErrInvalidSession):
				// The cookie is cleared below all the same; the session row,
				// if there is one, stays until it expires. Any cookie value
				// gets here, so the line goes through the limited log.
				opts.lookupLog.printf(err, "frontend: logout: look up session: %v", err)
			}
		}
		clearSessionCookie(w, opts.CSRFSecure)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// startSession creates a session for userID and sets its cookie. The
// session records the client's address from the connection.
func startSession(w http.ResponseWriter, r *http.Request, opts Options, userID int64) error {
	raw, row, err := opts.Sessions.Create(r.Context(), userID, r.UserAgent(), clientIP(r), sessionTTL)
	if err != nil {
		return err
	}
	setSessionCookie(w, raw, row.ExpiresAt.Time, opts.CSRFSecure)
	return nil
}

func renderPage(w http.ResponseWriter, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = c.Render(context.TODO(), w)
}

// renderPageStatus is renderPage with a status code. The headers are set
// before the status is written.
func renderPageStatus(w http.ResponseWriter, status int, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = c.Render(context.TODO(), w)
}
