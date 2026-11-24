package frontend

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/csrf"

	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	mailtemplates "github.com/Bazinga0o0/tunnel/internal/server/mail/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/passwordreset"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func forgotPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderPage(w, templates.ForgotPage(templates.ForgotData{
			CSRFToken: csrf.Token(r),
			CSPNonce:  CSPNonceFromContext(r.Context()),
		}))
	}
}

// forgotSubmit issues a password-reset link and mails it. The answer is the
// same page whether or not an account exists.
//
// Requests are limited per client (Options.ResetRequestsPerIP) and per
// typed address (ResetRequestsPerAccount); over a limit the answer is 429
// with the same generic page and nothing is issued or sent. The address
// limit counts addresses without an account too, so it reveals nothing.
// Only these two limits, keyed on what the client controls, answer 429.
//
// The mail goes to the address the service returns for the account,
// never to the spelling that was typed, and it is sent in the background:
// the response never waits for SMTP.
func forgotSubmit(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		email := strings.TrimSpace(r.PostFormValue("email"))
		render := func(status int) {
			renderPageStatus(w, status, templates.ForgotPage(templates.ForgotData{
				CSRFToken:   csrf.Token(r),
				CSPNonce:    CSPNonceFromContext(r.Context()),
				GenericSent: true,
			}))
		}

		lim := opts.limiters
		if _, retry, ok := lim.resetIP.take(sourceKey(clientIP(r))); !ok {
			setRetryAfter(w, retry)
			render(http.StatusTooManyRequests)
			return
		}
		// The typed-address limit applies to whatever was typed.
		if _, retry, ok := lim.resetAccount.take(opts.keyOf(email)); !ok {
			setRetryAfter(w, retry)
			render(http.StatusTooManyRequests)
			return
		}

		// An address that fails validation gets the generic answer and
		// nothing else: no lookup, no token, no mail.
		validEmail := users.ValidateEmail(email) == nil
		if opts.PasswordReset != nil && opts.Mailer != nil && opts.PublicBaseURL != "" && validEmail {
			issueReset(r, opts, email)
		}
		render(http.StatusOK)
	}
}

// issueReset issues a reset link for the account of email, if there is one
// within its budget, and queues the mail. Every path asks for one audit row
// (auditOutsider), so that every path does a database write; once the
// minute's budget of rows of requests without a login is spent
// (Options.UnauthenticatedAuditRowsPerMinute), the row is counted in that
// minute's summary instead, on every path alike, so whether it is written
// says nothing about the address.
//
// The address stored for the account has a budget of its own
// (Options.ResetRequestsPerAccount, kept in a separate limiter), which also
// covers spellings that differ but match the same account. It is checked
// before a token is issued and silently: over it there is no token and no
// mail, and the client gets the usual page. A visible 429 here would come
// only for an existing account.
func issueReset(r *http.Request, opts Options, email string) {
	const action = "auth.password.reset.request"
	u, err := opts.Users.FindByEmail(r.Context(), email)
	switch {
	case errors.Is(err, users.ErrNotFound):
		// No account: nothing to issue.
	case err != nil:
		log.Printf("frontend: forgot password: look up account: %v", err)
	default:
		key := opts.keyOf(u.Email)
		stamp, _, ok := opts.limiters.resetStored.take(key)
		if !ok {
			// The account is over its budget: no token, no mail.
			break
		}
		raw, userID, stored, err := opts.PasswordReset.IssueWithAddress(r.Context(), email)
		if err == nil && raw != "" {
			// Nobody is logged in; the account is the target.
			opts.auditOutsider(r, action, map[string]any{"target_user_id": userID})
			sendResetMail(opts, raw, stored)
			return
		}
		if err != nil {
			log.Printf("frontend: forgot password: issue reset: %v", err)
		}
		// Nothing was issued (an error, or a disabled account, which gets
		// nothing like an unknown address): the budget counts issued links,
		// so the slot goes back.
		opts.limiters.resetStored.giveBack(key, stamp)
	}
	// The row is written without user and address.
	opts.auditOutsider(r, action, nil)
}

// sendResetMail queues the mail with the reset link to the stored address
// to. It goes out in the background (mailQueue); the client sees the
// generic page either way.
func sendResetMail(opts Options, raw, to string) {
	link := opts.PublicBaseURL + "/reset?token=" + url.QueryEscape(raw)
	text, html, err := mailtemplates.PasswordReset(link)
	if err != nil {
		log.Printf("frontend: forgot password: render reset email: %v", err)
		return
	}
	opts.mails.send(mail.Message{
		To:       to,
		Subject:  "Reset your password",
		TextBody: text,
		HTMLBody: html,
	})
}

func resetPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		// Don't validate the token here — just render the form. Invalid
		// tokens are caught on POST. Empty token → still render; the form
		// won't submit anything useful. The page carries the token: keep it
		// out of caches.
		w.Header().Set("Cache-Control", "no-store")
		renderPage(w, templates.ResetPage(templates.ResetData{
			Token:     token,
			CSRFToken: csrf.Token(r),
			CSPNonce:  CSPNonceFromContext(r.Context()),
		}))
	}
}

// resetSubmit sets a new password with a reset link. The service applies
// the password rules and uses the link up in one transaction. The request
// takes one of the client's slots for hash work first (Options.HashPerIP);
// without a free one it is answered 429 at once. That bounds how many
// requests with one valid link a client can have hashing at the same time.
func resetSubmit(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		token := r.PostFormValue("token")
		newPW := r.PostFormValue("new")
		confirm := r.PostFormValue("confirm")

		renderErr := func(msg string, status int) {
			w.Header().Set("Cache-Control", "no-store")
			renderPageStatus(w, status, templates.ResetPage(templates.ResetData{
				Token:     token,
				CSRFToken: csrf.Token(r),
				CSPNonce:  CSPNonceFromContext(r.Context()),
				ErrMsg:    msg,
			}))
		}

		if newPW != confirm {
			renderErr("new password and confirmation do not match", http.StatusBadRequest)
			return
		}
		if opts.PasswordReset == nil {
			renderErr("password reset is not configured", http.StatusInternalServerError)
			return
		}
		// The rules are checked before a hash slot is taken, so that a
		// password the service refuses anyway gets its field error.
		if err := opts.Users.ValidatePassword(newPW); err != nil {
			renderErr("new "+err.Error(), http.StatusBadRequest)
			return
		}
		release, ok := opts.takeHashSlot(w, r)
		if !ok {
			renderErr(msgHashBusy, http.StatusTooManyRequests)
			return
		}
		defer release()

		userID, err := opts.PasswordReset.Consume(r.Context(), token, newPW)
		if err != nil {
			switch {
			case errors.Is(err, passwordreset.ErrInvalidReset):
				renderErr("this reset link is invalid or has expired", http.StatusBadRequest)
			case errors.Is(err, users.ErrPasswordTooShort), errors.Is(err, users.ErrPasswordTooLong):
				renderErr("new "+err.Error(), http.StatusBadRequest)
			default:
				status, msg := serviceFailure(w, "reset password", err)
				renderErr(msg, status)
			}
			return
		}
		// The holder of the link acts for the account it belongs to.
		opts.audit(r, &userID, "auth.password.reset.complete", nil)

		// Clear any existing session cookie and redirect to login.
		clearSessionCookie(w, opts.CSRFSecure)
		http.Redirect(w, r, "/login?reset=1", http.StatusSeeOther)
	}
}
