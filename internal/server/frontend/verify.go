package frontend

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/csrf"

	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	mailtemplates "github.com/Bazinga0o0/tunnel/internal/server/mail/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
	"github.com/Bazinga0o0/tunnel/internal/server/verifications"
)

// Texts of the verification pages.
const (
	msgVerifyMissing = "missing token"
	msgVerifyInvalid = "this link is invalid or has expired"
)

// verifyPage is what the link in the verification mail opens. It looks the
// token up without using it and shows a page with a button that submits it
// (POST /verify). Mail scanners and link previews fetch links with GET; they
// must not verify an address on somebody's behalf.
//
// Intentionally placed OUTSIDE the authenticated route group — users will
// often click the email link in a different browser than the one they used
// to sign up, so we don't want to bounce them through /login first.
func verifyPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The page carries the token: keep it out of caches.
		w.Header().Set("Cache-Control", "no-store")
		render := func(status int, data templates.VerifyData) {
			data.CSRFToken = csrf.Token(r)
			data.CSPNonce = CSPNonceFromContext(r.Context())
			renderPageStatus(w, status, templates.VerifyPage(data))
		}
		raw := r.URL.Query().Get("token")
		if opts.Verifications == nil || raw == "" {
			render(http.StatusOK, templates.VerifyData{ErrMsg: msgVerifyMissing})
			return
		}
		if _, err := opts.Verifications.Lookup(r.Context(), raw); err != nil {
			if errors.Is(err, verifications.ErrInvalidVerification) {
				render(http.StatusOK, templates.VerifyData{ErrMsg: msgVerifyInvalid})
				return
			}
			status, msg := serviceFailure(w, "verify: look up token", err)
			render(status, templates.VerifyData{ErrMsg: msg})
			return
		}
		render(http.StatusOK, templates.VerifyData{Token: raw})
	}
}

// verifySubmit uses the verification token from the confirmation page and
// redirects to the dashboard. In approval mode an account that waits for
// approval after the verification makes the admins get a mail
// (notifyAdminsOfPending); the dashboard shows the owner that it waits.
func verifySubmit(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		render := func(status int, msg string) {
			renderPageStatus(w, status, templates.VerifyPage(templates.VerifyData{
				ErrMsg:   msg,
				CSPNonce: CSPNonceFromContext(r.Context()),
			}))
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		raw := r.PostFormValue("token")
		if opts.Verifications == nil || raw == "" {
			render(http.StatusBadRequest, msgVerifyMissing)
			return
		}
		userID, err := opts.Verifications.Consume(r.Context(), raw)
		if err != nil {
			if errors.Is(err, verifications.ErrInvalidVerification) {
				render(http.StatusBadRequest, msgVerifyInvalid)
				return
			}
			status, msg := serviceFailure(w, "verify: consume token", err)
			render(status, msg)
			return
		}
		// The holder of the token acts for the account it belongs to.
		opts.audit(r, &userID, "auth.email.verify", nil)
		if opts.SignupMode == "approval" && signupMailEnabled(opts) {
			notifyAdminsOfPending(r, opts, userID)
		}
		http.Redirect(w, r, "/dashboard?verified=1", http.StatusSeeOther)
	}
}

// notifyAdminsOfPending queues a mail to every admin that is not disabled
// when the account userID waits for approval: not approved, no admin, not
// disabled (the accounts of the admin page /admin/approvals). The caller
// checks that the mode is "approval" and that mail is set up. Failures are
// logged and never fail the request: the address is verified, and the
// account shows up on the admin page all the same.
func notifyAdminsOfPending(r *http.Request, opts Options, userID int64) {
	u, err := opts.Users.FindByID(r.Context(), userID)
	if err != nil {
		log.Printf("frontend: verify: look up user %d for the approval mail: %v", userID, err)
		return
	}
	if users.IsApproved(u) || u.IsAdmin || u.DisabledAt.Valid {
		return
	}
	admins, err := opts.Users.AdminEmails(r.Context())
	if err != nil {
		log.Printf("frontend: verify: list admins for the approval mail: %v", err)
		return
	}
	text, html, err := mailtemplates.ApprovalNeeded(u.Email, opts.PublicBaseURL+"/admin/approvals")
	if err != nil {
		log.Printf("frontend: verify: render approval mail: %v", err)
		return
	}
	for _, to := range admins {
		opts.mails.send(mail.Message{
			To:       to,
			Subject:  "Account waits for approval",
			TextBody: text,
			HTMLBody: html,
		})
	}
}

// verifyResendHandler re-issues a verification link for the currently-signed-in
// user. Rate-limited to 1 request per minute per user (in-memory, resets on
// restart). No-ops silently if the user is already verified.
func verifyResendHandler(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := userIDFromContext(r.Context())
		if userID == 0 {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if _, _, ok := opts.limiters.resend.take(strconv.FormatInt(userID, 10)); !ok {
			http.Redirect(w, r, "/dashboard?resend=throttled", http.StatusSeeOther)
			return
		}
		if opts.Verifications == nil || opts.Mailer == nil || opts.PublicBaseURL == "" {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		u, err := opts.Users.FindByID(r.Context(), userID)
		if err != nil {
			serverError(w, "resend verification: look up user", err)
			return
		}
		if u.EmailVerifiedAt.Valid {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		sendVerificationMail(r, opts, "resend", userID, u.Email)
		http.Redirect(w, r, "/dashboard?resend=ok", http.StatusSeeOther)
	}
}
