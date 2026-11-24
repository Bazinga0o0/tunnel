package frontend

import (
	"errors"
	"log"
	"net/http"

	"github.com/gorilla/csrf"

	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func settingsPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := userIDFromContext(r.Context())
		u, err := opts.Users.FindByID(r.Context(), userID)
		if err != nil {
			serverError(w, "settings: look up user", err)
			return
		}
		renderPage(w, templates.SettingsPage(templates.SettingsData{
			Email:     string(u.Email),
			Changed:   r.URL.Query().Get("changed") == "1",
			CSRFToken: csrf.Token(r),
			CSPNonce:  CSPNonceFromContext(r.Context()),
		}))
	}
}

// renderSettingsError answers with the settings page of the user with the
// address email, showing msg, and status.
func renderSettingsError(w http.ResponseWriter, r *http.Request, email, msg string, status int) {
	renderPageStatus(w, status, templates.SettingsPage(templates.SettingsData{
		Email:     email,
		ErrMsg:    msg,
		CSRFToken: csrf.Token(r),
		CSPNonce:  CSPNonceFromContext(r.Context()),
	}))
}

// refuseOnSettingsPage answers a password change over
// Options.UserActionsPerHour the way the settings page reports its other
// errors: the page with msgTooManyUserActions (and 429).
func refuseOnSettingsPage(opts Options) userActionRefusal {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := opts.Users.FindByID(r.Context(), userIDFromContext(r.Context()))
		if err != nil {
			serverError(w, "change password: look up user", err)
			return
		}
		renderSettingsError(w, r, string(u.Email), msgTooManyUserActions, http.StatusTooManyRequests)
	}
}

// settingsChangePassword changes the password of the signed-in user after
// checking the current one (checkCurrentPassword: the check counts against
// the login limits). Every request counts against the user's budget of
// Options.UserActionsPerHour (limitUserActions, in front of the handler).
// Before the check the request takes one of the client's slots for hash
// work (Options.HashPerIP; 429 at once without a free one).
// The service applies the password rules (at least 8 characters, counted as
// characters, not bytes) and, in the transaction that stores the password,
// deletes every session of the user, the one the change came from included:
// a copy of the browser's cookie stops working. The browser then gets a new
// session, as at login. When that session cannot be stored, the password is
// changed and the account has no session left: the answer clears the cookie
// and sends the browser to the login page.
func settingsChangePassword(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := userIDFromContext(r.Context())
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		current := r.PostFormValue("current")
		newPW := r.PostFormValue("new")
		confirm := r.PostFormValue("confirm")

		u, err := opts.Users.FindByID(r.Context(), userID)
		if err != nil {
			serverError(w, "change password: look up user", err)
			return
		}

		renderErr := func(msg string, status int) {
			renderSettingsError(w, r, string(u.Email), msg, status)
		}
		failed := func(op string, err error) {
			status, msg := serviceFailure(w, op, err)
			renderErr(msg, status)
		}

		if newPW != confirm {
			renderErr("new password and confirmation do not match", http.StatusBadRequest)
			return
		}
		if err := opts.Users.ValidatePassword(newPW); err != nil {
			renderErr("new "+err.Error(), http.StatusBadRequest)
			return
		}
		// One slot of the client's hash work covers both hashes of the
		// request: the check of the current password and the new hash.
		release, ok := opts.takeHashSlot(w, r)
		if !ok {
			renderErr(msgHashBusy, http.StatusTooManyRequests)
			return
		}
		defer release()

		// The check of the current password counts against the login limits
		// (per account, keyed on the stored address, and per client), as a
		// login does: over a limit the answer is the login's 429.
		verdict, retry, err := opts.checkCurrentPassword(r, userID, u.Email, current)
		switch verdict {
		case passwordLimited:
			setRetryAfter(w, retry)
			renderErr(msgTooManyLogins, http.StatusTooManyRequests)
			return
		case passwordUndecided:
			failed("change password: verify current password", err)
			return
		case passwordWrong:
			renderErr("current password is incorrect", http.StatusUnauthorized)
			return
		}

		// The new password and the end of every session of the account are
		// one transaction: on an error neither has happened, and the browser
		// keeps its session.
		err = opts.Users.ChangePassword(r.Context(), userID, newPW)
		if err != nil {
			if errors.Is(err, users.ErrPasswordTooShort) || errors.Is(err, users.ErrPasswordTooLong) {
				renderErr("new "+err.Error(), http.StatusBadRequest)
				return
			}
			failed("change password: update", err)
			return
		}
		opts.audit(r, &userID, "auth.password.change", nil)

		// The session the request came from is gone; the browser gets a new
		// one. Without it there is no way back to the old one: log out.
		if err := startSession(w, r, opts, userID); err != nil {
			log.Printf("frontend: change password: create session for user %d: %v", userID, err)
			clearSessionCookie(w, opts.CSRFSecure)
			http.Redirect(w, r, "/login?changed=1", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/settings?changed=1", http.StatusSeeOther)
	}
}
