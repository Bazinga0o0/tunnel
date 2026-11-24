package frontend

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// Messages the user detail page shows when an action is refused. None of
// them carries internal error text. msgTooManyReentries answers a refusal
// by the per-account and by the per-address login limit alike: the address
// may be shared with others, so the text does not blame the account.
const (
	msgCurrentPasswordMissing = "Enter your current password to confirm this action. Nothing was changed."
	msgCurrentPasswordWrong   = "Your current password is not correct. Nothing was changed."
	msgBusy                   = "The server is busy. Try again in a moment. Nothing was changed."
	msgTooManyReentries       = "Too many failed password attempts. Try again later. Nothing was changed."
	msgPromoteUnverified      = "Cannot promote: the email address of this account is not verified."
	msgDemoteLastAdmin        = "Cannot demote: this is the last active admin."
	msgDisableLastAdmin       = "Cannot disable: this is the last active admin."
	// The revoke of all tokens can stop part-way: the tokens revoked before
	// the failure stay revoked and the tunnels are closed in any case, so
	// msgBusy ("Nothing was changed") would be false there.
	msgRevokeTokensIncomplete = "Not every API token could be revoked: the server is busy. " +
		"The tokens revoked so far stay revoked, and the tunnels of this user were closed. Try again in a moment."
)

// parseTargetID reads the {id} path parameter and returns 0 if invalid.
func parseTargetID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// loadTarget reads the {id} path parameter and loads that user. For a
// malformed id or a user that does not exist it answers the router's
// standard 404, on a database error 500; ok reports whether the handler can
// go on. op names the action in the log.
func loadTarget(w http.ResponseWriter, r *http.Request, opts Options, op string) (*sqlcgen.User, bool) {
	id, ok := parseTargetID(r)
	if !ok {
		adminNotFound(w, r)
		return nil, false
	}
	u, err := opts.Users.FindByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			adminNotFound(w, r)
			return nil, false
		}
		serverError(w, "admin "+op+": find user "+strconv.FormatInt(id, 10), err)
		return nil, false
	}
	return u, true
}

// auditAdminAction writes the audit entry of an action on target: the
// acting admin is the actor; target and extra go into the metadata.
func auditAdminAction(r *http.Request, opts Options, action string, target *sqlcgen.User, extra map[string]any) {
	actor := userIDFromContext(r.Context())
	md := map[string]any{"target_user_id": target.ID, "target_email": target.Email}
	for k, v := range extra {
		md[k] = v
	}
	opts.audit(r, &actor, action, md)
}

// actionFailure answers a service error of an action on the target user
// through the web UI's error mapping (serviceFailure): when the request may
// succeed if repeated (no free password-hash slot, a deadlock or a
// serialisation failure) the detail page with msgBusy, 503 and Retry-After;
// otherwise a plain 500 with a fixed text. The error itself is only logged.
func actionFailure(w http.ResponseWriter, r *http.Request, opts Options, targetID int64, op string, err error) {
	actionFailureWith(w, r, opts, targetID, op, err, msgBusy)
}

// actionFailureWith is actionFailure with busyMsg in place of msgBusy on the
// detail page, for an action that may have changed something before it
// failed.
func actionFailureWith(w http.ResponseWriter, r *http.Request, opts Options, targetID int64, op string, err error, busyMsg string) {
	status, msg := serviceFailure(w, op, err)
	if status == http.StatusServiceUnavailable {
		renderDetailStatus(w, r, opts, targetID, status, busyMsg)
		return
	}
	http.Error(w, msg, status)
}

// confirmCurrentPassword checks the acting admin's current password, sent in
// the form field current_password, before an action that needs it (promote,
// demote, password reset). When the password is missing or wrong, or cannot
// be checked, it answers (the detail page with an error, or a plain error)
// and returns false; nothing has been changed at that point. The caller has
// parsed the form.
//
// A re-entry counts against the login limits of the web UI before any
// password hash, through checkCurrentPassword, which the password change on
// the settings page uses too: the per-account limit (the same key and budget
// as a login with the admin's address) and the per-client limit. Over a
// limit it answers 429 with Retry-After. As at login, the attempt is counted
// up front and given back when it succeeds or cannot be decided, so only
// failures stay counted.
func confirmCurrentPassword(w http.ResponseWriter, r *http.Request, opts Options, target *sqlcgen.User, op string) bool {
	ctx := r.Context()
	actorID := userIDFromContext(ctx)
	pw := r.PostFormValue("current_password")
	if pw == "" {
		renderDetailStatus(w, r, opts, target.ID, http.StatusForbidden, msgCurrentPasswordMissing)
		return false
	}

	actor, err := opts.Users.FindByID(ctx, actorID)
	if err != nil {
		serverError(w, "admin "+op+": look up the acting admin", err)
		return false
	}
	verdict, retry, err := opts.checkCurrentPassword(r, actorID, actor.Email, pw)
	switch verdict {
	case passwordLimited:
		log.Printf("admin %s: password re-entry of user %d refused: too many failed password attempts "+
			"for the admin's address or from the client address", op, actorID)
		setRetryAfter(w, retry)
		renderDetailStatus(w, r, opts, target.ID, http.StatusTooManyRequests, msgTooManyReentries)
		return false
	case passwordUndecided:
		actionFailure(w, r, opts, target.ID, "admin "+op+": check the current password", err)
		return false
	case passwordWrong:
		log.Printf("admin %s: wrong current password from user %d (target user %d)", op, actorID, target.ID)
		renderDetailStatus(w, r, opts, target.ID, http.StatusForbidden, msgCurrentPasswordWrong)
		return false
	}
	return true
}

// adminHashSlot takes one of the acting admin's slots for hash work
// (Options.HashPerIP) for an action that hashes: the password re-entry, and
// for a password reset also the new hash. Without a free slot it answers 429
// at once on the detail page and returns ok false; nothing has been changed
// then. The caller defers release.
func adminHashSlot(w http.ResponseWriter, r *http.Request, opts Options, target *sqlcgen.User) (release func(), ok bool) {
	release, ok = opts.takeHashSlot(w, r)
	if !ok {
		renderDetailStatus(w, r, opts, target.ID, http.StatusTooManyRequests, msgHashBusyAdmin)
	}
	return release, ok
}

// adminUserVerify marks target user's email as verified.
func adminUserVerify(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target, ok := loadTarget(w, r, opts, "verify")
		if !ok {
			return
		}
		if err := opts.Users.MarkEmailVerified(r.Context(), target.ID); err != nil {
			actionFailure(w, r, opts, target.ID, "admin verify", err)
			return
		}
		auditAdminAction(r, opts, "admin.user.verify", target, nil)
		redirectToDetail(w, r, target.ID)
	}
}

// adminUserApprove approves a target account that waits for approval (the
// button on its detail page; approval and closed mode only, otherwise the
// standard 404). An approved account is left as it is. The owner gets the
// mail AccountApproved when mail is set up and the account is not
// disabled (sendApprovedMail).
func adminUserApprove(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !opts.approvalRequired() {
			adminNotFound(w, r)
			return
		}
		target, ok := loadTarget(w, r, opts, "approve")
		if !ok {
			return
		}
		if users.IsApproved(target) {
			redirectToDetail(w, r, target.ID)
			return
		}
		if err := opts.Users.Approve(r.Context(), target.ID); err != nil {
			if errors.Is(err, users.ErrNotFound) {
				adminNotFound(w, r)
				return
			}
			actionFailure(w, r, opts, target.ID, "admin approve", err)
			return
		}
		auditAdminAction(r, opts, "admin.user.approve", target, nil)
		sendApprovedMail(opts, target)
		redirectToDetail(w, r, target.ID)
	}
}

// adminUserDisable disables a target user and closes the user's tunnel
// sessions. Blocks self-disable; refuses to disable the last active admin.
func adminUserDisable(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target, ok := loadTarget(w, r, opts, "disable")
		if !ok {
			return
		}
		if target.ID == userIDFromContext(r.Context()) {
			http.Error(w, "cannot disable your own account; use CLI if needed", http.StatusForbidden)
			return
		}

		if err := opts.Users.Disable(r.Context(), opts.Sessions, target.ID); err != nil {
			switch {
			case errors.Is(err, users.ErrNotFound):
				adminNotFound(w, r)
			case errors.Is(err, users.ErrLastAdmin):
				renderDetailStatus(w, r, opts, target.ID, http.StatusConflict, msgDisableLastAdmin)
			default:
				actionFailure(w, r, opts, target.ID, "admin disable", err)
			}
			return
		}

		// Disable has logged the user out of the web UI, and their API tokens
		// no longer verify. The tunnels that are open right now are closed
		// here.
		closed := 0
		if opts.Registry != nil {
			closed = opts.Registry.KillByUser(target.ID)
		}
		auditAdminAction(r, opts, "admin.user.disable", target, map[string]any{"sessions_closed": closed})
		redirectToDetail(w, r, target.ID)
	}
}

// adminUserEnable re-enables a disabled user. An admin cannot enable their
// own account here.
func adminUserEnable(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target, ok := loadTarget(w, r, opts, "enable")
		if !ok {
			return
		}
		if target.ID == userIDFromContext(r.Context()) {
			http.Error(w, "cannot enable your own account", http.StatusForbidden)
			return
		}
		if err := opts.Users.Enable(r.Context(), target.ID); err != nil {
			actionFailure(w, r, opts, target.ID, "admin enable", err)
			return
		}
		auditAdminAction(r, opts, "admin.user.enable", target, nil)
		redirectToDetail(w, r, target.ID)
	}
}

// adminUserRevokeTokens revokes every API token of the target user and
// closes the user's tunnel sessions.
func adminUserRevokeTokens(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target, ok := loadTarget(w, r, opts, "revoke tokens")
		if !ok {
			return
		}
		revoked, revokeErr := revokeAllTokens(r.Context(), opts.Tokens, target.ID)
		// Close the sessions and write the entry also when revoking stopped
		// half-way: the tokens revoked so far are revoked.
		closed := 0
		if opts.Registry != nil {
			closed = opts.Registry.KillByUser(target.ID)
		}
		md := map[string]any{"tokens_revoked": revoked, "sessions_closed": closed}
		if revokeErr != nil {
			md["incomplete"] = true
		}
		auditAdminAction(r, opts, "admin.user.tokens_revoke", target, md)
		if revokeErr != nil {
			// With a text that does not claim that nothing was changed.
			actionFailureWith(w, r, opts, target.ID, "admin revoke tokens", revokeErr, msgRevokeTokensIncomplete)
			return
		}
		redirectToDetail(w, r, target.ID)
	}
}

// revokeAllTokens revokes every token of userID that is not revoked yet and
// returns how many it revoked.
func revokeAllTokens(ctx context.Context, svc *tokens.Service, userID int64) (int, error) {
	list, err := svc.ListActiveByUser(ctx, userID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, tok := range list {
		changed, err := svc.RevokeAny(ctx, tok.ID)
		if err != nil {
			return n, err
		}
		if changed {
			n++
		}
	}
	return n, nil
}

// adminUserPromote promotes a user to admin. It needs the acting admin's
// current password and a target with a verified email address. An admin
// never waits for approval: an account that waits is approved first, with
// its own entry admin.user.approve ("via": "promote"), which stays when the
// promotion then fails.
func adminUserPromote(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		target, ok := loadTarget(w, r, opts, "promote")
		if !ok {
			return
		}
		if !target.EmailVerifiedAt.Valid {
			renderDetailStatus(w, r, opts, target.ID, http.StatusConflict, msgPromoteUnverified)
			return
		}
		release, ok := adminHashSlot(w, r, opts, target)
		if !ok {
			return
		}
		defer release()
		if !confirmCurrentPassword(w, r, opts, target, "promote") {
			return
		}
		if !users.IsApproved(target) {
			if err := opts.Users.Approve(r.Context(), target.ID); err != nil {
				if errors.Is(err, users.ErrNotFound) {
					adminNotFound(w, r)
					return
				}
				actionFailure(w, r, opts, target.ID, "admin promote: approve", err)
				return
			}
			auditAdminAction(r, opts, "admin.user.approve", target, map[string]any{"via": "promote"})
		}
		if err := opts.Users.Promote(r.Context(), target.ID); err != nil {
			actionFailure(w, r, opts, target.ID, "admin promote", err)
			return
		}
		auditAdminAction(r, opts, "admin.user.promote", target, nil)
		redirectToDetail(w, r, target.ID)
	}
}

// adminUserDemote demotes an admin user. It needs the acting admin's current
// password, blocks self-demote, and shows the service's refusal to demote the
// last active admin on the detail page.
func adminUserDemote(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		target, ok := loadTarget(w, r, opts, "demote")
		if !ok {
			return
		}
		if target.ID == userIDFromContext(r.Context()) {
			http.Error(w, "cannot demote your own account via the UI; use CLI if needed", http.StatusForbidden)
			return
		}
		release, ok := adminHashSlot(w, r, opts, target)
		if !ok {
			return
		}
		defer release()
		if !confirmCurrentPassword(w, r, opts, target, "demote") {
			return
		}
		if err := opts.Users.Demote(r.Context(), target.ID); err != nil {
			switch {
			case errors.Is(err, users.ErrNotFound):
				adminNotFound(w, r)
			case errors.Is(err, users.ErrLastAdmin):
				renderDetailStatus(w, r, opts, target.ID, http.StatusConflict, msgDemoteLastAdmin)
			default:
				actionFailure(w, r, opts, target.ID, "admin demote", err)
			}
			return
		}
		auditAdminAction(r, opts, "admin.user.demote", target, nil)
		redirectToDetail(w, r, target.ID)
	}
}

// adminUserResetPassword sets a new password for a user. It needs the acting
// admin's current password and blocks a reset of the admin's own account.
// users.Service.SetPassword applies the rule for admin-set passwords (12
// characters) and, in one transaction, stores the password, logs the account
// out and deletes its open reset links.
func adminUserResetPassword(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		target, ok := loadTarget(w, r, opts, "reset-password")
		if !ok {
			return
		}
		if target.ID == userIDFromContext(r.Context()) {
			http.Error(w, "cannot reset your own password here; use /settings/password instead", http.StatusForbidden)
			return
		}

		newPW := r.PostFormValue("new_password")
		if err := opts.Users.ValidateAdminPassword(newPW); err != nil {
			renderDetailStatus(w, r, opts, target.ID, http.StatusBadRequest, newPasswordMessage(err))
			return
		}
		// One slot covers the re-entry and the hash of the new password.
		release, ok := adminHashSlot(w, r, opts, target)
		if !ok {
			return
		}
		defer release()
		if !confirmCurrentPassword(w, r, opts, target, "reset-password") {
			return
		}

		if err := opts.Users.SetPassword(r.Context(), target.ID, newPW); err != nil {
			switch {
			case errors.Is(err, users.ErrNotFound):
				adminNotFound(w, r)
			case errors.Is(err, users.ErrPasswordTooShort), errors.Is(err, users.ErrPasswordTooLong):
				renderDetailStatus(w, r, opts, target.ID, http.StatusBadRequest, newPasswordMessage(err))
			default:
				actionFailure(w, r, opts, target.ID, "admin reset-password: set", err)
			}
			return
		}
		auditAdminAction(r, opts, "admin.user.password_reset", target, nil)
		redirectToDetail(w, r, target.ID)
	}
}

// newPasswordMessage turns a password rule error of the users service into
// the banner text. Those errors name the rule and no secret.
func newPasswordMessage(err error) string {
	switch {
	case errors.Is(err, users.ErrPasswordTooShort), errors.Is(err, users.ErrPasswordTooLong):
		return "New password not accepted: " + err.Error() + "."
	default:
		return "New password not accepted."
	}
}

// redirectToDetail issues a 303 redirect back to the user detail page.
// It also sets HX-Redirect so HTMX requests navigate correctly.
func redirectToDetail(w http.ResponseWriter, r *http.Request, targetID int64) {
	dest := "/admin/users/" + strconv.FormatInt(targetID, 10)
	w.Header().Set("HX-Redirect", dest)
	http.Redirect(w, r, dest, http.StatusSeeOther)
}
