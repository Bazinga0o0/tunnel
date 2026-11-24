package frontend

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/a-h/templ"
	"github.com/gorilla/csrf"

	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	mailtemplates "github.com/Bazinga0o0/tunnel/internal/server/mail/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// Messages of the approvals page.
const (
	msgApprovalsNothingSelected = "Kein Konto ausgewählt. Nichts wurde geändert."
	msgApprovalsStopped         = "Der Server konnte nicht alle ausgewählten Konten bearbeiten. Was oben steht, ist erledigt; " +
		"die übrigen sind unverändert. Bitte später noch einmal versuchen."
)

// The approvals page, its menu item and the approve button of the user
// detail page exist only while accounts wait for an admin's approval
// (Options.approvalRequired: approval and closed mode). With an open
// sign-up no account waits: the accounts simply have no approval, and
// rejecting one would delete an account that is in use.

// adminPendingCount gives the admin pages, in approval and closed mode, the
// counter of their menu item "Freischaltungen (n)"
// (templates.WithPendingCount). It counts only when a page with the menu is
// rendered, not for fragments and actions.
func adminPendingCount(opts Options) func(http.Handler) http.Handler {
	if !opts.approvalRequired() {
		return func(next http.Handler) http.Handler { return next }
	}
	count := func(ctx context.Context) (int64, error) {
		n, err := opts.Users.CountPending(ctx)
		if err != nil {
			opts.lookupLog.printf(err, "admin: count the accounts waiting for approval: %v", err)
		}
		return n, err
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(templates.WithPendingCount(r.Context(), count)))
		})
	}
}

// renderAdminPage renders an admin page with the request's context, which
// carries the counter of the menu (adminPendingCount).
func renderAdminPage(w http.ResponseWriter, r *http.Request, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = c.Render(r.Context(), w)
}

// adminApprovalsPage serves GET /admin/approvals: the accounts that wait for
// approval, in approval and closed mode.
func adminApprovalsPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !opts.approvalRequired() {
			adminNotFound(w, r)
			return
		}
		renderApprovals(w, r, opts, http.StatusOK, templates.AdminApprovalsData{})
	}
}

// renderApprovals renders the approvals page with the accounts that wait
// now, and with what data holds already (the outcome of a POST).
func renderApprovals(w http.ResponseWriter, r *http.Request, opts Options, status int, data templates.AdminApprovalsData) {
	ctx := r.Context()
	rows, err := opts.Users.ListPending(ctx)
	if err != nil {
		serverError(w, "admin approvals: list the accounts", err)
		return
	}
	data.Rows = rows
	data.Now = time.Now()
	data.CSRFToken = csrf.Token(r)
	data.CSPNonce = CSPNonceFromContext(ctx)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = templates.AdminApprovalsPage(data).Render(ctx, w)
}

// adminApprovalsSubmit serves POST /admin/approvals: action "approve" or
// "reject" for every account named in an id field. Each account is handled
// on its own; the page then says, per account, what was done and what was
// skipped, and why.
//
//   - approve: an approved account is skipped, and so is one that does not
//     exist any more (rejected or deleted meanwhile). An approval writes
//     admin.user.approve and sends the owner the mail AccountApproved when
//     mail is set up and the account is not disabled.
//   - reject: the admin's own account and every admin are skipped, and so
//     is an account that does not wait (any more), is disabled or is in use
//     (users.Service.DeletePending). A rejection deletes the account with
//     everything that belongs to it and writes admin.user.reject.
//
// A database error stops the request; what was done before it stays done
// and is listed.
func adminApprovalsSubmit(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !opts.approvalRequired() {
			adminNotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		action := r.PostFormValue("action")
		var one func(*http.Request, Options, int64, *templates.AdminApprovalsData) error
		switch action {
		case "approve":
			one = approveOne
		case "reject":
			one = rejectOne
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
			return
		}
		ids, ok := parseApprovalIDs(r.PostForm["id"])
		if !ok {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		var data templates.AdminApprovalsData
		if len(ids) == 0 {
			data.ErrMsg = msgApprovalsNothingSelected
			renderApprovals(w, r, opts, http.StatusBadRequest, data)
			return
		}
		for _, id := range ids {
			if err := one(r, opts, id, &data); err != nil {
				status, _ := serviceFailure(w, "admin approvals: "+action+" user "+strconv.FormatInt(id, 10), err)
				data.ErrMsg = msgApprovalsStopped
				renderApprovals(w, r, opts, status, data)
				return
			}
		}
		renderApprovals(w, r, opts, http.StatusOK, data)
	}
}

// parseApprovalIDs reads the id fields: each a positive decimal number. It
// drops repeated ids and keeps the order; ok is false for anything else.
func parseApprovalIDs(raw []string) (ids []int64, ok bool) {
	seen := make(map[int64]bool, len(raw))
	for _, s := range raw {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil || id <= 0 {
			return nil, false
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, true
}

// approveOne approves the account id for adminApprovalsSubmit and notes the
// outcome in data. It returns only errors that stop the request.
func approveOne(r *http.Request, opts Options, id int64, data *templates.AdminApprovalsData) error {
	ctx := r.Context()
	u, err := opts.Users.FindByID(ctx, id)
	if errors.Is(err, users.ErrNotFound) {
		data.Skipped = append(data.Skipped, fmt.Sprintf("Konto %d: übersprungen, existiert nicht mehr", id))
		return nil
	}
	if err != nil {
		return err
	}
	if users.IsApproved(u) {
		data.Skipped = append(data.Skipped, u.Email+": übersprungen, bereits freigeschaltet")
		return nil
	}
	if err := opts.Users.Approve(ctx, id); err != nil {
		if errors.Is(err, users.ErrNotFound) {
			data.Skipped = append(data.Skipped, u.Email+": übersprungen, existiert nicht mehr")
			return nil
		}
		return err
	}
	auditAdminAction(r, opts, "admin.user.approve", u, nil)
	sendApprovedMail(opts, u)
	data.Done = append(data.Done, u.Email+": freigeschaltet")
	return nil
}

// rejectOne rejects (deletes) the account id for adminApprovalsSubmit and
// notes the outcome in data. It returns only errors that stop the request.
func rejectOne(r *http.Request, opts Options, id int64, data *templates.AdminApprovalsData) error {
	ctx := r.Context()
	u, err := opts.Users.FindByID(ctx, id)
	if errors.Is(err, users.ErrNotFound) {
		data.Skipped = append(data.Skipped, fmt.Sprintf("Konto %d: übersprungen, existiert nicht mehr", id))
		return nil
	}
	if err != nil {
		return err
	}
	switch {
	case u.ID == userIDFromContext(ctx):
		data.Skipped = append(data.Skipped, u.Email+": übersprungen, eigenes Konto")
		return nil
	case u.IsAdmin:
		data.Skipped = append(data.Skipped, u.Email+": übersprungen, Admin")
		return nil
	}
	if err := opts.Users.DeletePending(ctx, id); err != nil {
		if errors.Is(err, users.ErrNotPending) {
			data.Skipped = append(data.Skipped, u.Email+": übersprungen, wartet nicht auf Freischaltung")
			return nil
		}
		return err
	}
	auditAdminAction(r, opts, "admin.user.reject", u, nil)
	data.Done = append(data.Done, u.Email+": abgelehnt und gelöscht")
	return nil
}

// sendApprovedMail queues the mail AccountApproved to the owner of the
// account u an admin has just approved, when mail is set up (a mailer and
// PublicBaseURL). A disabled account gets no mail: its owner cannot log in.
// Failures are logged; the approval stands.
func sendApprovedMail(opts Options, u *sqlcgen.User) {
	if opts.mails == nil || opts.PublicBaseURL == "" || u.DisabledAt.Valid {
		return
	}
	text, html, err := mailtemplates.AccountApproved(opts.PublicBaseURL + "/login")
	if err != nil {
		log.Printf("frontend: admin approve: render the approval mail: %v", err)
		return
	}
	opts.mails.send(mail.Message{
		To:       u.Email,
		Subject:  mailtemplates.AccountApprovedSubject,
		TextBody: text,
		HTMLBody: html,
	})
}
