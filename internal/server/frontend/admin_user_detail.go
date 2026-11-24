package frontend

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/csrf"

	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// adminUserDetailPage serves GET /admin/users/{id}.
func adminUserDetailPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetID, ok := parseTargetID(r)
		if !ok {
			adminNotFound(w, r)
			return
		}
		renderDetailStatus(w, r, opts, targetID, http.StatusOK, "")
	}
}

// renderDetailStatus gathers all data for the user detail page and renders
// it with the given status. errMsg is shown as a banner (an action that was
// refused, e.g. for the last admin or a wrong password).
func renderDetailStatus(w http.ResponseWriter, r *http.Request, opts Options, targetID int64, status int, errMsg string) {
	ctx := r.Context()

	u, err := opts.Users.FindByID(ctx, targetID)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			adminNotFound(w, r)
			return
		}
		serverError(w, fmt.Sprintf("admin user detail: find user %d", targetID), err)
		return
	}

	sessCount, err := opts.Sessions.CountActiveByUser(ctx, targetID)
	if err != nil {
		serverError(w, fmt.Sprintf("admin user detail: count sessions %d", targetID), err)
		return
	}

	tokCount, err := opts.Tokens.CountActiveByUserQuery(ctx, targetID)
	if err != nil {
		serverError(w, fmt.Sprintf("admin user detail: count tokens %d", targetID), err)
		return
	}

	subCount, err := opts.Reservations.CountSubdomainsByUser(ctx, targetID)
	if err != nil {
		serverError(w, fmt.Sprintf("admin user detail: count subdomains %d", targetID), err)
		return
	}

	tcpCount, err := opts.Reservations.CountTCPPortsByUser(ctx, targetID)
	if err != nil {
		serverError(w, fmt.Sprintf("admin user detail: count tcp ports %d", targetID), err)
		return
	}

	udpCount, err := opts.Reservations.CountUDPPortsByUser(ctx, targetID)
	if err != nil {
		serverError(w, fmt.Sprintf("admin user detail: count udp ports %d", targetID), err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = templates.AdminUserDetailPage(templates.AdminUserDetailData{
		User:          *u,
		SessionCount:  sessCount,
		TokenCount:    tokCount,
		SubdomainResv: subCount,
		TCPPortResv:   tcpCount,
		UDPPortResv:   udpCount,
		ErrMsg:        errMsg,
		CSRFToken:     csrf.Token(r),
		CSPNonce:      CSPNonceFromContext(ctx),

		ApprovalsActive: opts.approvalRequired(),
	}).Render(ctx, w)
}
