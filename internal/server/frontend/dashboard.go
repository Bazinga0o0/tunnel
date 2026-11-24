package frontend

import (
	"net/http"

	"github.com/gorilla/csrf"

	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// dashboardPage renders the authenticated user's overview: account info plus
// counts of active tokens, reserved subdomains, and currently-live tunnels.
func dashboardPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := userIDFromContext(r.Context())
		if userID == 0 {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		u, err := opts.Users.FindByID(r.Context(), userID)
		if err != nil {
			serverError(w, "dashboard: look up user", err)
			return
		}

		tokenCount, err := opts.Tokens.CountActiveByUser(r.Context(), userID)
		if err != nil {
			serverError(w, "dashboard: count tokens", err)
			return
		}

		reservationRows, err := opts.Reservations.ListByUser(r.Context(), userID)
		if err != nil {
			serverError(w, "dashboard: list reservations", err)
			return
		}

		liveCount := 0
		if opts.Registry != nil {
			for _, e := range opts.Registry.Snapshot() {
				if uid, ok := e.Session.(registry.UserIDer); ok && uid.UserIDValue() == userID {
					liveCount++
				}
			}
		}

		renderPage(w, templates.DashboardPage(templates.DashboardData{
			Email:             u.Email,
			CreatedAt:         u.CreatedAt.Time,
			TokenCount:        tokenCount,
			ReservationCount:  len(reservationRows),
			LiveTunnelCount:   liveCount,
			Verified:          u.EmailVerifiedAt.Valid,
			JustVerified:      r.URL.Query().Get("verified") == "1",
			ResendStatus:      r.URL.Query().Get("resend"),
			NeedsVerification: r.URL.Query().Get("needs_verification") == "1",
			AwaitingApproval:  opts.approvalRequired() && !users.IsApproved(u),
			IsAdmin:           u.IsAdmin,
			CSRFToken:         csrf.Token(r),
			CSPNonce:          CSPNonceFromContext(r.Context()),
		}))
	}
}
