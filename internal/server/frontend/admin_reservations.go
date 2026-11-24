package frontend

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"

	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// PortRange is an inclusive range of ports, [Low, High]. The zero value
// means "not configured".
type PortRange struct {
	Low  int
	High int
}

// configured reports whether the range is set.
func (p PortRange) configured() bool { return p.Low != 0 || p.High != 0 }

// contains reports whether port lies inside the range.
func (p PortRange) contains(port int) bool { return port >= p.Low && port <= p.High }

// Messages the reservations page shows when a grant is refused. They are
// fixed texts: no database error text reaches the browser.
const (
	msgGrantInvalidSubdomain = "Invalid subdomain: use 3 to 63 lower-case letters, digits and inner hyphens."
	msgGrantSystemReserved   = "This subdomain is reserved for system use."
	msgGrantSubdomainTaken   = "This subdomain is already reserved."
	msgGrantPortTaken        = "This port is already reserved."
	msgGrantInvalidPort      = "Invalid port: enter a number from 1 to 65535."
	msgGrantUserNotFound     = "user not found: no account has this email address."
	msgGrantFailed           = "The reservation could not be stored."
)

// adminReservationsPage serves GET /admin/reservations.
// Tabs: ?tab=subdomain (default), ?tab=tcp, ?tab=udp.
// Server-renders only the active tab's table.
func adminReservationsPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tab := r.URL.Query().Get("tab")
		if tab != "tcp" && tab != "udp" {
			tab = "subdomain"
		}

		adminReservationsRender(w, r, opts, tab, http.StatusOK, "")
	}
}

// adminReservationsRender is the shared render helper used by the page handler
// and by the grant handler on error. status is the response status.
func adminReservationsRender(w http.ResponseWriter, r *http.Request, opts Options, tab string, status int, errMsg string) {
	ctx := r.Context()

	sds, err := opts.Reservations.ListAllSubdomains(ctx)
	if err != nil {
		serverError(w, "admin reservations: list subdomains", err)
		return
	}
	tcps, err := opts.Reservations.ListAllTCPPorts(ctx)
	if err != nil {
		serverError(w, "admin reservations: list tcp", err)
		return
	}
	udps, err := opts.Reservations.ListAllUDPPorts(ctx)
	if err != nil {
		serverError(w, "admin reservations: list udp", err)
		return
	}

	// Collect all user IDs for a single batched email lookup.
	idSet := map[int64]struct{}{}
	for _, s := range sds {
		idSet[s.UserID] = struct{}{}
	}
	for _, p := range tcps {
		idSet[p.UserID] = struct{}{}
	}
	for _, p := range udps {
		idSet[p.UserID] = struct{}{}
	}
	ids := make([]int64, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}

	emails := map[int64]string{}
	if opts.Users != nil && len(ids) > 0 {
		emails, err = opts.Users.LookupEmails(ctx, ids)
		if err != nil {
			log.Printf("admin reservations: lookup emails: %v", err)
		}
	}

	data := templates.AdminReservationsPageFromRaw(
		tab,
		csrf.Token(r),
		CSPNonceFromContext(ctx),
		errMsg,
		sds, tcps, udps,
		emails,
	)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = templates.AdminReservationsPage(data).Render(ctx, w)
}

// isReservationType reports whether t is one of the three reservation types.
func isReservationType(t string) bool {
	return t == "subdomain" || t == "tcp" || t == "udp"
}

// parsePort parses a port number as an admin types it: decimal digits only,
// 1 to 65535.
func parsePort(s string) (int, bool) {
	p, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || p == 0 {
		return 0, false
	}
	return int(p), true
}

// portRangeFor returns the configured range for a port type ("tcp", "udp").
func portRangeFor(opts Options, resType string) PortRange {
	if resType == "udp" {
		return opts.UDPPortRange
	}
	return opts.TCPPortRange
}

// adminReservationsGrant serves POST /admin/reservations/grant.
// Form fields: type (subdomain|tcp|udp), key, email.
//
// The name is normalised with reservations.NormalizeSubdomain; a port must be
// a decimal number from 1 to 65535 and lie inside the configured range of its
// edge when one is configured. Refusals re-render the page with a fixed
// message; an unknown type answers 400. Before the grant the account is
// approved (users.Service.Approve), so that an account that waits for
// approval can use what it is given; an account that waited gets an
// admin.user.approve row, whatever the grant's outcome. After the grant,
// tunnel sessions of other users that hold the name or port are closed.
func adminReservationsGrant(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resType := r.PostFormValue("type")
		if !isReservationType(resType) {
			http.Error(w, "unknown reservation type", http.StatusBadRequest)
			return
		}
		key := strings.TrimSpace(r.PostFormValue("key"))
		email := strings.TrimSpace(r.PostFormValue("email"))
		refuse := func(status int, msg string) {
			adminReservationsRender(w, r, opts, resType, status, msg)
		}

		// Check the key before anything is looked up.
		var (
			name string
			port int
		)
		if resType == "subdomain" {
			n, err := reservations.NormalizeSubdomain(key)
			if err != nil {
				refuse(http.StatusBadRequest, grantErrorMessage(err, resType))
				return
			}
			name = n
		} else {
			p, ok := parsePort(key)
			if !ok {
				refuse(http.StatusBadRequest, msgGrantInvalidPort)
				return
			}
			if rng := portRangeFor(opts, resType); rng.configured() && !rng.contains(p) {
				refuse(http.StatusBadRequest, fmt.Sprintf("Port %d is outside the configured %s port range (%d to %d).",
					p, strings.ToUpper(resType), rng.Low, rng.High))
				return
			}
			port = p
		}

		u, err := opts.Users.FindByEmail(ctx, email)
		if err != nil {
			if errors.Is(err, users.ErrNotFound) {
				refuse(http.StatusBadRequest, msgGrantUserNotFound)
				return
			}
			serverError(w, "admin grant: look up user", err)
			return
		}
		// Approving an account that waits gets an audit row of its own,
		// written at once: the approval stays when the grant below is
		// refused.
		wasPending := !users.IsApproved(u)
		if err := opts.Users.Approve(ctx, u.ID); err != nil {
			serverError(w, "admin grant: approve user", err)
			return
		}
		if wasPending {
			auditAdminAction(r, opts, "admin.user.approve", u, map[string]any{"via": "admin.reservation.grant"})
		}

		var md map[string]any
		switch resType {
		case "subdomain":
			err = opts.Reservations.GrantSubdomain(ctx, name, u.ID)
			md = map[string]any{"type": resType, "subdomain": name}
		case "tcp":
			err = opts.Reservations.GrantTCPPort(ctx, port, u.ID)
			md = map[string]any{"type": resType, "port": port}
		case "udp":
			err = opts.Reservations.GrantUDPPort(ctx, port, u.ID)
			md = map[string]any{"type": resType, "port": port}
		}
		if err != nil {
			status, msg := grantErrorStatus(err), grantErrorMessage(err, resType)
			if status == http.StatusInternalServerError {
				// Not a refusal the service names: the web UI's mapping decides
				// between "try again" (503, Retry-After) and a failure.
				status, msg = serviceFailure(w, fmt.Sprintf("admin grant %s %q to user %d", resType, key, u.ID), err)
				if status == http.StatusInternalServerError {
					msg = msgGrantFailed
				}
			}
			refuse(status, msg)
			return
		}

		// The name or port belongs to u now; a tunnel another user holds on
		// it is closed.
		closed := 0
		if opts.Registry != nil {
			switch resType {
			case "subdomain":
				closed = opts.Registry.EvictSubdomain(name, u.ID)
			case "tcp":
				closed = opts.Registry.EvictTCPPort(port, u.ID)
			case "udp":
				closed = opts.Registry.EvictUDPPort(port, u.ID)
			}
		}
		md["sessions_closed"] = closed
		auditAdminAction(r, opts, "admin.reservation.grant", u, md)

		http.Redirect(w, r, "/admin/reservations?tab="+resType, http.StatusSeeOther)
	}
}

// grantErrorStatus is the response status for an error of a grant.
func grantErrorStatus(err error) int {
	switch {
	case errors.Is(err, reservations.ErrInvalidSubdomain),
		errors.Is(err, reservations.ErrSystemReserved),
		errors.Is(err, reservations.ErrInvalidPort):
		return http.StatusBadRequest
	case errors.Is(err, reservations.ErrAlreadyReserved):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

// grantErrorMessage is the fixed text shown for an error of a grant.
func grantErrorMessage(err error, resType string) string {
	switch {
	case errors.Is(err, reservations.ErrInvalidSubdomain):
		return msgGrantInvalidSubdomain
	case errors.Is(err, reservations.ErrSystemReserved):
		return msgGrantSystemReserved
	case errors.Is(err, reservations.ErrInvalidPort):
		return msgGrantInvalidPort
	case errors.Is(err, reservations.ErrAlreadyReserved):
		if resType == "subdomain" {
			return msgGrantSubdomainTaken
		}
		return msgGrantPortTaken
	default:
		return msgGrantFailed
	}
}

// adminReservationsRevoke serves POST /admin/reservations/{type}/revoke.
// The form field key carries the subdomain or port. A subdomain is used
// exactly as stored, without normalising it, so that a name stored before
// names were checked can still be revoked. Returns 200 with an empty body;
// HTMX swaps the row out.
func adminReservationsRevoke(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resType := chi.URLParam(r, "type")
		key := r.PostFormValue("key")

		var (
			owner    int64
			reserved bool
			err      error
			md       map[string]any
			revoke   func() error
		)
		switch resType {
		case "subdomain":
			if key == "" {
				http.Error(w, "missing subdomain", http.StatusBadRequest)
				return
			}
			owner, reserved, err = opts.Reservations.Owner(ctx, key)
			md = map[string]any{"type": resType, "subdomain": key}
			revoke = func() error { return opts.Reservations.RevokeSubdomain(ctx, key) }
		case "tcp", "udp":
			port, ok := parsePort(key)
			if !ok {
				http.Error(w, "bad port", http.StatusBadRequest)
				return
			}
			md = map[string]any{"type": resType, "port": port}
			if resType == "tcp" {
				owner, reserved, err = opts.Reservations.OwnerTCPPort(ctx, port)
				revoke = func() error { return opts.Reservations.RevokeTCPPort(ctx, port) }
			} else {
				owner, reserved, err = opts.Reservations.OwnerUDPPort(ctx, port)
				revoke = func() error { return opts.Reservations.RevokeUDPPort(ctx, port) }
			}
		default:
			http.Error(w, "unknown type", http.StatusBadRequest)
			return
		}
		if err != nil {
			serverError(w, fmt.Sprintf("admin revoke %s %q: look up", resType, key), err)
			return
		}

		if reserved {
			if err := revoke(); err != nil {
				serverError(w, fmt.Sprintf("admin revoke %s %q", resType, key), err)
				return
			}
			actor := userIDFromContext(ctx)
			md["target_user_id"] = owner
			opts.audit(r, &actor, "admin.reservation.revoke", md)
		}

		// Empty 200 — HTMX removes the row via hx-swap="outerHTML".
		w.WriteHeader(http.StatusOK)
	}
}
