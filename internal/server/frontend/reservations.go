package frontend

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"

	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
)

// Field errors of the reservation form.
const (
	msgSubdomainInvalid  = "subdomain must be 3–63 chars, lowercase letters/digits/hyphens"
	msgSubdomainSystem   = "that subdomain is reserved for system use"
	msgSubdomainTaken    = "that subdomain is already reserved"
	msgTooManySubdomains = "you have reached the maximum number of reserved subdomains"
)

// domainFromOpts returns the base domain used to render "<sub>.<domain>".
// Falls back to "localhost" when unset (e.g. in unit tests that don't wire it).
func domainFromOpts(opts Options) string {
	if opts.Domain != "" {
		return opts.Domain
	}
	return "localhost"
}

func reservationsPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := userIDFromContext(r.Context())
		rows, err := opts.Reservations.ListByUser(r.Context(), userID)
		if err != nil {
			serverError(w, "reservations: list", err)
			return
		}
		out := make([]templates.ReservationRow, 0, len(rows))
		for _, row := range rows {
			out = append(out, templates.ReservationRow{
				Subdomain: row.Subdomain,
				CreatedAt: row.CreatedAt.Time,
			})
		}
		renderPage(w, templates.ReservationsPage(templates.ReservationsData{
			Rows:      out,
			Domain:    domainFromOpts(opts),
			CSRFToken: csrf.Token(r),
			CSPNonce:  CSPNonceFromContext(r.Context()),
		}))
	}
}

// reservationsCreate reserves a subdomain for the user. The name is
// normalised by the reservations service (trimmed, lower-cased, checked
// against the format and the system names). Its errors, the per-user limit
// included, come back as field errors. After the reservation a tunnel of
// another user that is serving the name right now is closed: the name is
// the owner's from now on.
func reservationsCreate(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := userIDFromContext(r.Context())
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fieldError := func(msg string) {
			w.WriteHeader(statusFieldError)
			_ = templates.ReservationsError(msg).Render(r.Context(), w)
		}

		sub, err := reservations.NormalizeSubdomain(r.PostFormValue("subdomain"))
		if err == nil {
			err = opts.Reservations.Reserve(r.Context(), sub, userID)
		}
		if err != nil {
			switch {
			case errors.Is(err, reservations.ErrInvalidSubdomain):
				fieldError(msgSubdomainInvalid)
			case errors.Is(err, reservations.ErrSystemReserved):
				fieldError(msgSubdomainSystem)
			case errors.Is(err, reservations.ErrAlreadyReserved):
				fieldError(msgSubdomainTaken)
			case errors.Is(err, reservations.ErrReservationLimit):
				fieldError(msgTooManySubdomains)
			default:
				serverError(w, "reservations: reserve", err)
			}
			return
		}
		evicted := 0
		if opts.Registry != nil {
			evicted = opts.Registry.EvictSubdomain(sub, userID)
		}
		opts.audit(r, &userID, "reservation.create", map[string]any{"subdomain": sub, "sessions_closed": evicted})

		// Success: return the new row; HTMX prepends into #reservations-body.
		_ = templates.ReservationsRow(templates.ReservationRow{
			Subdomain: sub,
			CreatedAt: time.Now(),
		}, domainFromOpts(opts), csrf.Token(r)).Render(r.Context(), w)
		// Clear any prior error banner via OOB swap.
		_ = templates.ReservationsError("").Render(r.Context(), w)
	}
}

// reservationsRelease drops one of the user's reservations. Releasing a
// name that is not reserved is a no-op that succeeds (and is not audited);
// a name reserved by somebody else is refused.
func reservationsRelease(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := userIDFromContext(r.Context())
		sub := chi.URLParam(r, "subdomain")
		done := func() {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
		}

		_, reserved, err := opts.Reservations.Owner(r.Context(), sub)
		if err != nil {
			serverError(w, "reservations: look up owner", err)
			return
		}
		if !reserved {
			done()
			return
		}
		if err := opts.Reservations.Release(r.Context(), sub, userID); err != nil {
			if errors.Is(err, reservations.ErrNotOwned) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			serverError(w, "reservations: release", err)
			return
		}
		opts.audit(r, &userID, "reservation.release", map[string]any{"subdomain": sub})
		done()
	}
}
