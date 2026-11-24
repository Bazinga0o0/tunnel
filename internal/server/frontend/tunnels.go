package frontend

import (
	"net/http"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// tunnelsPage renders the Live tunnels skeleton; the table body is filled
// by an HTMX poll to /tunnels/status.
func tunnelsPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderPage(w, templates.TunnelsPage(templates.TunnelsData{
			Domain:   domainFromOpts(opts),
			CSPNonce: CSPNonceFromContext(r.Context()),
		}))
	}
}

// tunnelsStatusFragment returns an HTML fragment listing the current user's
// live tunnels — filtered from the registry snapshot by UserID.
func tunnelsStatusFragment(opts Options) http.HandlerFunc {
	domain := domainFromOpts(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		userID := userIDFromContext(r.Context())
		rows := []templates.TunnelRow{}
		if opts.Registry != nil {
			for _, e := range opts.Registry.Snapshot() {
				u, ok := e.Session.(registry.UserIDer)
				if !ok || u.UserIDValue() != userID {
					continue
				}
				connected := time.Time{}
				if c, ok := e.Session.(registry.ConnectedAter); ok {
					connected = c.ConnectedAtValue()
				}
				rows = append(rows, templates.TunnelRow{
					Subdomain: e.Subdomain,
					PublicURL: "https://" + e.Subdomain + "." + domain,
					Connected: connected,
				})
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = templates.TunnelsFragment(rows, time.Now()).Render(r.Context(), w)
	}
}
