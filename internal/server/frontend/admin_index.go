package frontend

import (
	"net/http"

	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
)

// adminIndex renders the /admin overview page with aggregate counts.
func adminIndex(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		nonce := CSPNonceFromContext(ctx)

		userCount, err := opts.Users.CountAll(ctx)
		if err != nil {
			serverError(w, "admin index: count users", err)
			return
		}
		adminCount, err := opts.Users.CountAdmins(ctx)
		if err != nil {
			serverError(w, "admin index: count admins", err)
			return
		}
		subdomainResv, err := opts.Reservations.CountSubdomains(ctx)
		if err != nil {
			serverError(w, "admin index: count subdomains", err)
			return
		}
		tcpResv, err := opts.Reservations.CountTCPPorts(ctx)
		if err != nil {
			serverError(w, "admin index: count tcp ports", err)
			return
		}
		udpResv, err := opts.Reservations.CountUDPPorts(ctx)
		if err != nil {
			serverError(w, "admin index: count udp ports", err)
			return
		}

		activeTunnels := 0
		if opts.Registry != nil {
			activeTunnels = len(opts.Registry.Snapshot())
		}

		renderAdminPage(w, r, templates.AdminIndexPage(templates.AdminIndexData{
			UserCount:     userCount,
			AdminCount:    adminCount,
			ActiveTunnels: activeTunnels,
			SubdomainResv: subdomainResv,
			TCPPortResv:   tcpResv,
			UDPPortResv:   udpResv,
			CSPNonce:      nonce,
		}))
	}
}
