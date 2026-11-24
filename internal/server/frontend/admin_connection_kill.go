package frontend

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// adminConnectionKill handles POST /admin/connections/{session_id}/kill.
// It finds every tracked session, with or without a tunnel. On success it
// returns 200 with an empty body; HTMX swaps the row out via
// hx-target="closest tr" hx-swap="outerHTML". On unknown session it returns
// the router's standard 404.
func adminConnectionKill(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The ID arrives path-escaped when it holds characters such as "/"
		// (chi matches on the raw path then).
		sessionID, err := url.PathUnescape(chi.URLParam(r, "session_id"))
		if err != nil || opts.Registry == nil {
			adminNotFound(w, r)
			return
		}

		// Note owner and tunnels for the audit entry while the session is
		// still there.
		var ownerID int64
		var tunnels []string
		for _, e := range opts.Registry.SnapshotAll() {
			if e.SessionID != sessionID {
				continue
			}
			if u, ok := e.Session.(registry.UserIDer); ok {
				ownerID = u.UserIDValue()
			}
			switch e.Type {
			case "http":
				tunnels = append(tunnels, "http "+e.Subdomain)
			case "tcp", "udp":
				tunnels = append(tunnels, fmt.Sprintf("%s %d", e.Type, e.Port))
			}
		}

		if !opts.Registry.KillSession(sessionID) {
			adminNotFound(w, r)
			return
		}

		md := map[string]any{"session_id": sessionID}
		if ownerID > 0 {
			md["target_user_id"] = ownerID
		}
		if len(tunnels) > 0 {
			md["tunnels"] = tunnels
		}
		actor := userIDFromContext(r.Context())
		opts.audit(r, &actor, "admin.connection.kill", md)
		w.WriteHeader(http.StatusOK)
	}
}
