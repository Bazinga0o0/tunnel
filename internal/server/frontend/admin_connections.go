package frontend

import (
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/gorilla/csrf"
)

// Display limits of the connections page.
const (
	// adminConnectionsMaxRows is the number of rows the table shows at most;
	// a note says how many there are when there are more.
	adminConnectionsMaxRows = 200
	// adminConnectionsMaxChars is the length, in characters, to which each
	// displayed value is cut.
	adminConnectionsMaxChars = 64
)

// adminConnectionsPage serves GET /admin/connections — page skeleton only;
// the inner table is polled via HTMX.
func adminConnectionsPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderAdminPage(w, r, templates.AdminConnectionsPage(templates.AdminConnectionsData{
			CSPNonce:  CSPNonceFromContext(r.Context()),
			CSRFToken: csrf.Token(r),
		}))
	}
}

// connectionEntry is one snapshot entry with the session's connect time.
type connectionEntry struct {
	registry.SnapshotEntry
	connectedAt time.Time
}

// adminConnectionsStatus serves GET /admin/connections/status — HTMX fragment
// listing all live sessions across all users, sessions without a tunnel
// included. Polled every 3s. It shows the newest adminConnectionsMaxRows
// rows and cuts every displayed value to adminConnectionsMaxChars.
func adminConnectionsStatus(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		var rows []templates.ConnectionRow
		total := 0
		if opts.Registry != nil {
			snapshot := opts.Registry.SnapshotAll()
			total = len(snapshot)

			entries := make([]connectionEntry, 0, len(snapshot))
			for _, e := range snapshot {
				ce := connectionEntry{SnapshotEntry: e}
				if c, ok := e.Session.(registry.ConnectedAter); ok {
					ce.connectedAt = c.ConnectedAtValue()
				}
				entries = append(entries, ce)
			}
			// Newest first; the rest only makes the order stable.
			sort.Slice(entries, func(i, j int) bool {
				a, b := entries[i], entries[j]
				if !a.connectedAt.Equal(b.connectedAt) {
					return a.connectedAt.After(b.connectedAt)
				}
				if a.SessionID != b.SessionID {
					return a.SessionID < b.SessionID
				}
				if a.Type != b.Type {
					return a.Type < b.Type
				}
				if a.Subdomain != b.Subdomain {
					return a.Subdomain < b.Subdomain
				}
				return a.Port < b.Port
			})
			if len(entries) > adminConnectionsMaxRows {
				entries = entries[:adminConnectionsMaxRows]
			}

			// Collect unique user IDs for a single batched email lookup.
			idSet := map[int64]struct{}{}
			for _, e := range entries {
				if u, ok := e.Session.(registry.UserIDer); ok {
					idSet[u.UserIDValue()] = struct{}{}
				}
			}
			ids := make([]int64, 0, len(idSet))
			for id := range idSet {
				ids = append(ids, id)
			}

			emails := map[int64]string{}
			if opts.Users != nil && len(ids) > 0 {
				var err error
				emails, err = opts.Users.LookupEmails(ctx, ids)
				if err != nil {
					log.Printf("admin connections: lookup emails: %v", err)
				}
			}

			for _, e := range entries {
				key := e.Subdomain // empty for a session without a tunnel
				if e.Type == "tcp" || e.Type == "udp" {
					key = fmt.Sprintf(":%d", e.Port)
				}

				ownerEmail := ""
				if u, ok := e.Session.(registry.UserIDer); ok {
					ownerEmail = emails[u.UserIDValue()]
					if ownerEmail == "" {
						ownerEmail = fmt.Sprintf("uid:%d", u.UserIDValue())
					}
				}

				rows = append(rows, templates.ConnectionRow{
					SessionID:   e.SessionID,
					Type:        truncateDisplay(e.Type, adminConnectionsMaxChars),
					Key:         truncateDisplay(key, adminConnectionsMaxChars),
					OwnerEmail:  truncateDisplay(ownerEmail, adminConnectionsMaxChars),
					ConnectedAt: e.connectedAt,
				})
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = templates.AdminConnectionsTable(templates.AdminConnectionsTableData{
			Rows:      rows,
			Total:     total,
			Now:       time.Now(),
			CSRFToken: csrf.Token(r),
		}).Render(ctx, w)
	}
}

// truncateDisplay cuts s to at most max characters for display; a value
// that was cut ends in "…" (which counts as one of the max characters).
func truncateDisplay(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	return string(runes[:max-1]) + "…"
}
