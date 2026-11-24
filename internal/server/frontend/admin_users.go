package frontend

import (
	"math"
	"net/http"
	"strconv"

	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
)

const adminUsersPageSize = 20

// adminUsersMaxPage is the highest page number served. It keeps the offset,
// (page-1)*adminUsersPageSize, inside the int32 the query takes; a larger
// page number is served as this page (which is empty).
const adminUsersMaxPage = math.MaxInt32 / adminUsersPageSize

// adminUsersPage serves GET /admin/users with optional ?q= search and ?page= pagination.
// When the request carries HX-Request: true it returns only the #users-table fragment.
func adminUsersPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		nonce := CSPNonceFromContext(ctx)

		query := r.URL.Query().Get("q")
		pageStr := r.URL.Query().Get("page")
		// Anything that is not a number above 1 (an int overflow included)
		// is page 1.
		page := 1
		if p, err := strconv.Atoi(pageStr); err == nil && p > 1 {
			page = min(p, adminUsersMaxPage)
		}
		offset := (page - 1) * adminUsersPageSize

		rows, total, err := opts.Users.Search(ctx, query, adminUsersPageSize, offset)
		if err != nil {
			serverError(w, "admin users: search", err)
			return
		}

		data := templates.AdminUsersData{
			Rows:     rows,
			Query:    query,
			Page:     page,
			PageSize: adminUsersPageSize,
			Total:    total,
			CSPNonce: nonce,
		}

		// HTMX partial: return only the table fragment.
		if r.Header.Get("HX-Request") == "true" {
			renderPage(w, templates.AdminUsersTable(data))
			return
		}

		renderAdminPage(w, r, templates.AdminUsersPage(data))
	}
}
