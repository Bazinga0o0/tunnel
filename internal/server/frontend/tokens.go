package frontend

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"

	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
)

// Field errors of the token form.
const (
	msgTokenNameMissing = "Enter a name for the token."
	msgTokenNameTooLong = "The token name is too long."
	msgTooManyTokens    = "You have reached the maximum number of active tokens. Revoke one before you create another."
)

// statusFieldError is the status of a response that carries a field error
// for an htmx form. The layout configures htmx to swap 422 responses (it
// does not swap other 4xx responses), so the error fragment is shown.
const statusFieldError = http.StatusUnprocessableEntity

func tokensPage(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := userIDFromContext(r.Context())
		rows, err := opts.Tokens.ListActiveByUser(r.Context(), userID)
		if err != nil {
			serverError(w, "tokens: list", err)
			return
		}
		renderPage(w, templates.TokensPage(templates.TokensData{
			Tokens:    toTokenRows(rows, time.Now()),
			CSRFToken: csrf.Token(r),
			CSPNonce:  CSPNonceFromContext(r.Context()),
		}))
	}
}

// tokensCreate issues a token and answers with the new table row plus an
// out-of-band banner that shows the raw token once. The limits of the
// service (number of active tokens, name length) come back as field errors.
func tokensCreate(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := userIDFromContext(r.Context())
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fieldError := func(msg string) {
			w.WriteHeader(statusFieldError)
			_ = templates.TokensError(msg).Render(r.Context(), w)
		}

		name := strings.TrimSpace(r.PostFormValue("name"))
		if name == "" {
			fieldError(msgTokenNameMissing)
			return
		}

		raw, row, err := opts.Tokens.Issue(r.Context(), userID, name)
		if err != nil {
			switch {
			case errors.Is(err, tokens.ErrNameTooLong):
				fieldError(msgTokenNameTooLong)
			case errors.Is(err, tokens.ErrTooManyTokens):
				fieldError(msgTooManyTokens)
			default:
				serverError(w, "tokens: create", err)
			}
			return
		}

		opts.audit(r, &userID, "token.create", map[string]any{"token_id": row.ID, "name": row.Name})

		// Out-of-band banner with the raw token — shown once, never again.
		_ = templates.TokenBanner(raw).Render(r.Context(), w)
		// The row itself — this is what the hx-swap=afterbegin targets.
		_ = templates.TokensRow(templates.TokenRow{
			ID:        row.ID,
			Name:      row.Name,
			Prefix:    row.TokenPrefix,
			CreatedAt: row.CreatedAt.Time,
		}, csrf.Token(r)).Render(r.Context(), w)
		// Clear an earlier error.
		_ = templates.TokensError("").Render(r.Context(), w)
	}
}

// tokensRevoke revokes one of the user's own tokens and closes every tunnel
// session that authenticated with it. The revoke is bound to the owner in
// the database: a token of somebody else, one that does not exist and one
// already revoked are all answered 404, and nothing is closed for them.
func tokensRevoke(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := userIDFromContext(r.Context())
		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}

		revoked, err := opts.Tokens.RevokeForUser(r.Context(), userID, id)
		if err != nil {
			serverError(w, "tokens: revoke", err)
			return
		}
		if !revoked {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		closed := 0
		if opts.Registry != nil {
			closed = opts.Registry.KillByToken(id)
		}
		opts.audit(r, &userID, "token.revoke", map[string]any{"token_id": id, "sessions_closed": closed})

		// Empty body → HTMX removes the row via outerHTML swap.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}
}

// toTokenRows converts the stored tokens for the page. A token whose expiry
// lies before now is marked expired: it is listed (so that its owner can
// revoke it) but no longer works.
func toTokenRows(rows []sqlcgen.ListAPITokensByUserRow, now time.Time) []templates.TokenRow {
	out := make([]templates.TokenRow, 0, len(rows))
	for _, r := range rows {
		row := templates.TokenRow{
			ID:        r.ID,
			Name:      r.Name,
			Prefix:    r.TokenPrefix,
			CreatedAt: r.CreatedAt.Time,
			Expired:   r.ExpiresAt.Valid && !r.ExpiresAt.Time.After(now),
		}
		if r.LastUsedAt.Valid {
			t := r.LastUsedAt.Time
			row.LastUsedAt = &t
		}
		out = append(out, row)
	}
	return out
}
