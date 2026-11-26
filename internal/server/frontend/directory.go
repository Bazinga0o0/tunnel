package frontend

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// DirectoryPath is the path of the directory API on the web UI hosts (the
// apex domain and app.<domain>).
const DirectoryPath = "/api/v1/directory"

// DirectoryRequestsPerMinute bounds the requests per client address to the
// directory API; every request counts, whatever its outcome.
const DirectoryRequestsPerMinute = 60

// directoryCheckTimeout bounds the token check of a request. A check that
// has not finished by then is answered 503, not 401: the token may be valid.
const directoryCheckTimeout = 5 * time.Second

// DirectoryVerifier checks a tunnel API token; satisfied by
// *auth.DBVerifier, which refuses revoked and expired tokens and those of
// disabled and not yet approved accounts.
type DirectoryVerifier interface {
	VerifyWithUser(ctx context.Context, raw string) (int64, bool)
}

// DirectoryEntry is a listed service as the directory API shows it.
type DirectoryEntry struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

// Directory holds the listed services. It is replaced as a whole (Set), so
// a reload never shows a half-changed list.
type Directory struct {
	entries atomic.Pointer[[]DirectoryEntry]
}

// Set replaces the listed services.
func (d *Directory) Set(entries []DirectoryEntry) {
	cp := append([]DirectoryEntry(nil), entries...)
	d.entries.Store(&cp)
}

// Entries returns the listed services (never nil).
func (d *Directory) Entries() []DirectoryEntry {
	if p := d.entries.Load(); p != nil {
		return append([]DirectoryEntry{}, *p...)
	}
	return []DirectoryEntry{}
}

// directoryHandler answers GET DirectoryPath: {"services": [...]} to a
// request with "Authorization: Bearer <API token>" of a valid token. Without
// one, or with an invalid, revoked or expired one, it answers 401; a client
// address over DirectoryRequestsPerMinute gets 429 before the token is
// looked at, a token check that fails or does not finish 503. The answer is
// never cached.
func directoryHandler(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		if _, retry, ok := opts.limiters.directory.take(sourceKey(clientIP(r))); !ok {
			setRetryAfter(w, retry)
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		token, ok := directoryBearer(r.Header)
		if !ok {
			directoryUnauthorized(w)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), directoryCheckTimeout)
		defer cancel()
		if _, ok := opts.DirectoryVerifier.VerifyWithUser(ctx, token); !ok {
			if err := ctx.Err(); err != nil { // the check did not finish: the token may be valid
				if errors.Is(err, context.DeadlineExceeded) {
					http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				}
				return
			}
			directoryUnauthorized(w)
			return
		}
		body, err := json.Marshal(struct {
			Services []DirectoryEntry `json:"services"`
		}{opts.Directory.Entries()})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		h.Set("Content-Type", "application/json")
		_, _ = w.Write(append(body, '\n'))
	}
}

func directoryUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// directoryBearer returns the token of the request's one Authorization
// header of the Bearer scheme.
func directoryBearer(h http.Header) (string, bool) {
	values := h.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}
