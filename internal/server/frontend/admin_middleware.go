package frontend

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// adminNotFound answers with the router's standard 404: the handler the
// chi router serving the request uses for a path that does not exist, or
// http.NotFound outside a chi router. Everything under /admin that is not
// for the requesting admin answers this way, so that it cannot be told apart
// from a missing page.
func adminNotFound(w http.ResponseWriter, r *http.Request) {
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		if mux, ok := rctx.Routes.(interface{ NotFoundHandler() http.HandlerFunc }); ok {
			mux.NotFoundHandler()(w, r)
			return
		}
	}
	http.NotFound(w, r)
}

// requireAdmin is chi middleware for everything under /admin. It does its
// own session check and is mounted outside requireAuth: a request passes only
// with a valid session of an active (not disabled) admin, and then carries
// the user and session IDs in its context as behind requireAuth.
//
// Everybody else gets adminNotFound, the router's standard 404, and no
// redirect to the login page: a request without a session, with an unknown
// or expired session, or from a user who is no admin. The admin URL space
// then answers like a path that does not exist.
//
// secure selects the session cookie name, as in requireAuth; the log lines of
// failed lookups go through lookupLog.
func requireAdmin(sessSvc *sessions.Service, userSvc *users.Service, secure bool, lookupLog *lookupErrorLog) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := readSessionCookie(r, secure)
			if !ok {
				adminNotFound(w, r)
				return
			}
			// Any failure before the request is known to come from an active
			// admin, a database error included, answers the 404 (fail closed):
			// a different answer would tell the admin area apart from a
			// missing page. The error goes to the log.
			sess, err := sessSvc.Lookup(r.Context(), raw)
			if err != nil {
				if !errors.Is(err, sessions.ErrInvalidSession) {
					lookupLog.printf(err, "admin: session lookup: %v", err)
				}
				adminNotFound(w, r)
				return
			}
			isAdmin, err := userSvc.IsAdmin(r.Context(), sess.UserID)
			if err != nil {
				lookupLog.printf(err, "admin: admin check for user %d: %v", sess.UserID, err)
				adminNotFound(w, r)
				return
			}
			if !isAdmin {
				adminNotFound(w, r)
				return
			}
			// As behind requireAuth, no admin response may stay in a cache. It
			// is set only here, after the check: the 404 above must carry
			// exactly the headers of a path that does not exist.
			w.Header().Set("Cache-Control", "no-store")
			ctx := context.WithValue(r.Context(), ctxUserID, sess.UserID)
			ctx = context.WithValue(ctx, ctxSessionID, sess.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
