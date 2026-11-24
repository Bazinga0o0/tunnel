package frontend

import (
	"net/http"
	"strconv"
	"time"

	"github.com/a-h/templ"
)

// userActionWindow is the window of Options.UserActionsPerHour.
const userActionWindow = time.Hour

// msgTooManyUserActions answers a user over Options.UserActionsPerHour.
const msgTooManyUserActions = "Too many changes in a short time. Please try again later."

// userActionKey is the key of a user in the user-actions limiter.
func userActionKey(userID int64) string { return strconv.FormatInt(userID, 10) }

// userActionRefusal writes the answer to a request over
// Options.UserActionsPerHour. Retry-After is set when it runs; it writes the
// status 429 itself.
type userActionRefusal func(w http.ResponseWriter, r *http.Request)

// limitUserActions is the middleware of the mutating actions of the user
// area (create and revoke a token, reserve and release a name, change the
// password): every request that reaches it counts against the signed-in
// user's budget (Options.UserActionsPerHour), whatever the action's
// outcome. Over the budget it sets Retry-After, answers 429 through refuse
// and the action does not run. It runs behind requireAuth (and, for the
// actions that create, behind the verified-address gate, so that a refused
// attempt there does not count). All routes share one budget per user,
// whatever refuse is.
func limitUserActions(opts Options, refuse userActionRefusal) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := userIDFromContext(r.Context())
			if _, retry, ok := opts.limiters.userActions.take(userActionKey(userID)); !ok {
				setRetryAfter(w, retry)
				refuse(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// refuseInErrorField answers an htmx request over the budget with field,
// the out-of-band error field of the page the action belongs to, holding
// msgTooManyUserActions, and HX-Reswap: none, so that htmx shows the message
// and leaves the target of the action (a table row, the table body) as it
// is. The page's htmx configuration swaps 429 responses (templates.Layout).
// A request that is not from htmx gets the message as plain text.
func refuseInErrorField(field func(msg string) templ.Component) userActionRefusal {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("HX-Request") != "true" {
			http.Error(w, msgTooManyUserActions, http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("HX-Reswap", "none")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = field(msgTooManyUserActions).Render(r.Context(), w)
	}
}
