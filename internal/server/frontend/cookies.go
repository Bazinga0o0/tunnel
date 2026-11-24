package frontend

import (
	"net/http"
	"time"
)

// Cookie names. With CSRFSecure (production, HTTPS) both cookies carry the
// __Host- prefix: a browser accepts such a cookie only from the host itself,
// with Secure, Path=/ and no Domain attribute. A tunnel on a subdomain can
// therefore not plant a cookie of the same name for the web UI (cookie
// tossing). Over plain HTTP (tests with httptest) the prefix cannot be used,
// so the old names stay.
const (
	sessionCookieNamePlain  = "tunneld_session"
	sessionCookieNameSecure = "__Host-tunneld_session"
	csrfCookieNamePlain     = "_gorilla_csrf" // gorilla/csrf's default name
	csrfCookieNameSecure    = "__Host-tunneld_csrf"
)

// sessionCookieName returns the name of the session cookie for the mode.
func sessionCookieName(secure bool) string {
	if secure {
		return sessionCookieNameSecure
	}
	return sessionCookieNamePlain
}

// csrfCookieName returns the name of the CSRF cookie for the mode.
func csrfCookieName(secure bool) string {
	if secure {
		return csrfCookieNameSecure
	}
	return csrfCookieNamePlain
}

// setSessionCookie writes the session cookie. secure should be true in
// production (HTTPS); tests against httptest.NewServer (plain HTTP) must
// pass false or Go's cookiejar will refuse to store/send the cookie.
func setSessionCookie(w http.ResponseWriter, raw string, expiresAt time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName(secure),
		Value:    raw,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// readSessionCookie returns the value of the session cookie for the mode.
// rejectDuplicateCookies has already refused requests that carry it twice.
func readSessionCookie(r *http.Request, secure bool) (string, bool) {
	c, err := r.Cookie(sessionCookieName(secure))
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	clearCookie(w, sessionCookieName(secure), secure)
}

// clearCookie tells the browser to drop the host-only cookie name. The
// attributes match the ones the cookie was set with; for a __Host- name the
// browser ignores a Set-Cookie without Secure and Path=/.
func clearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// rejectDuplicateCookies refuses a request that carries the session cookie
// or the CSRF cookie more than once, answers 400 and clears both names.
//
// Two cookies of one name mean that something other than this host set one
// of them, for example a tunnel on a subdomain with Domain=<domain> and a
// longer Path, which the browser then sends first. Which of the two is the
// real one cannot be told, so neither is used.
//
// With secure set it also expires the cookies under the plain names
// (tunneld_session, _gorilla_csrf) that a request still carries, for
// example from before the switch to the __Host- names: in that mode they
// are never read, and nothing else would remove them.
func rejectDuplicateCookies(secure bool) func(http.Handler) http.Handler {
	session, csrfName := sessionCookieName(secure), csrfCookieName(secure)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var nSession, nCSRF int
			var oldSession, oldCSRF bool
			for _, c := range r.Cookies() {
				switch c.Name {
				case session:
					nSession++
				case csrfName:
					nCSRF++
				case sessionCookieNamePlain:
					oldSession = secure
				case csrfCookieNamePlain:
					oldCSRF = secure
				}
			}
			if oldSession {
				clearCookie(w, sessionCookieNamePlain, true)
			}
			if oldCSRF {
				clearCookie(w, csrfCookieNamePlain, true)
			}
			if nSession > 1 || nCSRF > 1 {
				clearCookie(w, session, secure)
				clearCookie(w, csrfName, secure)
				http.Error(w, "bad request: duplicate cookies", http.StatusBadRequest)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
