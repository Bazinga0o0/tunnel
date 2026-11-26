package frontend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenVerifier accepts the tokens in valid, as the DB verifier does for
// tokens that are neither revoked nor expired.
type tokenVerifier map[string]bool

func (v tokenVerifier) VerifyWithUser(_ context.Context, raw string) (int64, bool) {
	return 1, v[raw]
}

// stuckVerifier never finishes its check.
type stuckVerifier struct{}

func (stuckVerifier) VerifyWithUser(ctx context.Context, _ string) (int64, bool) {
	<-ctx.Done()
	return 0, false
}

func directoryOpts(v DirectoryVerifier) (Options, *Directory) {
	d := &Directory{}
	d.Set([]DirectoryEntry{{Name: "svc", Title: "Svc", Description: "A service", URL: "https://svc.tunnel.test"}})
	o := Options{Directory: d, DirectoryVerifier: v}
	o.limiters = newRateLimiters(o)
	return o, d
}

func getDirectory(h http.Handler, authorization ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", DirectoryPath, nil)
	req.RemoteAddr = "192.0.2.1:1234"
	for _, a := range authorization {
		req.Header.Add("Authorization", a)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestDirectoryAnswersAValidToken(t *testing.T) {
	o, _ := directoryOpts(tokenVerifier{"good": true})
	w := getDirectory(directoryHandler(o), "Bearer good")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.JSONEq(t, `{"services":[{"name":"svc","title":"Svc","description":"A service","url":"https://svc.tunnel.test"}]}`, w.Body.String())
}

func TestDirectoryRefusesWithoutAValidToken(t *testing.T) {
	// "expired" and "revoked" tokens are the verifier's "false" as well.
	o, _ := directoryOpts(tokenVerifier{"good": true, "expired": false})
	h := directoryHandler(o)
	for name, auth := range map[string][]string{
		"no header":     nil,
		"unknown":       {"Bearer nope"},
		"expired":       {"Bearer expired"},
		"empty token":   {"Bearer "},
		"other scheme":  {"Basic good"},
		"two headers":   {"Bearer good", "Bearer good"},
		"scheme only":   {"Bearer"},
		"token no sche": {"good"},
	} {
		w := getDirectory(h, auth...)
		assert.Equal(t, http.StatusUnauthorized, w.Code, name)
		assert.Equal(t, "Bearer", w.Header().Get("WWW-Authenticate"), name)
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), name)
		assert.NotContains(t, w.Body.String(), "svc", name)
	}
}

func TestDirectoryAnswers503WhenTheCheckDoesNotFinish(t *testing.T) {
	o, _ := directoryOpts(stuckVerifier{})
	h := directoryHandler(o)
	start := time.Now()
	w := getDirectory(h, "Bearer x")
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Less(t, time.Since(start), directoryCheckTimeout+2*time.Second)
}

func TestDirectoryListsNothingWhenNothingIsListed(t *testing.T) {
	o, d := directoryOpts(tokenVerifier{"good": true})
	d.Set(nil)
	w := getDirectory(directoryHandler(o), "Bearer good")
	require.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"services":[]}`, w.Body.String())
}

func TestDirectoryFollowsSet(t *testing.T) {
	o, d := directoryOpts(tokenVerifier{"good": true})
	h := directoryHandler(o)
	d.Set([]DirectoryEntry{{Name: "b", Title: "B", URL: "https://b.tunnel.test"}})
	w := getDirectory(h, "Bearer good")
	assert.JSONEq(t, `{"services":[{"name":"b","title":"B","description":"","url":"https://b.tunnel.test"}]}`, w.Body.String())
}

func TestDirectoryIsRateLimitedPerClient(t *testing.T) {
	o, _ := directoryOpts(tokenVerifier{"good": true})
	h := directoryHandler(o)
	for i := 0; i < DirectoryRequestsPerMinute; i++ {
		// Refused requests count as well.
		require.Equal(t, http.StatusUnauthorized, getDirectory(h, "Bearer bad").Code)
	}
	w := getDirectory(h, "Bearer good")
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

	// Another client has its own budget.
	req := httptest.NewRequest("GET", DirectoryPath, nil)
	req.RemoteAddr = "192.0.2.2:1234"
	req.Header.Set("Authorization", "Bearer good")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDirectoryRouteExistsOnlyWhenConfigured(t *testing.T) {
	for name, o := range map[string]Options{
		"without directory": {CSRFKey: testCSRFKey, DirectoryVerifier: tokenVerifier{}},
		"without verifier":  {CSRFKey: testCSRFKey, Directory: &Directory{}},
	} {
		w := getDirectory(New(o), "Bearer good")
		assert.Equal(t, http.StatusNotFound, w.Code, name)
	}
	d := &Directory{}
	d.Set([]DirectoryEntry{{Name: "svc", Title: "Svc", URL: "https://svc.tunnel.test"}})
	h := New(Options{CSRFKey: testCSRFKey, Directory: d, DirectoryVerifier: tokenVerifier{"good": true}})
	w := getDirectory(h, "Bearer good")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Result().Cookies(), "the directory API sets no cookie")
	assert.Equal(t, http.StatusUnauthorized, getDirectory(h).Code)
}
