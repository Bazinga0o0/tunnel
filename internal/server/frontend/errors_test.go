package frontend

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freshServiceFailureLog gives serviceFailure a limited log of its own for
// the rest of the test, so that lines of earlier tests hold nothing back.
func freshServiceFailureLog(t *testing.T) {
	t.Helper()
	prev := serviceFailureLog
	serviceFailureLog = newLimitedErrorLog("request failures")
	t.Cleanup(func() { serviceFailureLog = prev })
}

// A failure the server could not handle is logged through a limited log: a
// burst writes its first line, and the lines held back are counted in the
// next one. A failure because the client went away is not logged at all.
func TestServiceFailuresAreLoggedWithALimit(t *testing.T) {
	freshServiceFailureLog(t)
	logs := captureLog(t)
	for i := 0; i < 20; i++ {
		status, _ := serviceFailure(httptest.NewRecorder(), "login", errors.New("database down"))
		require.Equal(t, http.StatusInternalServerError, status)
	}
	assert.Equal(t, 1, strings.Count(logs.String(), "database down"), "one line for a burst:\n%s", logs.String())

	before := logs.String()
	serviceFailure(httptest.NewRecorder(), "login", fmt.Errorf("look up user: %w", context.Canceled))
	assert.Equal(t, before, logs.String(), "a client that went away is no fault of the server")
}

// Logins whose client goes away write no log line, however many come.
func TestAbandonedLoginsWriteNoLogLines(t *testing.T) {
	s := newStack(t)
	logs := captureLog(t)
	for i := 0; i < 20; i++ {
		w := postFormFrom(t, s.h, nil, "/login", url.Values{"email": {"someone@example.com"}, "password": {"short-pw-1"}},
			"203.0.113.9:1", clientGone)
		require.NotEqual(t, http.StatusSeeOther, w.Code)
	}
	assert.NotContains(t, logs.String(), "frontend: login")
}
