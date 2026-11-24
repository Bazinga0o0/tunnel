package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsEndpointExposesCounters(t *testing.T) {
	AuthAttemptsTotal.WithLabelValues("success").Inc()
	ActiveSessions.WithLabelValues("http").Set(3)

	ts := httptest.NewServer(promhttp.Handler())
	defer ts.Close()

	res, err := http.Get(ts.URL)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	body, _ := io.ReadAll(res.Body)
	s := string(body)
	assert.Contains(t, s, "tunneld_auth_attempts_total")
	assert.Contains(t, s, "tunneld_active_sessions")
	assert.Contains(t, s, "tunneld_cert_not_after_unix")
	assert.True(t, strings.Contains(s, `result="success"`))
}
