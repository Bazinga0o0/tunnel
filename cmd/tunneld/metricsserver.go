package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metricsPath is where the Prometheus metrics are served.
const metricsPath = "/_tunneld/metrics"

// Timeouts of the metrics endpoint. A scrape is one short request.
const (
	metricsReadHeaderTimeout = 5 * time.Second
	metricsReadTimeout       = 10 * time.Second
	metricsWriteTimeout      = 30 * time.Second
	metricsIdleTimeout       = 60 * time.Second
	metricsMaxHeaderBytes    = 16 << 10
)

// shutdownTimeout bounds the graceful part of a server shutdown.
const shutdownTimeout = 5 * time.Second

// startMetricsServer binds the metrics endpoint to addr (already checked by
// config validation) and serves it in the background. An empty addr disables
// the endpoint: it returns nil and no error. A bind error is returned, and
// the server must not start without the endpoint it was told to provide.
func startMetricsServer(addr string, logger *slog.Logger) (*http.Server, string, error) {
	if addr == "" {
		logger.Info("metrics endpoint disabled (metrics.addr is empty)")
		return nil, "", nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("metrics listen: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.Handler())
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: metricsReadHeaderTimeout,
		ReadTimeout:       metricsReadTimeout,
		WriteTimeout:      metricsWriteTimeout,
		IdleTimeout:       metricsIdleTimeout,
		MaxHeaderBytes:    metricsMaxHeaderBytes,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server failed", "err", err)
		}
	}()
	bound := ln.Addr().String()
	logger.Info("metrics endpoint enabled", "addr", bound, "path", metricsPath)
	return srv, bound, nil
}

// shutdownServer shuts srv down gracefully within timeout and then closes
// whatever is still open. A nil srv is ignored.
func shutdownServer(srv *http.Server, timeout time.Duration) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		_ = srv.Close()
	}
}
