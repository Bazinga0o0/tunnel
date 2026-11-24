package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Timeouts of the service API. A call is one short JSON request; setting a
// holder waits for one database transaction.
const (
	serviceAPIReadHeaderTimeout = 5 * time.Second
	serviceAPIReadTimeout       = 10 * time.Second
	serviceAPIWriteTimeout      = 30 * time.Second
	serviceAPIIdleTimeout       = 60 * time.Second
	serviceAPIMaxHeaderBytes    = 16 << 10
)

// startServiceAPIServer binds the service API to addr (a loopback address,
// checked by config validation) and serves h in the background, like
// startMetricsServer. Without an address or without a handler (no service
// is registered) there is nothing to serve: it returns nil and no error. A
// bind error is returned: the server must not start without the API a
// service relies on.
func startServiceAPIServer(addr string, h http.Handler, logger *slog.Logger) (*http.Server, string, error) {
	if addr == "" || h == nil {
		if addr != "" {
			logger.Info("service API not started: no service is registered", "addr", addr)
		}
		return nil, "", nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("service API listen: %w", err)
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: serviceAPIReadHeaderTimeout,
		ReadTimeout:       serviceAPIReadTimeout,
		WriteTimeout:      serviceAPIWriteTimeout,
		IdleTimeout:       serviceAPIIdleTimeout,
		MaxHeaderBytes:    serviceAPIMaxHeaderBytes,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("service API failed", "err", err)
		}
	}()
	bound := ln.Addr().String()
	logger.Info("service API enabled", "addr", bound)
	return srv, bound, nil
}
