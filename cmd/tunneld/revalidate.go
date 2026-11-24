package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

const (
	// revalidateQueryTimeout bounds one revalidation query.
	revalidateQueryTimeout = 10 * time.Second
	// revalidateErrLogInterval spaces out the log lines of failing sweeps:
	// during a database outage one line per interval, with the number of
	// failures held back.
	revalidateErrLogInterval = 5 * time.Minute
)

// tokenChecker reports which of the given API token IDs can no longer be
// used. *tokens.Service implements it.
type tokenChecker interface {
	InvalidTokenIDs(ctx context.Context, ids []int64) ([]int64, error)
}

// sessionRevalidator closes tunnel sessions whose API token stopped being
// valid after the login: revoked, expired or deleted, or owned by an account
// that was disabled. The admin CLI changes the database from another process
// and cannot reach the registry of the running server; and a login that was
// verified just before a disable can enter the registry just after
// KillByUser ran. The periodic sweep closes both gaps.
//
// Static-token sessions have no token ID and are never touched.
type sessionRevalidator struct {
	reg      *registry.Registry
	tokens   tokenChecker
	interval time.Duration
	logger   *slog.Logger
	errLog   *edgeguard.LogLimiter
}

func newSessionRevalidator(reg *registry.Registry, tokens tokenChecker, interval time.Duration, logger *slog.Logger) *sessionRevalidator {
	if logger == nil {
		logger = slog.Default()
	}
	return &sessionRevalidator{
		reg:      reg,
		tokens:   tokens,
		interval: interval,
		logger:   logger,
		errLog:   edgeguard.NewLogLimiter(revalidateErrLogInterval),
	}
}

// sweep checks the tokens of all live database sessions with one query and
// closes the sessions of the tokens that are no longer valid. It returns the
// number of sessions it closed. When the query fails it closes nothing and
// returns the error: a database outage must not end every tunnel.
func (v *sessionRevalidator) sweep(ctx context.Context) (int, error) {
	ids := v.reg.TokenIDs()
	if len(ids) == 0 {
		return 0, nil
	}
	qctx, cancel := context.WithTimeout(ctx, revalidateQueryTimeout)
	defer cancel()
	invalid, err := v.tokens.InvalidTokenIDs(qctx, ids)
	if err != nil {
		return 0, err
	}
	closed := 0
	for _, id := range invalid {
		closed += v.reg.KillByToken(id)
	}
	return closed, nil
}

// run sweeps every interval until ctx ends.
func (v *sessionRevalidator) run(ctx context.Context) {
	ticker := time.NewTicker(v.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		closed, err := v.sweep(ctx)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			if ok, suppressed := v.errLog.Allow(); ok {
				v.logger.Error("session revalidation skipped: the token query failed, no session was closed",
					"err", err, "suppressed", suppressed)
			}
		case closed > 0:
			v.logger.Info("closed tunnel sessions whose token is no longer valid", "sessions", closed)
		}
	}
}
