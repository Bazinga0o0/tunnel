// Package edgeguard holds the building blocks that the public edges
// (edgehttp, edgetcp, edgeudp) share to stay within bounded resources:
// connection and flow limits, idle deadlines, accept backoff, rate-limited
// logging and panic recovery.
package edgeguard

import (
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"
)

// Resolve applies the convention that all edge options follow: zero selects
// def, a negative value disables the setting, anything else is taken as is.
// A disabled setting is returned as zero, which Limiter and Idle treat as
// "no limit" and "no timeout".
func Resolve[T int | time.Duration](v, def T) T {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return v
}

// Recover stops a panic of the calling goroutine and logs it together with
// the stack, so that one faulty flow or connection cannot end the process.
// It only works when deferred directly:
//
//	defer edgeguard.Recover(logger, "tcp connection", "port", port)
func Recover(logger *slog.Logger, where string, attrs ...any) {
	if r := recover(); r != nil {
		LogPanic(logger, r, where, attrs...)
	}
}

// LogPanic logs a recovered panic value together with the stack. It is for
// deferred functions that call recover themselves because they have to do
// more than log, such as a loop that starts over.
func LogPanic(logger *slog.Logger, recovered any, where string, attrs ...any) {
	args := append([]any{"where", where, "panic", fmt.Sprint(recovered), "stack", string(debug.Stack())}, attrs...)
	logger.Error("panic recovered", args...)
}
