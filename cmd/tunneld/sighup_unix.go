//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// reloadSignals returns a channel that receives once per SIGHUP until ctx
// ends: the signal that asks the server to reload its config (see reload.go).
func reloadSignals(ctx context.Context) <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		<-ctx.Done()
		signal.Stop(ch)
	}()
	return ch
}
