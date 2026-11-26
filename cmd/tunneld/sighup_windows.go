//go:build windows

package main

import (
	"context"
	"os"
)

// reloadSignals returns a channel that never receives: Windows has no SIGHUP,
// so the config is not reloaded there.
func reloadSignals(context.Context) <-chan os.Signal { return nil }
