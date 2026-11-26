package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Bazinga0o0/tunnel/internal/server/config"
)

// Build information. Release builds set these through the linker
// (-ldflags "-X main.version=... -X main.commit=... -X main.date=...", see
// .goreleaser.yaml); a plain `go build` keeps the defaults.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "serve":
		if err := serve(args); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "admin":
		if err := runAdmin(args); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "version", "--version":
		printVersion(os.Stdout)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tunneld serve --config PATH")
	fmt.Fprintln(os.Stderr, "       tunneld admin <subcommand> --config PATH ...")
	fmt.Fprintln(os.Stderr, "       tunneld version")
	os.Exit(2)
}

// printVersion writes the build information.
func printVersion(w io.Writer) {
	fmt.Fprintf(w, "tunneld %s (commit %s, built %s)\n", version, commit, date)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/tunneld/config.yaml", "path to YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// The errors of Load name the config themselves; none of them quotes a
	// secret (the database URL in particular, see config.errDatabaseURL).
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("tunneld starting", "version", version, "commit", commit, "built", date)
	for _, w := range cfg.Warnings {
		logger.Warn(w)
	}

	// A signal ends the start as well (the wait for an ACME certificate)
	// and then the run.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runServer(ctx, cfg, logger)
}

// runServer assembles the server, binds its listeners and serves until ctx
// ends or a listener fails.
func runServer(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	warnAboutMemory(cfg, logger)

	a, err := newApp(ctx, cfg, logger)
	if err != nil {
		if ctx.Err() != nil {
			logger.Info("shutting down before the start completed")
			return nil
		}
		return err
	}
	// Every way out from here runs this, in this order: the public server
	// stops taking requests; the web UI's mail sender delivers what is
	// queued, with a deadline of its own; the metrics endpoint and the
	// service API stop; the background loops end; the pool they use closes.
	var metricsSrv, serviceAPISrv *http.Server
	defer func() {
		shutdownServer(a.public, shutdownTimeout)
		if err := a.closeFrontend(shutdownTimeout); err != nil {
			logger.Warn("mail queue not empty at shutdown", "err", err)
		}
		shutdownServer(metricsSrv, shutdownTimeout)
		shutdownServer(serviceAPISrv, shutdownTimeout)
		cancel()
		a.closePool()
	}()

	tunnelLn, err := tls.Listen("tcp", cfg.Listen.TunnelAddr, a.tlsConfig)
	if err != nil {
		return fmt.Errorf("tunnel listen: %w", err)
	}
	defer tunnelLn.Close()

	httpLn, err := listenPublic(cfg.Listen.HTTPAddr, a.tlsConfig, cfg.HTTPServer, logger)
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}
	defer httpLn.Close()

	// Loopback-only Prometheus metrics endpoint (config validation refuses
	// other addresses unless metrics.allow_non_loopback is set). A bind
	// error ends the start; a failure of the endpoint later is logged and
	// the server goes on without it.
	metricsSrv, _, err = startMetricsServer(cfg.Metrics.Address(), logger)
	if err != nil {
		return err
	}

	// Loopback-only service API (config validation refuses other
	// addresses), through which the registered services set the holders of
	// their TCP ports. A bind error ends the start.
	serviceAPISrv, _, err = startServiceAPIServer(cfg.ServiceAPI.Addr, a.serviceAPI, logger)
	if err != nil {
		return err
	}

	// The background loops (ACME renewal among them) start only now: a
	// start that fails at one of the binds above has contacted no CA.
	a.startBackground(ctx)

	logger.Info("tunneld listening", "tunnel", cfg.Listen.TunnelAddr, "http", cfg.Listen.HTTPAddr, "domain", cfg.Domain)

	errCh := make(chan error, 2)
	go func() { errCh <- a.acceptor.Serve(ctx, tunnelLn) }()
	go func() { errCh <- a.public.Serve(httpLn) }()

	reloads := reloadSignals(ctx)
	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return nil
		case err := <-errCh:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		case <-reloads:
			a.reloadFromFile()
		}
	}
}
