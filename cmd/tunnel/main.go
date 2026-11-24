package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/Bazinga0o0/tunnel/internal/client/config"
	"github.com/Bazinga0o0/tunnel/internal/client/connector"
	"github.com/Bazinga0o0/tunnel/internal/client/dialer"
	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// Build information. Release builds set these through the linker
// (-ldflags "-X main.version=... -X main.commit=... -X main.date=...", see
// .goreleaser.yaml); a plain `go build` keeps the defaults.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// maxErrorTextRunes is how much of a command's final error is printed. It is
// far more than any error this program composes itself, and it bounds what a
// peer can put on the terminal through an error that quotes its data.
const maxErrorTextRunes = 2048

func main() {
	if err := rootCmd().Execute(); err != nil {
		printError(os.Stderr, err)
		os.Exit(1)
	}
}

// printError writes the final error of a command on one line. The text can
// contain bytes chosen by the peer even when the peer failed verification: a
// TLS verification error quotes the names from the peer's certificate. It is
// therefore cleaned the same way as text from the server (no escape
// sequences, no line breaks, no bidirectional controls) before it is printed.
func printError(w io.Writer, err error) {
	fmt.Fprintln(w, "error:", dialer.SanitizeText(err.Error(), maxErrorTextRunes))
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tunnel",
		Short: "Tunnel CLI client",
		// main prints the error itself, cleaned by printError. cobra would
		// print it as it is.
		SilenceErrors: true,
	}
	cmd.AddCommand(httpCmd(), tcpCmd(), udpCmd(), configCmd(), versionCmd())
	return cmd
}

func configCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Client configuration",
	}
	c.AddCommand(configInitCmd(), configPathCmd())
	return c
}

func configPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "path",
		Short: "Print the default config file path",
		RunE: func(*cobra.Command, []string) error {
			p, err := config.DefaultPath()
			if err != nil {
				return err
			}
			fmt.Println(p)
			return nil
		},
	}
}

func configInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a blank config file with default fields (safe to re-run)",
		RunE: func(*cobra.Command, []string) error {
			path, err := config.DefaultPath()
			if err != nil {
				return err
			}
			created, err := config.EnsureTemplate(path)
			if err != nil {
				return err
			}
			if created {
				fmt.Printf("✔ wrote template to %s\n", path)
			} else {
				fmt.Printf("✓ already exists at %s\n", path)
			}
			fmt.Println("  Edit server + token, then run: tunnel http <port>")
			return nil
		},
	}
}

// loadClientConfig resolves cfgPath (or default), loads the config, and on
// "file missing" / "blank fields" errors prints a friendly message pointing
// the user at `tunnel config init`. Returns a nil *Config on those paths so
// the caller can bail out cleanly.
//
// Warnings about the config (certificate verification switched off, config
// file readable by other users) are written to warn, one line each.
func loadClientConfig(cfgPath string, warn io.Writer) (*config.Config, error) {
	if cfgPath == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return nil, err
		}
		cfgPath = p
	}

	cfg, err := config.Load(cfgPath)
	if err == nil {
		for _, w := range cfg.Warnings {
			fmt.Fprintf(warn, "warning: %s\n", w.Message)
		}
		return cfg, nil
	}

	// First-run: auto-create an empty template so the user has something to edit.
	if errors.Is(err, config.ErrMissingFile) {
		if _, werr := config.EnsureTemplate(cfgPath); werr != nil {
			return nil, fmt.Errorf("auto-create template: %w", werr)
		}
		// One line each: printError removes line breaks from the final error.
		return nil, fmt.Errorf(
			"no config found — wrote a template to %s. "+
				"Edit server + token, then rerun.", cfgPath)
	}
	if errors.Is(err, config.ErrNotConfigured) {
		return nil, fmt.Errorf(
			"config at %s is incomplete — server + token are required. "+
				"Edit the file, then rerun. (Use `tunnel config path` to re-print the path.)",
			cfgPath)
	}
	return nil, err
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit and build date",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "tunnel %s (commit %s, built %s)\n", version, commit, date)
		},
	}
}

// tunnel describes what differs between the http, tcp and udp commands.
type tunnel struct {
	// streamType is the only type of data stream the command serves.
	streamType protocol.StreamType
	// register sets the tunnel up on the server and returns the status line
	// for the user. Texts taken from the server's reply are already cleaned
	// by the dialer.
	register func(ctx context.Context, sess *dialer.Session, localAddr string) (string, error)
}

// run loads the config, connects, registers the tunnel and serves streams
// until the context is cancelled or the session ends.
func (tn tunnel) run(cmd *cobra.Command, cfgPath string, localPort int) error {
	cfg, err := loadClientConfig(cfgPath, cmd.ErrOrStderr())
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	d := dialer.New(dialer.Options{
		ServerAddr:         cfg.Server,
		Token:              cfg.Token,
		ClientVersion:      version,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		CAFile:             cfg.CAFile,
	})

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	sess, err := d.Dial(ctx)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", cfg.Server, err)
	}
	defer sess.Close()

	// Unblock AcceptStream when the context is cancelled (Ctrl+C).
	go func() {
		<-ctx.Done()
		_ = sess.Close()
	}()

	localAddr := fmt.Sprintf("127.0.0.1:%d", localPort)
	status, err := tn.register(ctx, sess, localAddr)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, status)
	fmt.Fprintln(out, "  (Ctrl+C to stop)")

	conn := connector.New(connector.Options{
		LocalAddr:    localAddr,
		Logger:       logger,
		ExpectedType: tn.streamType,
	})

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept stream: %w", err)
		}
		go func() {
			if err := conn.Handle(stream); err != nil {
				logger.Debug("handle stream", "err", err)
			}
		}()
	}
}

func parsePort(arg, what string) (int, error) {
	port, err := strconv.Atoi(arg)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid %s %q", what, arg)
	}
	return port, nil
}

func httpCmd() *cobra.Command {
	var cfgPath, subdomain string

	c := &cobra.Command{
		Use:   "http PORT",
		Short: "Expose a local HTTP port via the tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			port, err := parsePort(args[0], "port")
			if err != nil {
				return err
			}
			return tunnel{
				streamType: protocol.StreamTypeHTTP,
				register: func(ctx context.Context, sess *dialer.Session, localAddr string) (string, error) {
					ack, err := sess.RegisterHTTP(ctx, subdomain)
					if err != nil {
						return "", fmt.Errorf("register: %w", err)
					}
					return fmt.Sprintf("✔ tunnel up: %s → http://%s", ack.PublicURL, localAddr), nil
				},
			}.run(cmd, cfgPath, port)
		},
	}

	c.Flags().StringVar(&cfgPath, "config", "", "path to client config")
	c.Flags().StringVar(&subdomain, "subdomain", "", "requested subdomain (optional)")
	return c
}

func tcpCmd() *cobra.Command {
	var cfgPath string
	var publicPort int

	c := &cobra.Command{
		Use:   "tcp LOCAL_PORT",
		Short: "Expose a local TCP port via the tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			localPort, err := parsePort(args[0], "local port")
			if err != nil {
				return err
			}
			return tunnel{
				streamType: protocol.StreamTypeTCP,
				register: func(ctx context.Context, sess *dialer.Session, localAddr string) (string, error) {
					ack, err := sess.RegisterTCP(ctx, publicPort)
					if err != nil {
						return "", fmt.Errorf("register tcp: %w", err)
					}
					return fmt.Sprintf("✔ tcp tunnel up: %s → %s", ack.PublicAddr, localAddr), nil
				},
			}.run(cmd, cfgPath, localPort)
		},
	}

	c.Flags().StringVar(&cfgPath, "config", "", "path to client config")
	c.Flags().IntVar(&publicPort, "port", 0, "requested public port (0 = server picks)")
	return c
}

func udpCmd() *cobra.Command {
	var cfgPath string
	var publicPort int

	c := &cobra.Command{
		Use:   "udp LOCAL_PORT",
		Short: "Expose a local UDP port via the tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			localPort, err := parsePort(args[0], "local port")
			if err != nil {
				return err
			}
			return tunnel{
				streamType: protocol.StreamTypeUDP,
				register: func(ctx context.Context, sess *dialer.Session, localAddr string) (string, error) {
					ack, err := sess.RegisterUDP(ctx, publicPort)
					if err != nil {
						return "", fmt.Errorf("register udp: %w", err)
					}
					return fmt.Sprintf("tunnel up (udp): %s  ->  %s", ack.PublicAddr, localAddr), nil
				},
			}.run(cmd, cfgPath, localPort)
		},
	}

	c.Flags().StringVar(&cfgPath, "config", "", "path to client config")
	c.Flags().IntVar(&publicPort, "port", 0, "requested public port (0 = server picks)")
	return c
}
