package integration

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/client/dialer"
	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

// sessionCloseWait bounds the waits for something the server is expected to do; they
// end as soon as it happens.
const sessionCloseWait = 15 * time.Second

func TestDBAuthAndReservationFlow(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	// Seed two users.
	userSvc := users.NewService(pool)
	userA, err := userSvc.Create(ctx, "a@example.com", "pw12345678")
	require.NoError(t, err)
	userB, err := userSvc.Create(ctx, "b@example.com", "pw12345678")
	require.NoError(t, err)

	// Issue tokens.
	tokenSvc := tokens.NewService(pool)
	tokenA, _, err := tokenSvc.Issue(ctx, userA.ID, "a-laptop")
	require.NoError(t, err)
	tokenB, _, err := tokenSvc.Issue(ctx, userB.ID, "b-laptop")
	require.NoError(t, err)

	// User B reserves "myapp".
	resSvc := reservations.NewService(pool)
	require.NoError(t, resSvc.Reserve(ctx, "myapp", userB.ID))

	reg := registry.New()
	addr := startDBAcceptor(t, reg, tokenSvc, resSvc)

	// Client A dials with valid token.
	sessA, err := dialer.New(dialer.Options{
		ServerAddr: addr, Token: tokenA, InsecureSkipVerify: true,
	}).Dial(ctx)
	require.NoError(t, err)

	// A asks for "myapp" — should be rejected (reserved by B).
	_, err = sessA.RegisterHTTP(ctx, "myapp")
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "reserved")

	// A asks for "other-app" — should succeed.
	ack, err := sessA.RegisterHTTP(ctx, "other-app")
	require.NoError(t, err)
	require.Equal(t, "other-app", ack.Subdomain)
	require.Eventually(t, func() bool {
		_, ok := reg.LookupHTTP("other-app")
		return ok
	}, 2*time.Second, 20*time.Millisecond)
	sessA.Close()

	// Client B dials with valid token.
	sessB, err := dialer.New(dialer.Options{
		ServerAddr: addr, Token: tokenB, InsecureSkipVerify: true,
	}).Dial(ctx)
	require.NoError(t, err)
	defer sessB.Close()

	// B asks for "myapp" — should succeed.
	ack, err = sessB.RegisterHTTP(ctx, "myapp")
	require.NoError(t, err)
	require.Equal(t, "myapp", ack.Subdomain)
	require.Eventually(t, func() bool {
		_, ok := reg.LookupHTTP("myapp")
		return ok
	}, 2*time.Second, 20*time.Millisecond)
}

// startDBAcceptor serves database-backed tunnel logins on a loopback port.
func startDBAcceptor(t *testing.T, reg *registry.Registry, tokenSvc *tokens.Service, resSvc *reservations.Service) string {
	t.Helper()
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	acc := acceptor.New(acceptor.Options{
		Domain:       "localhost",
		Registry:     reg,
		DBVerifier:   auth.NewDBVerifier(tokenSvc),
		Reservations: resSvc,
	})
	ln, err := tls.Listen("tcp", testports.Loopback+":0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = acc.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String()
}

// liveTunnel is a logged-in client with an HTTP tunnel.
type liveTunnel struct {
	sess      *dialer.Session
	subdomain string
	ended     chan struct{} // closed when the server ends the session
}

func openTunnel(t *testing.T, addr, token, subdomain string) *liveTunnel {
	t.Helper()
	ctx := context.Background()
	sess, err := dialer.New(dialer.Options{ServerAddr: addr, Token: token, InsecureSkipVerify: true}).Dial(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	ack, err := sess.RegisterHTTP(ctx, subdomain)
	require.NoError(t, err)
	lt := &liveTunnel{sess: sess, subdomain: ack.Subdomain, ended: make(chan struct{})}
	go func() {
		defer close(lt.ended)
		for {
			s, err := sess.AcceptStream()
			if err != nil {
				return
			}
			_ = s.Close()
		}
	}()
	return lt
}

func (lt *liveTunnel) requireClosed(t *testing.T, reg *registry.Registry) {
	t.Helper()
	select {
	case <-lt.ended:
	case <-time.After(sessionCloseWait):
		t.Fatalf("tunnel %s is still connected", lt.subdomain)
	}
	_, ok := reg.LookupHTTP(lt.subdomain)
	require.False(t, ok, "tunnel %s is still routed", lt.subdomain)
}

func (lt *liveTunnel) requireOpen(t *testing.T, reg *registry.Registry) {
	t.Helper()
	select {
	case <-lt.ended:
		t.Fatalf("tunnel %s was closed", lt.subdomain)
	default:
	}
	_, ok := reg.LookupHTTP(lt.subdomain)
	require.True(t, ok, "tunnel %s is routed", lt.subdomain)
}

// The web UI revokes a token with RevokeForUser and then closes the sessions
// opened with it: the session carries its token ID.
func TestRevokingATokenClosesItsTunnelSession(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, err := userSvc.Create(ctx, "revoke@example.com", "pw12345678")
	require.NoError(t, err)
	tokenSvc := tokens.NewService(pool)
	laptop, laptopRow, err := tokenSvc.Issue(ctx, u.ID, "laptop")
	require.NoError(t, err)
	desktop, _, err := tokenSvc.Issue(ctx, u.ID, "desktop")
	require.NoError(t, err)

	reg := registry.New()
	addr := startDBAcceptor(t, reg, tokenSvc, reservations.NewService(pool))
	revoked := openTunnel(t, addr, laptop, "laptop-app")
	kept := openTunnel(t, addr, desktop, "desktop-app")

	changed, err := tokenSvc.RevokeForUser(ctx, u.ID, laptopRow.ID)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, 1, reg.KillByToken(laptopRow.ID))

	revoked.requireClosed(t, reg)
	kept.requireOpen(t, reg)

	// The revoked token cannot open a new session.
	_, err = dialer.New(dialer.Options{ServerAddr: addr, Token: laptop, InsecureSkipVerify: true}).Dial(ctx)
	require.Error(t, err)
}

// The admin panel disables an account with users.Disable and then closes all
// of its sessions.
func TestDisablingAUserClosesTheirTunnelSessions(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	victim, err := userSvc.Create(ctx, "disabled@example.com", "pw12345678")
	require.NoError(t, err)
	bystander, err := userSvc.Create(ctx, "bystander@example.com", "pw12345678")
	require.NoError(t, err)
	tokenSvc := tokens.NewService(pool)
	victimToken, _, err := tokenSvc.Issue(ctx, victim.ID, "laptop")
	require.NoError(t, err)
	victimToken2, _, err := tokenSvc.Issue(ctx, victim.ID, "desktop")
	require.NoError(t, err)
	bystanderToken, _, err := tokenSvc.Issue(ctx, bystander.ID, "laptop")
	require.NoError(t, err)

	reg := registry.New()
	addr := startDBAcceptor(t, reg, tokenSvc, reservations.NewService(pool))
	first := openTunnel(t, addr, victimToken, "victim-one")
	second := openTunnel(t, addr, victimToken2, "victim-two")
	other := openTunnel(t, addr, bystanderToken, "bystander-app")

	require.NoError(t, userSvc.Disable(ctx, nil, victim.ID))
	require.Equal(t, 2, reg.KillByUser(victim.ID))

	first.requireClosed(t, reg)
	second.requireClosed(t, reg)
	other.requireOpen(t, reg)

	// The disabled account's tokens cannot open a new session.
	_, err = dialer.New(dialer.Options{ServerAddr: addr, Token: victimToken, InsecureSkipVerify: true}).Dial(ctx)
	require.Error(t, err)
}
