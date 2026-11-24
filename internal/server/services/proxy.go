// Package services connects registered services (config services) to
// tunneld: a reverse proxy per service that lets only requests with a valid
// tunnel API token through and tells the service whose token it was.
package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
	"github.com/Bazinga0o0/tunnel/internal/server/edgehttp"
)

// The headers by which a service learns the account of a request. Only
// tunneld sets them: whatever a client sends under these names, or any other
// X-Tunnel- name, in any spelling, is dropped.
const (
	HeaderAccountID    = "X-Tunnel-Account-Id"    // decimal
	HeaderAccountEmail = "X-Tunnel-Account-Email" // the account's address
)

// DefaultMaxRequestBodyBytes bounds a request body to a service whose
// max_request_body_bytes is zero: 64 MiB.
const DefaultMaxRequestBodyBytes int64 = 64 << 20

// RequestTimeout is the read and the write deadline of a request to a
// service. It is generous, so that a large upload over a slow line gets
// through: 32 MiB at 5 Mbit/s take about a minute.
const RequestTimeout = 5 * time.Minute

// IdentityTimeout bounds the token check and the account lookup of a
// request together. A check that has not finished by then is answered 503,
// not 401: the token may be valid.
const IdentityTimeout = 5 * time.Second

// Verifier checks a tunnel API token and returns its account. It is
// satisfied by *auth.DBVerifier, which refuses the tokens of disabled and
// not yet approved accounts.
type Verifier interface {
	VerifyWithUser(ctx context.Context, raw string) (int64, bool)
}

// EmailLookup returns the addresses of accounts; satisfied by *users.Service.
type EmailLookup interface {
	LookupEmails(ctx context.Context, ids []int64) (map[int64]string, error)
}

// proxy passes the requests of one service on to its upstream.
type proxy struct {
	name     string
	verifier Verifier
	emails   EmailLookup
	maxBody  int64
	timeout  time.Duration // read and write deadline of a request; tests shorten it
	rp       *httputil.ReverseProxy
	logger   *slog.Logger
	failures *edgeguard.LogLimiter // upstream and lookup failures

	// checkTimeout bounds the token check and the account lookup together
	// (IdentityTimeout); tests shorten it.
	checkTimeout time.Duration
}

// NewProxy returns the handler of the requests to svc. A request needs
// "Authorization: Bearer <token>" with a valid tunnel API token, otherwise
// it is answered 401 and does not reach the service; a token check or
// account lookup that fails or takes longer than IdentityTimeout is 503. The
// service gets neither the Authorization header nor anything a client sent
// as its identity; it gets HeaderAccountID, HeaderAccountEmail and the
// X-Forwarded-* headers of the connection. A request to switch protocols
// (WebSocket, h2c) is answered 400 and does not reach the service either.
//
// A body larger than svc.MaxRequestBodyBytes (zero:
// DefaultMaxRequestBodyBytes) is answered 413, a failing upstream 502. Every
// request has RequestTimeout to send its body and to receive its answer; an
// upstream that has not answered by then is given up (504).
func NewProxy(svc config.Service, v Verifier, users EmailLookup, logger *slog.Logger) (http.Handler, error) {
	target, err := url.Parse(svc.Upstream)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("service %q: upstream is not an absolute URL", svc.Name)
	}
	if v == nil || users == nil || logger == nil {
		return nil, fmt.Errorf("service %q: verifier, email lookup and logger are required", svc.Name)
	}
	p := &proxy{
		name:     svc.Name,
		verifier: v,
		emails:   users,
		maxBody:  svc.MaxRequestBodyBytes,
		timeout:  RequestTimeout,
		logger:   logger,
		failures: edgeguard.NewLogLimiter(edgeguard.LogInterval),

		checkTimeout: IdentityTimeout,
	}
	if p.maxBody <= 0 {
		p.maxBody = DefaultMaxRequestBodyBytes
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // the upstream is on this machine
	p.rp = &httputil.ReverseProxy{
		Rewrite:      func(pr *httputil.ProxyRequest) { rewrite(pr, target) },
		Transport:    identityGuard{transport},
		ErrorHandler: p.fail,
		// What is left for the log are errors while copying an answer, mostly
		// clients that went away.
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
	}
	return p, nil
}

// identity is the checked account of a request.
type identity struct {
	userID int64
	email  string
}

type identityKey struct{}

// valid reports whether id can be passed on: an account id and an address.
func (id identity) valid() bool { return id.userID > 0 && id.email != "" }

// identityFrom returns the checked account that ServeHTTP put into ctx.
func identityFrom(ctx context.Context) (identity, bool) {
	id, ok := ctx.Value(identityKey{}).(identity)
	return id, ok && id.valid()
}

// errNoIdentity is the refusal of identityGuard.
var errNoIdentity = errors.New("request to the service without a checked account")

// identityGuard is the transport's last check: a request without a checked
// account in its context does not go out, whatever path it took to get here.
// ServeHTTP checks the account before; this cannot happen.
type identityGuard struct{ http.RoundTripper }

func (g identityGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, ok := identityFrom(req.Context()); !ok {
		if req.Body != nil {
			_ = req.Body.Close() // a RoundTripper closes the body, also on error
		}
		return nil, errNoIdentity
	}
	return g.RoundTripper.RoundTrip(req)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Deadlines as for the web UI (cmd/tunneld dispatchHost), only longer.
	// The read deadline ends with the body: after it net/http keeps a read
	// pending to notice a client that goes away, and a deadline left in place
	// would cancel the request while the service is still working on it.
	rc := http.NewResponseController(w)
	now := time.Now()
	withBody := hasBody(r)
	if withBody {
		_ = rc.SetReadDeadline(now.Add(p.timeout))
	}
	_ = rc.SetWriteDeadline(now.Add(p.timeout))

	if asksForUpgrade(r.Header) {
		refuse(w, http.StatusBadRequest, "protocol upgrades are not supported")
		return
	}
	id, status := p.identify(r)
	switch status {
	case http.StatusOK:
	case http.StatusUnauthorized:
		refuse(w, status, "unauthorized")
		return
	default:
		refuse(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}

	if r.ContentLength > p.maxBody {
		refuse(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	if withBody {
		r.Body = &requestBody{
			ReadCloser: http.MaxBytesReader(w, r.Body, p.maxBody),
			clear:      func() { _ = rc.SetReadDeadline(time.Time{}) },
		}
	}
	// The call to the service ends with the deadlines: a service that does
	// not answer cannot hold the request beyond them.
	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), identityKey{}, id), p.timeout)
	defer cancel()
	p.rp.ServeHTTP(w, r.WithContext(ctx))
}

// identify checks the token of r and looks up the address of its account,
// both within p.checkTimeout. It returns the account and 200, or the status
// to refuse r with: 401 for a token that is missing or not valid and for an
// account deleted since the check, 503 for a check or lookup that failed or
// did not finish.
func (p *proxy) identify(r *http.Request) (identity, int) {
	token, ok := bearerToken(r.Header)
	if !ok {
		return identity{}, http.StatusUnauthorized
	}
	ctx, cancel := context.WithTimeout(r.Context(), p.checkTimeout)
	defer cancel()
	userID, ok := p.verifier.VerifyWithUser(ctx, token)
	if !ok {
		if err := ctx.Err(); err != nil { // the check did not finish: the token may be valid
			if errors.Is(err, context.DeadlineExceeded) {
				p.logFailure("token check did not finish within the deadline", err)
			}
			return identity{}, http.StatusServiceUnavailable
		}
		return identity{}, http.StatusUnauthorized
	}
	emails, err := p.emails.LookupEmails(ctx, []int64{userID})
	if err != nil {
		p.logFailure("account lookup failed", err)
		return identity{}, http.StatusServiceUnavailable
	}
	email, ok := emails[userID]
	if !ok { // deleted since the token check
		return identity{}, http.StatusUnauthorized
	}
	id := identity{userID: userID, email: email}
	if !id.valid() {
		p.logFailure("account without id or address", fmt.Errorf("user_id %d, email empty: %t", userID, email == ""))
		return identity{}, http.StatusServiceUnavailable
	}
	return id, http.StatusOK
}

// asksForUpgrade reports whether a request asks to switch protocols: it has
// an Upgrade or an HTTP2-Settings header, in any spelling, or "upgrade" among
// its Connection options. No service gets such a request. After the switch
// the client would talk to the service directly, past the identity headers,
// the body limit and the deadlines.
func asksForUpgrade(h http.Header) bool {
	for key, values := range h {
		switch headerName(key) {
		case "upgrade", "http2-settings":
			return true
		case "connection":
			for _, v := range values {
				for _, option := range strings.Split(v, ",") {
					if strings.EqualFold(strings.TrimSpace(option), "upgrade") {
						return true
					}
				}
			}
		}
	}
	return false
}

// refuse answers a request before its body is read, and ends the
// connection (edgehttp.LastAnswer): net/http would otherwise wait for the
// unread body under the generous read deadline, which a client without a
// token could use to hold connections.
func refuse(w http.ResponseWriter, status int, msg string) {
	answered := edgehttp.LastAnswer(w)
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	http.Error(w, msg, status)
	answered()
}

// bearerToken returns the token of the request's one Authorization header
// of the Bearer scheme.
func bearerToken(h http.Header) (string, bool) {
	values := h.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// rewrite builds the request to the service. The ReverseProxy has removed
// the hop-by-hop headers, and with them the ones a client named in
// Connection, before. X-Forwarded-Host is the host in the form the server
// routes on (lower case, no port, no trailing dot): <subdomain>.<domain>.
func rewrite(pr *httputil.ProxyRequest, target *url.URL) {
	out := pr.Out
	for key := range out.Header {
		if isIdentityHeader(key) || edgehttp.IsForwardingHeader(key) {
			delete(out.Header, key)
		}
	}
	// Announced trailers would arrive after the body, in any name.
	for key := range out.Trailer {
		if isIdentityHeader(key) || strings.EqualFold(key, "Authorization") {
			delete(out.Trailer, key)
		}
	}
	out.Header.Del("Authorization")
	pr.SetURL(target)
	pr.SetXForwarded()
	if host, ok := edgehttp.NormalizeHost(pr.In.Host); ok {
		out.Header.Set("X-Forwarded-Host", host)
	} else { // dispatchHost lets no such request through
		out.Header.Del("X-Forwarded-Host")
	}
	id, ok := identityFrom(pr.In.Context())
	if !ok {
		return // identityGuard refuses the request
	}
	out.Header.Set(HeaderAccountID, strconv.FormatInt(id.userID, 10))
	out.Header.Set(HeaderAccountEmail, id.email)
}

// isIdentityHeader reports whether key is one of tunneld's X-Tunnel- headers
// in any spelling, also with "_" for "-", which some frameworks treat as the
// same name.
func isIdentityHeader(key string) bool {
	return strings.HasPrefix(headerName(key), "x-tunnel-")
}

// headerName returns a header name in the form the checks here compare:
// lower case, "_" read as "-".
func headerName(key string) string {
	return strings.ToLower(strings.ReplaceAll(key, "_", "-"))
}

// fail answers a request that did not get an answer from the service. A
// request without a checked account is 500. A body over the limit is 413; a
// body that broke off or came too slowly is the client's doing, as is a
// request it gave up. A service that does not answer within the deadline is
// 504, any other failure of the service 502; both are logged.
func (p *proxy) fail(w http.ResponseWriter, r *http.Request, err error) {
	body, _ := r.Body.(*requestBody)
	bodyErr := body.readErr()
	var tooLarge *http.MaxBytesError
	switch {
	case errors.Is(err, errNoIdentity):
		p.logFailure("refused", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	case errors.As(bodyErr, &tooLarge):
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
	case bodyErr != nil:
		http.Error(w, "request body could not be read", http.StatusBadRequest)
	case errors.Is(r.Context().Err(), context.DeadlineExceeded):
		p.logFailure("upstream did not answer within the deadline", err)
		http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
	case r.Context().Err() != nil:
		w.WriteHeader(http.StatusBadGateway) // the client went away; nobody reads it
	default:
		p.logFailure("upstream failed", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}
}

// logFailure logs a failure of the service or the account lookup, at most
// one line per edgeguard.LogInterval.
func (p *proxy) logFailure(msg string, err error) {
	if ok, suppressed := p.failures.Allow(); ok {
		p.logger.Warn("service "+p.name+": "+msg, "service", p.name, "err", err, "suppressed", suppressed)
	}
}

// hasBody reports whether the request announces a body.
func hasBody(r *http.Request) bool {
	return r.Body != nil && r.Body != http.NoBody && (r.ContentLength != 0 || len(r.TransferEncoding) > 0)
}

// requestBody clears the read deadline when the body has been read to its
// end or a read has failed, and keeps the failure for fail. The transport
// reads it on a goroutine of its own.
type requestBody struct {
	io.ReadCloser
	clear func()
	once  sync.Once
	mu    sync.Mutex
	err   error // first read error other than io.EOF
}

func (b *requestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.clear)
		if err != io.EOF {
			b.mu.Lock()
			if b.err == nil {
				b.err = err
			}
			b.mu.Unlock()
		}
	}
	return n, err
}

// readErr returns the first read error; nil for a nil body.
func (b *requestBody) readErr() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}
