package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/edgehttp"
	"github.com/Bazinga0o0/tunnel/internal/server/reaper"
)

// errDatabaseURL is the whole message for a database URL that cannot be
// parsed. The parser's own error quotes the URL, password included.
var errDatabaseURL = errors.New("config: database.url cannot be parsed; " +
	"check its format and percent-encode special characters in the user name and password")

// ownPort is a port the server listens on itself.
type ownPort struct {
	key  string
	port int
}

func (c *Config) validate() error {
	if c.Domain == "" {
		return errors.New("config: domain is required")
	}
	// The same rules as for the Host of a request; the domain has no port.
	if _, ok := edgehttp.NormalizeHost(c.Domain); !ok || strings.Contains(c.Domain, ":") {
		return fmt.Errorf("config: domain %q is not a host name", c.Domain)
	}
	if c.Listen.TunnelAddr == "" {
		return errors.New("config: listen.tunnel_addr is required")
	}
	if c.Listen.HTTPAddr == "" {
		return errors.New("config: listen.http_addr is required")
	}
	tunnelPort, err := listenPort("listen.tunnel_addr", c.Listen.TunnelAddr)
	if err != nil {
		return err
	}
	httpPort, err := listenPort("listen.http_addr", c.Listen.HTTPAddr)
	if err != nil {
		return err
	}
	if err := c.validateTLS(); err != nil {
		return err
	}
	metricsPort, err := c.validateMetrics()
	if err != nil {
		return err
	}
	serviceAPIPort, err := c.validateServiceAPI()
	if err != nil {
		return err
	}
	own := []ownPort{
		{"listen.tunnel_addr", tunnelPort},
		{"listen.http_addr", httpPort},
		{"metrics.addr", metricsPort},
		{"service_api.addr", serviceAPIPort},
	}
	if c.TCP.Enabled {
		if c.TCP.PortRange.Low == 0 && c.TCP.PortRange.High == 0 {
			c.TCP.PortRange.Low = 10000
			c.TCP.PortRange.High = 20000
		}
		if err := checkPortRange("tcp", c.TCP.PortRange, own); err != nil {
			return err
		}
	}
	if c.UDP.Enabled {
		if c.UDP.PortRange.Low == 0 && c.UDP.PortRange.High == 0 {
			c.UDP.PortRange.Low = 30000
			c.UDP.PortRange.High = 40000
		}
		if err := checkPortRange("udp", c.UDP.PortRange, own); err != nil {
			return err
		}
		if c.UDP.FlowIdleTimeout < 0 {
			return errors.New("config: udp.flow_idle_timeout must not be negative (it cannot be disabled)")
		}
		if c.UDP.FlowBufferSize < 0 {
			return errors.New("config: udp.flow_buffer_size must not be negative")
		}
		if c.UDP.FlowIdleTimeout == 0 {
			c.UDP.FlowIdleTimeout = 30 * time.Second
		}
		if c.UDP.FlowBufferSize == 0 {
			c.UDP.FlowBufferSize = 64
		}
	}
	if err := c.validateAuth(); err != nil {
		return err
	}
	// After the TCP section: the tcp_ports are checked against the port range
	// with its defaults applied.
	if err := c.validateServices(); err != nil {
		return err
	}
	if err := c.validateFrontend(); err != nil {
		return err
	}
	if err := c.validateMail(); err != nil {
		return err
	}
	if err := c.validateBounds(); err != nil {
		return err
	}
	return c.validateLimits()
}

// listenPort checks a listen address and returns its port.
func listenPort(key, addr string) (int, error) {
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be host:port, for example \":443\"", key)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return 0, fmt.Errorf("config: %s must have a numeric port from 0 to 65535", key)
	}
	return port, nil
}

func (c *Config) validateTLS() error {
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		if c.TLS.CertFile == "" {
			return errors.New("config: tls.key_file is set without tls.cert_file")
		}
		return errors.New("config: tls.cert_file is set without tls.key_file")
	}
	hasFiles := c.TLS.CertFile != ""
	hasSelf := len(c.TLS.SelfSignedHosts) > 0
	hasACME := c.TLS.ACME != nil

	configured := 0
	for _, has := range []bool{hasFiles, hasSelf, hasACME} {
		if has {
			configured++
		}
	}
	if configured == 0 {
		return errors.New("config: set one of tls.cert_file+tls.key_file, tls.self_signed_hosts, or tls.acme")
	}
	if configured > 1 {
		return errors.New("config: set only one of tls.cert_file, tls.self_signed_hosts, or tls.acme")
	}
	if !hasACME {
		return nil
	}
	a := c.TLS.ACME
	switch {
	case a.Email == "":
		return errors.New("config: tls.acme.email is required")
	case a.DNSProvider == "":
		return errors.New("config: tls.acme.dns_provider is required")
	case !supportedDNSProviders[a.DNSProvider]:
		return fmt.Errorf("config: tls.acme.dns_provider %q is not supported (supported: ionos)", a.DNSProvider)
	case len(a.Domains) == 0:
		return errors.New("config: tls.acme.domains must not be empty")
	case a.CacheDir == "":
		return errors.New("config: tls.acme.cache_dir is required")
	case !isAbsPath(a.CacheDir):
		return fmt.Errorf("config: tls.acme.cache_dir %q must be an absolute path", a.CacheDir)
	}
	names := make([]string, 0, len(a.Domains))
	for i, d := range a.Domains {
		name, ok := acmeName(d)
		if !ok {
			return fmt.Errorf("config: tls.acme.domains entry %d (%q) is not a host name or *.<host name>", i+1, d)
		}
		names = append(names, name)
	}
	apex, _ := edgehttp.NormalizeHost(c.Domain) // checked by validate
	for _, need := range []string{apex, "app." + apex} {
		if !coveredBy(need, names) {
			return fmt.Errorf("config: tls.acme.domains must cover %s (list it, or a wildcard *.%s)", need, parentOf(need))
		}
	}
	return nil
}

// isAbsPath reports whether p is absolute. A path rooted at "/" counts on
// every system, so that a Linux path in a config can be checked on Windows.
func isAbsPath(p string) bool {
	return filepath.IsAbs(p) || strings.HasPrefix(p, "/")
}

// acmeName checks an ACME certificate name: a host name, or "*." and a host
// name. It returns the name in lower case without a trailing dot.
func acmeName(d string) (string, bool) {
	rest, wildcard := strings.CutPrefix(d, "*.")
	if strings.Contains(rest, ":") {
		return "", false
	}
	host, ok := edgehttp.NormalizeHost(rest)
	if !ok {
		return "", false
	}
	if wildcard {
		return "*." + host, true
	}
	return host, true
}

// coveredBy reports whether one of the certificate names matches host: the
// same name, or a wildcard for its parent (one label).
func coveredBy(host string, names []string) bool {
	for _, n := range names {
		if n == host || n == "*."+parentOf(host) {
			return true
		}
	}
	return false
}

// parentOf returns host without its first label ("" for a single label).
func parentOf(host string) string {
	_, parent, _ := strings.Cut(host, ".")
	return parent
}

// validateMetrics checks metrics.addr and returns its port, 0 when the
// endpoint is disabled.
func (c *Config) validateMetrics() (int, error) {
	addr := c.Metrics.Address()
	if addr == "" {
		return 0, nil
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, errors.New("config: metrics.addr must be host:port, for example \"127.0.0.1:9090\" (an empty string disables the endpoint)")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return 0, errors.New("config: metrics.addr must have a numeric port from 0 to 65535")
	}
	if !c.Metrics.AllowNonLoopback && !isLoopbackHost(host) {
		return 0, fmt.Errorf("config: metrics.addr %q is not a loopback address; the endpoint has no authentication. "+
			"Use 127.0.0.1, ::1 or localhost, or set metrics.allow_non_loopback: true", addr)
	}
	return port, nil
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP
// address. An empty host (all interfaces) is not.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// checkPortRange validates a tunnel port range.
func checkPortRange(name string, r PortRange, own []ownPort) error {
	const lowest, highest = 1024, 65535
	if r.Low < lowest || r.Low > highest {
		return fmt.Errorf("config: %s.port_range.low must be in [%d, %d]", name, lowest, highest)
	}
	if r.High < lowest || r.High > highest {
		return fmt.Errorf("config: %s.port_range.high must be in [%d, %d]", name, lowest, highest)
	}
	if r.Low > r.High {
		return fmt.Errorf("config: %s.port_range.low must be <= %s.port_range.high", name, name)
	}
	for _, o := range own {
		if o.port != 0 && o.port >= r.Low && o.port <= r.High {
			return fmt.Errorf("config: %s.port_range [%d, %d] contains port %d of %s", name, r.Low, r.High, o.port, o.key)
		}
	}
	return nil
}

func (c *Config) validateAuth() error {
	hasDB := c.Database.URL != ""
	hasStatic := len(c.Auth.Tokens) > 0
	if hasDB == hasStatic {
		return errors.New("config: set exactly one of database.url or auth.tokens")
	}
	if s := c.Auth.Signup; s != "" && !supportedSignupModes[s] {
		return fmt.Errorf("config: auth.signup %q is not supported (supported: open, approval, closed)", s)
	}
	if hasStatic {
		if c.Auth.Signup != "" {
			return errors.New("config: auth.signup requires database.url (static auth.tokens have no accounts); remove it in static-token mode")
		}
		// Named by position only: the value is a secret.
		for i, tok := range c.Auth.Tokens {
			if tok == "" {
				return fmt.Errorf("config: auth.tokens entry %d of %d is empty", i+1, len(c.Auth.Tokens))
			}
			if utf8.RuneCountInString(tok) < auth.MinStaticTokenLength {
				return fmt.Errorf("config: auth.tokens entry %d of %d has fewer than %d characters",
					i+1, len(c.Auth.Tokens), auth.MinStaticTokenLength)
			}
		}
		return nil
	}
	if _, err := pgxpool.ParseConfig(c.Database.URL); err != nil {
		return errDatabaseURL
	}
	if c.Auth.CSRFKey == "" {
		return errors.New("config: auth.csrf_key is required when database.url is set (generate via `tunneld admin gen-csrf-key`)")
	}
	decoded, err := base64.StdEncoding.DecodeString(c.Auth.CSRFKey)
	if err != nil {
		return fmt.Errorf("config: auth.csrf_key must be base64-encoded: %w", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("config: auth.csrf_key must decode to 32 bytes, got %d", len(decoded))
	}
	return nil
}

// validateServiceAPI checks service_api.addr and returns its port, 0 when it
// is not set. The API changes who may hold a port, so unlike metrics.addr it
// has no way out of the loopback rule. Port 0 is refused: the service needs
// a port it knows, not one the system picks at every start.
func (c *Config) validateServiceAPI() (int, error) {
	addr := c.ServiceAPI.Addr
	if addr == "" {
		return 0, nil
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, errors.New("config: service_api.addr must be host:port, for example \"127.0.0.1:9100\"")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("config: service_api.addr must have a numeric port from 1 to 65535")
	}
	if !isLoopbackHost(host) {
		return 0, fmt.Errorf("config: service_api.addr %q is not a loopback address; "+
			"the service API must be reachable from this machine only. Use 127.0.0.1, ::1 or localhost", addr)
	}
	return port, nil
}

// serviceNameRE is the shape of services[].name.
var serviceNameRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// dnsLabelRE is one DNS label in lower case: letters, digits and inner
// hyphens, at most 63 characters.
var dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// serviceError is an error of services entry n (counted from 1).
func serviceError(n int, name, format string, args ...any) error {
	return fmt.Errorf("config: services entry %d (%q): %s", n, name, fmt.Sprintf(format, args...))
}

// validateServices checks the registered services. It runs after
// validateAuth (database mode is known) and after the TCP section (the port
// range has its defaults). The secret files are not read here: the admin
// CLI loads the config as well, without access to them.
func (c *Config) validateServices() error {
	if len(c.Services) == 0 {
		return nil
	}
	if c.Database.URL == "" {
		return errors.New("config: services require database.url; " +
			"static auth.tokens have no accounts to pass on to a service")
	}
	apex, _ := edgehttp.NormalizeHost(c.Domain) // checked by validate
	var certNames []string
	if a := c.TLS.ACME; a != nil {
		for _, d := range a.Domains {
			name, _ := acmeName(d) // checked by validateTLS
			certNames = append(certNames, name)
		}
	}
	names := map[string]int{}      // name -> entry
	subdomains := map[string]int{} // subdomain -> entry
	ports := map[int]int{}         // tcp port -> entry
	for i, s := range c.Services {
		n := i + 1
		if !serviceNameRE.MatchString(s.Name) {
			return serviceError(n, s.Name, "name must be 1 to 32 characters of a-z, 0-9 and \"-\"")
		}
		if prev, ok := names[s.Name]; ok {
			return serviceError(n, s.Name, "name is already used by services entry %d", prev)
		}
		names[s.Name] = n

		if !dnsLabelRE.MatchString(s.Subdomain) {
			return serviceError(n, s.Name, "subdomain %q must be one DNS label: "+
				"lower-case letters, digits and inner hyphens, at most 63 characters", s.Subdomain)
		}
		if s.Subdomain == "app" {
			return serviceError(n, s.Name, "subdomain \"app\" is the web UI")
		}
		if prev, ok := subdomains[s.Subdomain]; ok {
			return serviceError(n, s.Name, "subdomain %q is already used by services entry %d", s.Subdomain, prev)
		}
		subdomains[s.Subdomain] = n
		host := s.Subdomain + "." + apex
		if _, ok := edgehttp.NormalizeHost(host); !ok {
			return serviceError(n, s.Name, "%s is not a host name (longer than 253 characters)", host)
		}
		if certNames != nil && !coveredBy(host, certNames) {
			return serviceError(n, s.Name, "tls.acme.domains must cover %s (list it, or a wildcard *.%s)", host, apex)
		}

		if err := checkUpstream(s.Upstream); err != nil {
			return serviceError(n, s.Name, "%s", err)
		}

		if s.SecretFile == "" {
			return serviceError(n, s.Name, "secret_file is required")
		}
		if !isAbsPath(s.SecretFile) {
			return serviceError(n, s.Name, "secret_file %q must be an absolute path", s.SecretFile)
		}

		if s.MaxRequestBodyBytes < 0 {
			return serviceError(n, s.Name, "max_request_body_bytes must not be negative (zero selects 67108864)")
		}
		if s.MaxRequestBodyBytes > maxServiceRequestBody {
			return serviceError(n, s.Name, "max_request_body_bytes must be at most %d", maxServiceRequestBody)
		}

		if err := checkDirectory(s.Directory); err != nil {
			return serviceError(n, s.Name, "%s", err)
		}

		if len(s.TCPPorts) == 0 {
			continue
		}
		if !c.TCP.Enabled {
			return serviceError(n, s.Name, "tcp_ports need tcp.enabled: true")
		}
		if c.ServiceAPI.Addr == "" {
			return serviceError(n, s.Name, "service_api.addr is required for tcp_ports "+
				"(a loopback address such as 127.0.0.1:9100)")
		}
		r := c.TCP.PortRange
		for _, p := range s.TCPPorts {
			if p < r.Low || p > r.High {
				return serviceError(n, s.Name, "tcp_ports: port %d is outside tcp.port_range [%d, %d]", p, r.Low, r.High)
			}
			if prev, ok := ports[p]; ok {
				if prev == n {
					return serviceError(n, s.Name, "tcp_ports: port %d is listed twice", p)
				}
				return serviceError(n, s.Name, "tcp_ports: port %d already belongs to services entry %d (%q)",
					p, prev, c.Services[prev-1].Name)
			}
			ports[p] = n
		}
	}
	return nil
}

// checkDirectory checks services[].directory: a listed service needs a
// title, and both texts must be plain text of bounded length (no control,
// formatting or line-separator characters, valid UTF-8), whether the service
// is listed or not, so that listing it later cannot fail.
func checkDirectory(d Directory) error {
	if d.Listed && strings.TrimSpace(d.Title) == "" {
		return errors.New("directory.title is required when directory.listed is true")
	}
	if err := checkDirectoryText("directory.title", d.Title, MaxDirectoryTitleRunes); err != nil {
		return err
	}
	return checkDirectoryText("directory.description", d.Description, MaxDirectoryDescriptionRunes)
}

func checkDirectoryText(field, v string, max int) error {
	if !utf8.ValidString(v) {
		return fmt.Errorf("%s is not valid UTF-8", field)
	}
	if utf8.RuneCountInString(v) > max {
		return fmt.Errorf("%s must be at most %d characters", field, max)
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return fmt.Errorf("%s must be plain text without control characters or line breaks", field)
		}
	}
	if v != strings.TrimSpace(v) {
		return fmt.Errorf("%s must not start or end with white space", field)
	}
	return nil
}

// checkUpstream checks services[].upstream: an http URL with a loopback host
// and a port, and nothing else. The error does not quote the URL, which can
// carry a password; only the host.
func checkUpstream(raw string) error {
	const example = "upstream must be an http:// URL with a loopback host and a port, such as http://127.0.0.1:8080"
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || !strings.EqualFold(u.Scheme, "http") {
		return errors.New(example)
	}
	if u.User != nil {
		return errors.New("upstream must not contain a user name or password")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("upstream must not have a path, query or fragment")
	}
	if port, err := strconv.Atoi(u.Port()); err != nil || port < 1 || port > 65535 {
		return errors.New("upstream must have a port from 1 to 65535, such as http://127.0.0.1:8080")
	}
	if host := u.Hostname(); !isLoopbackHost(host) {
		return fmt.Errorf("upstream host %q is not a loopback address; use 127.0.0.1, ::1 or localhost", host)
	}
	return nil
}

func (c *Config) validateFrontend() error {
	f := c.Frontend
	if f.PublicBaseURL != "" {
		if err := checkPublicBaseURL(f.PublicBaseURL); err != nil {
			return err
		}
	}
	for _, w := range []struct {
		key string
		v   time.Duration
	}{
		{"login_failure_window", f.LoginFailureWindow},
		{"signup_window", f.SignupWindow},
		{"reset_request_window", f.ResetRequestWindow},
	} {
		if w.v < 0 {
			return fmt.Errorf("config: frontend.%s must not be negative (zero selects the default)", w.key)
		}
	}
	return nil
}

// checkPublicBaseURL requires an absolute https URL without user info,
// query or fragment; http only for loopback hosts.
func checkPublicBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return errors.New("config: frontend.public_base_url must be an absolute URL such as https://app.example.com")
	}
	if u.User != nil {
		return errors.New("config: frontend.public_base_url must not contain a user name or password")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("config: frontend.public_base_url must not contain a query or a fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return errors.New("config: frontend.public_base_url must be an https URL (http is accepted only for localhost and loopback addresses)")
}

func (c *Config) validateLimits() error {
	h := c.HTTPServer
	if h.ReadHeaderTimeout < 0 {
		return errors.New("config: http_server.read_header_timeout cannot be disabled (it also bounds the TLS handshake); zero selects 10s")
	}
	if h.IdleTimeout < 0 {
		return errors.New("config: http_server.idle_timeout cannot be disabled; zero selects 120s")
	}
	if h.MaxHeaderBytes < 0 {
		return errors.New("config: http_server.max_header_bytes cannot be disabled; zero selects 65536")
	}
	if h.MaxHeaderBytes > 0 && h.MaxHeaderBytes < minHeaderBytes {
		return fmt.Errorf("config: http_server.max_header_bytes must be at least %d", minHeaderBytes)
	}
	t := c.Tunnel
	if t.MaxPreAuthFrameBytes > maxFrameBytes {
		return fmt.Errorf("config: tunnel.max_preauth_frame_bytes must be at most %d", maxFrameBytes)
	}
	if t.MaxControlFrameBytes > maxFrameBytes {
		return fmt.Errorf("config: tunnel.max_control_frame_bytes must be at most %d", maxFrameBytes)
	}
	if t.RevalidateInterval > 0 && t.RevalidateInterval < minRevalidateInterval {
		return fmt.Errorf("config: tunnel.revalidate_interval must be at least %s (negative disables it)", minRevalidateInterval)
	}
	if ttl := c.Limits.UnverifiedAccountTTL; ttl > 0 && ttl < reaper.MinUnverifiedAccountTTL {
		return fmt.Errorf("config: limits.unverified_account_ttl must be at least %s (zero leaves the rule off)",
			reaper.MinUnverifiedAccountTTL)
	}
	if ttl := c.Limits.PendingAccountTTL; ttl > 0 && ttl < reaper.MinUnverifiedAccountTTL {
		return fmt.Errorf("config: limits.pending_account_ttl must be at least %s (zero selects 720h, negative switches the deletion off)",
			reaper.MinUnverifiedAccountTTL)
	}
	// A per-address bound as large as the process-wide limit lets one
	// address take every slot: it would protect nothing. Only a value the
	// operator set is checked: unset, the bound follows hash_concurrency
	// (cmd/tunneld hashPerIP), so lowering hash_concurrency alone keeps a
	// config valid.
	perIP, total := c.Limits.HashPerIP, resolve(c.Limits.HashConcurrency, auth.DefaultHashConcurrency)
	if perIP > 0 && total > 0 && perIP >= total {
		return errors.New("config: limits.hash_per_ip must be lower than limits.hash_concurrency, " +
			"or one client address can take every password-hash slot; a negative value switches the per-address bound off")
	}
	return nil
}
