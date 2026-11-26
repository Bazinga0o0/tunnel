package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staticBase is a valid config in static-token mode; tests append sections.
const staticBase = `domain: tunnel.localhost
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [tunnel.localhost]
auth:
  tokens: [twbl_static_token_0001]
`

// dbBase is a valid config in database mode with ACME, so that it carries no
// warning by itself.
const dbBase = `domain: example.org
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  acme:
    email: "ops@example.org"
    dns_provider: "ionos"
    domains: ["example.org", "*.example.org"]
    cache_dir: "/var/lib/tunneld/certs"
auth:
  csrf_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
database:
  url: "postgres://tunneld:secret@127.0.0.1:5432/tunneld?sslmode=disable"
`

// load writes body to a config file and loads it.
func load(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tunneld.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return Load(path)
}

func mustLoad(t *testing.T, body string) *Config {
	t.Helper()
	cfg, err := load(t, body)
	require.NoError(t, err)
	return cfg
}

func requireRefused(t *testing.T, body, want string) error {
	t.Helper()
	_, err := load(t, body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), want)
	return err
}

func TestBaseConfigsAreValid(t *testing.T) {
	cfg := mustLoad(t, staticBase)
	assert.Empty(t, cfg.Warnings)
	cfg = mustLoad(t, dbBase)
	assert.Empty(t, cfg.Warnings)
}

// ---- unknown keys ----

func TestUnknownKeysAreRefused(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"unknown top-level key": {staticBase + "tunel:\n  max_sessions: 5\n", "tunel"},
		// A classic mistake: an acme block that slipped out of tls: must not
		// leave the self-signed certificate active.
		"acme block outside tls": {strings.Replace(dbBase, "  acme:", "acme:", 1), "acme"},
		"unknown nested key":     {staticBase + "tunnel:\n  max_session: 5\n", "max_session"},
		"typo in a listen key":   {strings.Replace(staticBase, "http_addr", "https_addr", 1), "https_addr"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) { requireRefused(t, tc.body, tc.want) })
	}
}

func TestASecondYAMLDocumentIsRefused(t *testing.T) {
	requireRefused(t, staticBase+"---\ndomain: other.localhost\n", "more than one YAML document")
}

func TestDurationsNeedAUnit(t *testing.T) {
	// A bare number would be nanoseconds.
	err := requireRefused(t, staticBase+"tunnel:\n  handshake_timeout: 10\n", "time.Duration")
	assert.Contains(t, err.Error(), "line 10")
}

// ---- file mode ----

func TestFileModeWarning(t *testing.T) {
	cases := []struct {
		goos string
		mode fs.FileMode
		warn bool
	}{
		{"linux", 0o600, false},
		{"linux", 0o640, false}, // the installer's root:tunneld 0640 on purpose
		{"linux", 0o660, false},
		{"linux", 0o644, true},
		{"linux", 0o604, true},
		{"linux", 0o602, true},
		{"linux", 0o601, true},
		{"darwin", 0o666, true},
		{"windows", 0o666, false}, // the bits do not describe the ACL there
	}
	for _, tc := range cases {
		w := fileModeWarning(tc.goos, "/etc/tunneld/config.yaml", tc.mode)
		if tc.warn {
			assert.Contains(t, w, "/etc/tunneld/config.yaml", "%s %o", tc.goos, tc.mode)
			assert.Contains(t, w, "other users", "%s %o", tc.goos, tc.mode)
		} else {
			assert.Empty(t, w, "%s %o", tc.goos, tc.mode)
		}
	}
}

func TestLoadAttachesTheFileModeWarning(t *testing.T) {
	prev := currentGOOS
	currentGOOS = "linux"
	defer func() { currentGOOS = prev }()

	path := filepath.Join(t.TempDir(), "tunneld.yaml")
	require.NoError(t, os.WriteFile(path, []byte(staticBase), 0o644))
	require.NoError(t, os.Chmod(path, 0o644))
	cfg, err := Load(path)
	require.NoError(t, err)
	// On Windows Chmod cannot clear the "other" bits, so 0644 holds there too.
	require.Len(t, cfg.Warnings, 1)
	assert.Contains(t, cfg.Warnings[0], path)
}

// ---- listen addresses ----

func TestListenAddressesNeedHostAndNumericPort(t *testing.T) {
	for _, addr := range []string{"7443", ":https", "127.0.0.1", ":70000", ":-1"} {
		body := strings.Replace(staticBase, `tunnel_addr: ":7443"`, `tunnel_addr: "`+addr+`"`, 1)
		requireRefused(t, body, "listen.tunnel_addr")
	}
	for _, addr := range []string{":0", "127.0.0.1:7443", "[::1]:7443"} {
		body := strings.Replace(staticBase, `tunnel_addr: ":7443"`, `tunnel_addr: "`+addr+`"`, 1)
		mustLoad(t, body)
	}
}

// ---- port ranges ----

func TestPortRangesStartAtOrAbove1024(t *testing.T) {
	requireRefused(t, staticBase+"tcp:\n  enabled: true\n  port_range: {low: 80, high: 2000}\n", "tcp.port_range.low")
	requireRefused(t, staticBase+"tcp:\n  enabled: true\n  port_range: {low: 1023, high: 2000}\n", "tcp.port_range.low")
	requireRefused(t, staticBase+"udp:\n  enabled: true\n  port_range: {low: 53, high: 2000}\n", "udp.port_range.low")
	cfg := mustLoad(t, staticBase+"tcp:\n  enabled: true\n  port_range: {low: 1024, high: 2000}\n")
	assert.Equal(t, PortRange{Low: 1024, High: 2000}, cfg.TCP.PortRange)
	mustLoad(t, staticBase+"udp:\n  enabled: true\n  port_range: {low: 1024, high: 2000}\n")
}

func TestPortRangesExcludeTheServersOwnPorts(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"tcp range with the tunnel port": {
			staticBase + "tcp:\n  enabled: true\n  port_range: {low: 7000, high: 8000}\n", "listen.tunnel_addr"},
		"tcp range with the https port": {
			strings.Replace(staticBase, `http_addr: ":443"`, `http_addr: ":10443"`, 1) +
				"tcp:\n  enabled: true\n  port_range: {low: 10000, high: 20000}\n", "listen.http_addr"},
		"tcp range with the metrics port": {
			staticBase + "metrics:\n  addr: \"127.0.0.1:15000\"\ntcp:\n  enabled: true\n", "metrics.addr"},
		"tcp range with the default metrics port": {
			staticBase + "tcp:\n  enabled: true\n  port_range: {low: 9000, high: 9100}\n", "metrics.addr"},
		"tcp range with the service API port": {
			staticBase + "service_api:\n  addr: \"127.0.0.1:15000\"\ntcp:\n  enabled: true\n", "service_api.addr"},
		"udp range with the tunnel port": {
			staticBase + "udp:\n  enabled: true\n  port_range: {low: 7443, high: 7443}\n", "listen.tunnel_addr"},
		"upper end": {
			staticBase + "tcp:\n  enabled: true\n  port_range: {low: 7000, high: 7443}\n", "listen.tunnel_addr"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := requireRefused(t, tc.body, tc.want)
			assert.Contains(t, err.Error(), "port_range")
		})
	}

	// Ports next to the range are fine, and a disabled metrics endpoint has
	// no port.
	mustLoad(t, staticBase+"tcp:\n  enabled: true\n  port_range: {low: 7444, high: 8000}\n")
	mustLoad(t, staticBase+"metrics:\n  addr: \"\"\ntcp:\n  enabled: true\n  port_range: {low: 9000, high: 9100}\n")
	// Port 0 (pick any) is no port of the server.
	mustLoad(t, strings.Replace(staticBase, `":7443"`, `"127.0.0.1:0"`, 1)+
		"tcp:\n  enabled: true\n  port_range: {low: 1024, high: 65535}\nmetrics:\n  addr: \"\"\n"+
		"udp:\n  enabled: true\n  port_range: {low: 1024, high: 1100}\n")
}

// ---- TLS sources ----

func TestACMEBlockWithoutEmailIsRefused(t *testing.T) {
	body := strings.Replace(dbBase, `    email: "ops@example.org"`+"\n", "", 1)
	requireRefused(t, body, "tls.acme.email")
}

func TestACMEWithAnUnsupportedDNSProviderIsRefused(t *testing.T) {
	requireRefused(t, strings.Replace(dbBase, `"ionos"`, `"route53"`, 1), "tls.acme.dns_provider")
}

func TestACMENeedsACacheDir(t *testing.T) {
	requireRefused(t, strings.Replace(dbBase, `    cache_dir: "/var/lib/tunneld/certs"`+"\n", "", 1), "tls.acme.cache_dir")
}

func TestACMEAndAnotherSourceAreRefused(t *testing.T) {
	body := strings.Replace(dbBase, "tls:\n", "tls:\n  self_signed_hosts: [example.org]\n", 1)
	requireRefused(t, body, "only one of")
}

func TestCertFileAndKeyFileGoTogether(t *testing.T) {
	body := strings.Replace(staticBase, "  self_signed_hosts: [tunnel.localhost]\n", "  cert_file: /etc/tunneld/cert.pem\n", 1)
	requireRefused(t, body, "tls.key_file")
	body = strings.Replace(staticBase, "  self_signed_hosts: [tunnel.localhost]\n", "  key_file: /etc/tunneld/key.pem\n", 1)
	requireRefused(t, body, "tls.cert_file")
	body = strings.Replace(staticBase, "  self_signed_hosts: [tunnel.localhost]\n",
		"  cert_file: /etc/tunneld/cert.pem\n  key_file: /etc/tunneld/key.pem\n", 1)
	mustLoad(t, body)
}

// ---- static tokens ----

func TestStaticTokensNeedSixteenCharacters(t *testing.T) {
	withTokens := func(tokens string) string {
		return strings.Replace(staticBase, "[twbl_static_token_0001]", tokens, 1)
	}
	err := requireRefused(t, withTokens(`["twbl_static_token_0001", "short_token_15c", "twbl_static_token_0003"]`), "entry 2 of 3")
	assert.NotContains(t, err.Error(), "short_token_15c", "the token is named by its position, never by its value")
	assert.Contains(t, err.Error(), "16")

	err = requireRefused(t, withTokens(`["", "twbl_static_token_0002"]`), "entry 1 of 2")
	assert.Contains(t, err.Error(), "empty")

	// Counted in characters: 16 umlauts pass, 15 do not (30 bytes).
	mustLoad(t, withTokens(`["`+strings.Repeat("ä", 16)+`"]`))
	err = requireRefused(t, withTokens(`["`+strings.Repeat("ä", 15)+`"]`), "entry 1 of 1")
	assert.NotContains(t, err.Error(), "ä")
	mustLoad(t, withTokens(`["0123456789abcdef"]`))
}

// ---- sign-up mode and the wait for approval ----

func TestSignupMode(t *testing.T) {
	signup := func(base, mode string) string {
		return strings.Replace(base, "auth:\n", "auth:\n  signup: "+mode+"\n", 1)
	}
	approval := signup(dbBase, "approval")
	cases := map[string]struct{ body, mode, err string }{
		"unset is open":               {body: dbBase, mode: "open"},
		"approval":                    {body: approval, mode: "approval"},
		"closed":                      {body: signup(dbBase, "closed"), mode: "closed"},
		"unknown mode":                {body: signup(dbBase, "foo"), err: `auth.signup "foo" is not supported`},
		"with static tokens":          {body: signup(staticBase, "approval"), err: "auth.signup requires database.url"},
		"pending ttl below one hour":  {body: approval + "limits:\n  pending_account_ttl: 30m\n", err: "limits.pending_account_ttl must be at least 1h"},
		"negative pending ttl is off": {body: approval + "limits:\n  pending_account_ttl: -1s\n", mode: "approval"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tc.err != "" {
				requireRefused(t, tc.body, tc.err)
				return
			}
			assert.Equal(t, tc.mode, mustLoad(t, tc.body).Auth.SignupMode())
		})
	}
}

// ---- registered services and the service API ----

func TestServicesValidation(t *testing.T) {
	entry := func(name, subdomain, upstream, ports string) string {
		return "  - name: " + name + "\n    subdomain: " + subdomain + "\n    upstream: \"" + upstream + "\"\n" +
			"    secret_file: /etc/tunneld/services/" + name + ".secret\n    tcp_ports: " + ports + "\n"
	}
	services := func(entries ...string) string { return "services:\n" + strings.Join(entries, "") }
	dir := func(flow string) string { return "    directory: " + flow + "\n" }
	const tcp = "tcp:\n  enabled: true\n  port_range: {low: 19000, high: 20000}\n"
	const api = "service_api:\n  addr: \"127.0.0.1:9100\"\n"
	ww := entry("myservice", "myservice", "http://127.0.0.1:8080", "[19000]")

	cases := map[string]struct {
		body string
		errs []string // all in the error; none: the config loads
	}{
		"valid entry": {body: dbBase + tcp + api + services(ww)},
		"upstream not on loopback": {
			body: dbBase + tcp + api + services(entry("myservice", "myservice", "http://10.0.0.5:80", "[19000]")),
			errs: []string{`services entry 1 ("myservice")`, "upstream", "loopback"}},
		"subdomain app": {
			body: dbBase + tcp + api + services(entry("myservice", "app", "http://127.0.0.1:8080", "[19000]")),
			errs: []string{`services entry 1 ("myservice")`, "subdomain", `"app"`}},
		"duplicate name": {
			body: dbBase + tcp + api + services(ww, entry("myservice", "other", "http://127.0.0.1:8081", "[]")),
			errs: []string{`services entry 2 ("myservice")`, "name", "entry 1"}},
		"port outside tcp.port_range": {
			body: dbBase + tcp + api + services(entry("myservice", "myservice", "http://127.0.0.1:8080", "[20001]")),
			errs: []string{`services entry 1 ("myservice")`, "20001", "tcp.port_range"}},
		"one port in two services": {
			body: dbBase + tcp + api + services(ww, entry("other", "other", "http://127.0.0.1:8081", "[19000]")),
			errs: []string{`services entry 2 ("other")`, "19000", "entry 1"}},
		"tcp_ports without service_api.addr": {
			body: dbBase + tcp + services(ww),
			errs: []string{"service_api.addr", "required", "tcp_ports"}},
		"service_api on every interface": {
			body: dbBase + tcp + "service_api:\n  addr: \"0.0.0.0:9100\"\n" + services(ww),
			errs: []string{"service_api.addr", "loopback"}},
		"service_api on port 0": {
			body: dbBase + tcp + "service_api:\n  addr: \"127.0.0.1:0\"\n" + services(ww),
			errs: []string{"service_api.addr", "1 to 65535"}},
		"service_api on port 0 without services": {
			body: dbBase + "service_api:\n  addr: \"127.0.0.1:0\"\n",
			errs: []string{"service_api.addr", "1 to 65535"}},
		"service_api on port 65536": {
			body: dbBase + tcp + "service_api:\n  addr: \"127.0.0.1:65536\"\n" + services(ww),
			errs: []string{"service_api.addr", "1 to 65535"}},
		"directory listed": {
			body: dbBase + tcp + api + services(ww+dir("{listed: true, title: Demo, description: A demo service}"))},
		"directory listed without title": {
			body: dbBase + tcp + api + services(ww+dir("{listed: true}")),
			errs: []string{`services entry 1 ("myservice")`, "directory.title", "required"}},
		"directory title too long": {
			body: dbBase + tcp + api + services(ww+dir(`{title: "`+strings.Repeat("a", 81)+`"}`)),
			errs: []string{"directory.title", "at most 80"}},
		"directory description too long": {
			body: dbBase + tcp + api + services(ww+dir(`{description: "`+strings.Repeat("a", 401)+`"}`)),
			errs: []string{"directory.description", "at most 400"}},
		"directory description with line break": {
			body: dbBase + tcp + api + services(ww+dir(`{description: "a\nb"}`)),
			errs: []string{"directory.description", "control characters"}},
		"directory title with direction override": {
			body: dbBase + tcp + api + services(ww+dir(`{listed: true, title: "a‮b"}`)),
			errs: []string{"directory.title", "control characters"}},
		"directory title with outer white space": {
			body: dbBase + tcp + api + services(ww+dir(`{listed: true, title: " a"}`)),
			errs: []string{"directory.title", "white space"}},
		"static tokens": {
			body: staticBase + tcp + api + services(ww),
			errs: []string{"services", "database.url"}},
		"request body over 256 MiB": {
			body: dbBase + tcp + api + services(ww+"    max_request_body_bytes: 300000000\n"),
			errs: []string{`services entry 1 ("myservice")`, "max_request_body_bytes", "268435456"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if len(tc.errs) == 0 {
				cfg := mustLoad(t, tc.body)
				require.Len(t, cfg.Services, 1)
				assert.Zero(t, cfg.Services[0].MaxRequestBodyBytes, "the default is set where the proxy is built")
				return
			}
			err := requireRefused(t, tc.body, tc.errs[0])
			for _, want := range tc.errs[1:] {
				assert.Contains(t, err.Error(), want)
			}
		})
	}
}

// Load remembers the file, as an absolute path: the server names it in the
// commands it suggests in its log.
func TestLoadRemembersTheAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.WriteFile("relative.yaml", []byte(dbBase), 0o600))
	cfg, err := Load("relative.yaml")
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(cfg.Path), cfg.Path)
	want, err := os.Stat(filepath.Join(dir, "relative.yaml"))
	require.NoError(t, err)
	got, err := os.Stat(cfg.Path)
	require.NoError(t, err)
	assert.True(t, os.SameFile(want, got), cfg.Path)
}

// ---- public base URL ----

func TestPublicBaseURLMustBeHTTPS(t *testing.T) {
	withURL := func(u string) string { return dbBase + "frontend:\n  public_base_url: \"" + u + "\"\n" }
	for _, ok := range []string{
		"", "https://app.example.org", "https://app.example.org:8443", "https://app.example.org/base",
		"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "HTTPS://app.example.org",
	} {
		mustLoad(t, withURL(ok))
	}
	for _, bad := range []string{
		"http://app.example.org", "http://10.0.0.1", "ftp://app.example.org", "app.example.org",
		"https://", "https:///path", "https://user:pw@app.example.org", "https://app.example.org/?x=1",
		"https://app.example.org/#frag", "http://localhost.evil.example",
	} {
		_, err := load(t, withURL(bad))
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), "frontend.public_base_url", bad)
	}
}

// ---- database URL ----

func TestUnparsableDatabaseURLGivesAFixedMessage(t *testing.T) {
	for _, url := range []string{
		"postgres://tunneld:pa#ss@127.0.0.1:5432/tunneld",
		"postgres://tunneld:se/cret@127.0.0.1:5432/tunneld",
		"postgres://tunneld:x?y@db.internal:5432/tunneld",
	} {
		body := strings.Replace(dbBase, "postgres://tunneld:secret@127.0.0.1:5432/tunneld?sslmode=disable", url, 1)
		_, err := load(t, body)
		require.Error(t, err, url)
		assert.Equal(t, errDatabaseURL.Error(), err.Error())
		for _, part := range []string{"tunneld", "pa#ss", "se/cret", "cret", "127.0.0.1", "db.internal", "5432", "x?y", "postgres"} {
			assert.NotContains(t, err.Error(), part, url)
		}
	}
}

// ---- metrics address ----

func TestMetricsAddress(t *testing.T) {
	cfg := mustLoad(t, staticBase)
	assert.Equal(t, "127.0.0.1:9090", cfg.Metrics.Address(), "absent: the loopback default")

	cfg = mustLoad(t, staticBase+"metrics:\n  addr: \"\"\n")
	assert.Equal(t, "", cfg.Metrics.Address(), "empty: disabled")

	for _, ok := range []string{"127.0.0.1:9100", "127.0.0.2:9100", "[::1]:9100", "localhost:9100", "LOCALHOST:9100"} {
		cfg = mustLoad(t, staticBase+"metrics:\n  addr: \""+ok+"\"\n")
		assert.Equal(t, ok, cfg.Metrics.Address())
		assert.Empty(t, cfg.Warnings)
	}
	for _, bad := range []string{"0.0.0.0:9090", ":9090", "[::]:9090", "10.0.0.5:9090", "example.com:9090", "localhost.example:9090"} {
		err := requireRefused(t, staticBase+"metrics:\n  addr: \""+bad+"\"\n", "metrics.addr")
		assert.Contains(t, err.Error(), "allow_non_loopback")
	}
	for _, bad := range []string{"127.0.0.1", "127.0.0.1:metrics", "127.0.0.1:70000"} {
		requireRefused(t, staticBase+"metrics:\n  addr: \""+bad+"\"\n", "metrics.addr")
	}

	cfg = mustLoad(t, staticBase+"metrics:\n  addr: \"0.0.0.0:9090\"\n  allow_non_loopback: true\n")
	assert.Equal(t, "0.0.0.0:9090", cfg.Metrics.Address())
	require.Len(t, cfg.Warnings, 1)
	assert.Contains(t, cfg.Warnings[0], "no authentication")
}

// ---- limits and timeouts ----

func TestLimitValuesThePackagesWouldNotHonourAreRefused(t *testing.T) {
	cases := map[string]struct{ section, want string }{
		// The head deadline also bounds the TLS handshake: it cannot be
		// switched off, nor can the idle timeout.
		"negative read header timeout":    {"http_server:\n  read_header_timeout: -1s\n", "http_server.read_header_timeout"},
		"negative idle timeout":           {"http_server:\n  idle_timeout: -1s\n", "http_server.idle_timeout"},
		"header bytes cannot be disabled": {"http_server:\n  max_header_bytes: -1\n", "http_server.max_header_bytes"},
		"header bytes below 4096":         {"http_server:\n  max_header_bytes: 4095\n", "http_server.max_header_bytes"},
		"pre-auth frame over 1 MiB":       {"tunnel:\n  max_preauth_frame_bytes: 1048577\n", "tunnel.max_preauth_frame_bytes"},
		"control frame over 1 MiB":        {"tunnel:\n  max_control_frame_bytes: 2097152\n", "tunnel.max_control_frame_bytes"},
		"revalidation below a second":     {"tunnel:\n  revalidate_interval: 999ms\n", "tunnel.revalidate_interval"},
		"negative udp idle timeout":       {"udp:\n  enabled: true\n  flow_idle_timeout: -1s\n", "udp.flow_idle_timeout"},
		"negative udp buffer":             {"udp:\n  enabled: true\n  flow_buffer_size: -1\n", "udp.flow_buffer_size"},
		"unverified ttl below one hour":   {"limits:\n  unverified_account_ttl: 59m59s\n", "limits.unverified_account_ttl"},
		"negative login window":           {"frontend:\n  login_failure_window: -1m\n", "frontend.login_failure_window"},
		"negative signup window":          {"frontend:\n  signup_window: -1m\n", "frontend.signup_window"},
		"negative reset window":           {"frontend:\n  reset_request_window: -1m\n", "frontend.reset_request_window"},
		"negative mail queue":             {"mail:\n  queue_size: -1\n", "mail.queue_size"},
		// As many hash slots per address as in total: one address could
		// take every slot, so the bound would protect nothing.
		"hash per ip at the default concurrency": {"limits:\n  hash_per_ip: 4\n", "limits.hash_per_ip"},
		"hash per ip above the concurrency":      {"limits:\n  hash_concurrency: 3\n  hash_per_ip: 5\n", "limits.hash_per_ip"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) { requireRefused(t, staticBase+tc.section, tc.want) })
	}
}

// Config errors name the keys and the rule, never the configured values.
func TestTheHashPerIPErrorQuotesNoValue(t *testing.T) {
	err := requireRefused(t, staticBase+"limits:\n  hash_concurrency: 37\n  hash_per_ip: 59\n", "limits.hash_per_ip")
	assert.Contains(t, err.Error(), "limits.hash_concurrency")
	assert.NotContains(t, err.Error(), "37")
	assert.NotContains(t, err.Error(), "59")
}

func TestLimitValuesAtTheBoundsAreAccepted(t *testing.T) {
	for _, section := range []string{
		"http_server:\n  max_header_bytes: 4096\n",
		"http_server:\n  max_header_bytes: 0\n",
		"tunnel:\n  max_preauth_frame_bytes: 1048576\n  max_control_frame_bytes: 1048576\n",
		"tunnel:\n  max_preauth_frame_bytes: -1\n  max_control_frame_bytes: -1\n",
		"tunnel:\n  revalidate_interval: 1s\n",
		"tunnel:\n  revalidate_interval: -1s\n",
		"limits:\n  unverified_account_ttl: 1h\n",
		"limits:\n  unverified_account_ttl: 168h\n",
		"limits:\n  unverified_account_ttl: -1h\n",
		"udp:\n  enabled: true\n  flow_idle_timeout: 0s\n  flow_buffer_size: 0\n",
		"frontend:\n  login_failure_window: 0s\n",
		"mail:\n  queue_size: 0\n",
		"limits:\n  hash_per_ip: 3\n",                         // below the default concurrency of 4
		"limits:\n  hash_per_ip: 0\n  hash_concurrency: 1\n",  // the default is not checked against a set concurrency
		"limits:\n  hash_per_ip: -1\n",                        // switched off
		"limits:\n  hash_per_ip: 9\n  hash_concurrency: -1\n", // no process-wide limit to compare with
		"limits:\n  hash_per_ip: 7\n  hash_concurrency: 8\n",
	} {
		mustLoad(t, staticBase+section)
	}
}

// Every key the example documents reaches its field: a typo in a yaml tag
// would make the decoder refuse the key here.
func TestEveryKeyReachesItsField(t *testing.T) {
	body := strings.Replace(dbBase, "auth:\n", "auth:\n  signup: closed\n", 1) + `metrics:
  addr: "127.0.0.1:9191"
  allow_non_loopback: false
http_server:
  read_header_timeout: 11s
  idle_timeout: 121s
  max_header_bytes: 65537
  max_conns: 30001
  max_conns_per_ip: 257
  frontend_read_timeout: 16s
  frontend_write_timeout: 31s
tunnel:
  handshake_timeout: 12s
  verify_timeout: 6s
  max_unauth_conns: 258
  max_unauth_conns_per_ip: 17
  max_preauth_frame_bytes: 4097
  max_control_frame_bytes: 16385
  accept_backlog: 33
  max_streams_per_session: 513
  max_streams_per_user: 514
  control_burst: 21
  control_refill_per_second: 6
  max_sessions_per_user: 11
  max_sessions: 5001
  revalidate_interval: 31s
edge:
  max_conns: 20001
  http:
    max_conns_per_tunnel: 514
    max_conns_per_ip: 65
    idle_timeout: 6m
  tcp:
    max_conns_per_tunnel: 515
    max_conns_per_ip: 66
    idle_timeout: 31m
  udp:
    max_flows_per_port: 1025
    max_flows_per_ip: 67
    max_flows: 16385
    reply_credit: 257
    max_reply_credit: 4097
    max_queued_bytes_per_flow: 262145
    max_queued_bytes_per_port: 2097153
    max_queued_bytes: 67108865
tcp:
  enabled: true
  port_range: {low: 10001, high: 19999}
udp:
  enabled: true
  port_range: {low: 30001, high: 39999}
  flow_idle_timeout: 32s
  flow_buffer_size: 65
limits:
  max_reservations_per_user: 12
  max_tokens_per_user: 26
  max_token_name_length: 65
  max_user_agent_bytes: 257
  min_password_length: 9
  min_admin_password_length: 13
  max_password_bytes: 1025
  hash_concurrency: 5
  hash_wait: 7s
  hash_per_ip: 3
  unverified_account_ttl: 169h
  pending_account_ttl: 721h
frontend:
  public_base_url: "https://app.example.org"
  login_failures_per_account: 11
  login_failures_per_ip: 31
  login_failure_window: 16m
  logins_per_account: 32
  signups_per_ip: 6
  signup_window: 61m
  reset_requests_per_ip: 4
  reset_requests_per_account: 5
  reset_request_window: 62m
  rate_limit_max_keys: 100001
  max_request_body_bytes: 65537
  user_actions_per_hour: 121
  unauthenticated_audit_rows_per_minute: 122
mail:
  from: "noreply@example.org"
  queue_size: 257
  smtp:
    host: "smtp.example.org"
    port: 587
    username: "user"
    password: "pass"
    auth_required: true
    allow_plaintext: true
    dial_timeout: 11s
    send_timeout: 31s
services:
  - name: myservice
    subdomain: myservice
    upstream: "http://127.0.0.1:8080"
    secret_file: "/etc/tunneld/services/myservice.secret"
    tcp_ports: [19000, 19001]
    max_request_body_bytes: 1048577
service_api:
  addr: "127.0.0.1:9101"
`
	cfg := mustLoad(t, body)

	assert.Equal(t, []Service{{
		Name: "myservice", Subdomain: "myservice", Upstream: "http://127.0.0.1:8080",
		SecretFile: "/etc/tunneld/services/myservice.secret", TCPPorts: []int{19000, 19001},
		MaxRequestBodyBytes: 1048577,
	}}, cfg.Services)
	assert.Equal(t, ServiceAPI{Addr: "127.0.0.1:9101"}, cfg.ServiceAPI)
	assert.Equal(t, "127.0.0.1:9191", cfg.Metrics.Address())
	assert.Equal(t, HTTPServer{
		ReadHeaderTimeout: 11 * time.Second, IdleTimeout: 121 * time.Second, MaxHeaderBytes: 65537,
		MaxConns: 30001, MaxConnsPerIP: 257,
		FrontendReadTimeout: 16 * time.Second, FrontendWriteTimeout: 31 * time.Second,
	}, cfg.HTTPServer)
	assert.Equal(t, Tunnel{
		HandshakeTimeout: 12 * time.Second, VerifyTimeout: 6 * time.Second,
		MaxUnauthConns: 258, MaxUnauthConnsPerIP: 17,
		MaxPreAuthFrameBytes: 4097, MaxControlFrameBytes: 16385, AcceptBacklog: 33,
		MaxStreamsPerSession: 513, MaxStreamsPerUser: 514, ControlBurst: 21, ControlRefillPerSecond: 6,
		MaxSessionsPerUser: 11, MaxSessions: 5001, RevalidateInterval: 31 * time.Second,
	}, cfg.Tunnel)
	assert.Equal(t, Edge{
		MaxConns: 20001,
		HTTP:     EdgeHTTP{MaxConnsPerTunnel: 514, MaxConnsPerIP: 65, IdleTimeout: 6 * time.Minute},
		TCP:      EdgeTCP{MaxConnsPerTunnel: 515, MaxConnsPerIP: 66, IdleTimeout: 31 * time.Minute},
		UDP: EdgeUDP{
			MaxFlowsPerPort: 1025, MaxFlowsPerIP: 67, MaxFlows: 16385, ReplyCredit: 257, MaxReplyCredit: 4097,
			MaxQueuedBytesPerFlow: 262145, MaxQueuedBytesPerPort: 2097153, MaxQueuedBytes: 67108865,
		},
	}, cfg.Edge)
	assert.Equal(t, TCP{Enabled: true, PortRange: PortRange{Low: 10001, High: 19999}}, cfg.TCP)
	assert.Equal(t, UDP{Enabled: true, PortRange: PortRange{Low: 30001, High: 39999},
		FlowIdleTimeout: 32 * time.Second, FlowBufferSize: 65}, cfg.UDP)
	assert.Equal(t, Limits{
		MaxReservationsPerUser: 12, MaxTokensPerUser: 26, MaxTokenNameLength: 65, MaxUserAgentBytes: 257,
		MinPasswordLength: 9, MinAdminPasswordLength: 13, MaxPasswordBytes: 1025,
		HashConcurrency: 5, HashWait: 7 * time.Second, HashPerIP: 3, UnverifiedAccountTTL: 169 * time.Hour,
		PendingAccountTTL: 721 * time.Hour,
	}, cfg.Limits)
	assert.Equal(t, "closed", cfg.Auth.Signup)
	assert.Equal(t, Frontend{
		PublicBaseURL:           "https://app.example.org",
		LoginFailuresPerAccount: 11, LoginFailuresPerIP: 31, LoginFailureWindow: 16 * time.Minute, LoginsPerAccount: 32,
		SignupsPerIP: 6, SignupWindow: 61 * time.Minute,
		ResetRequestsPerIP: 4, ResetRequestsPerAccount: 5, ResetRequestWindow: 62 * time.Minute,
		RateLimitMaxKeys: 100001, MaxRequestBodyBytes: 65537, UserActionsPerHour: 121,
		UnauthenticatedAuditRowsPerMinute: 122,
	}, cfg.Frontend)
	assert.Equal(t, Mail{
		From:      "noreply@example.org",
		QueueSize: 257,
		SMTP: MailSMTP{
			Host: "smtp.example.org", Port: 587, Username: "user", Password: "pass", AuthRequired: true,
			AllowPlaintext: true, DialTimeout: 11 * time.Second, SendTimeout: 31 * time.Second,
		},
	}, cfg.Mail)
}

// ---- defaults of the settings this package resolves itself ----

func TestHTTPServerDefaults(t *testing.T) {
	assert.Equal(t, HTTPServer{
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
		MaxConns: 1100, MaxConnsPerIP: 128,
		FrontendReadTimeout: 15 * time.Second, FrontendWriteTimeout: 30 * time.Second,
	}, HTTPServer{}.Resolved(), "zero selects the defaults")

	off := HTTPServer{
		ReadHeaderTimeout: -1, IdleTimeout: -1, MaxConns: -1, MaxConnsPerIP: -1,
		FrontendReadTimeout: -1, FrontendWriteTimeout: -1,
	}.Resolved()
	assert.Equal(t, HTTPServer{
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
	}, off, "negative disables, except the head timeout, the idle timeout and the header limit")

	set := HTTPServer{
		ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 4 * time.Second, MaxHeaderBytes: 8192,
		MaxConns: 5, MaxConnsPerIP: 6, FrontendReadTimeout: 7 * time.Second, FrontendWriteTimeout: 8 * time.Second,
	}
	assert.Equal(t, set, set.Resolved(), "positive values are kept")
}

func TestRevalidateIntervalDefault(t *testing.T) {
	assert.Equal(t, 30*time.Second, Tunnel{}.RevalidateEvery())
	assert.Equal(t, time.Duration(0), Tunnel{RevalidateInterval: -time.Second}.RevalidateEvery())
	assert.Equal(t, 5*time.Second, Tunnel{RevalidateInterval: 5 * time.Second}.RevalidateEvery())
}

// ---- start-up warnings ----

func TestSelfSignedWithDatabaseWarns(t *testing.T) {
	body := strings.Replace(dbBase, `  acme:
    email: "ops@example.org"
    dns_provider: "ionos"
    domains: ["example.org", "*.example.org"]
    cache_dir: "/var/lib/tunneld/certs"
`, "  self_signed_hosts: [example.org]\n", 1)
	cfg := mustLoad(t, body)
	require.Len(t, cfg.Warnings, 1)
	assert.Contains(t, cfg.Warnings[0], "self-signed")

	cfg = mustLoad(t, staticBase)
	assert.Empty(t, cfg.Warnings, "self-signed in static-token (development) mode is expected")
}

func TestAllowPlaintextWarns(t *testing.T) {
	cfg := mustLoad(t, dbBase+"mail:\n  from: noreply@example.org\n  smtp:\n    host: 127.0.0.1\n    port: 1025\n    allow_plaintext: true\n")
	require.Len(t, cfg.Warnings, 1)
	assert.Contains(t, cfg.Warnings[0], "allow_plaintext")
}

// ---- the shipped example ----

// exampleConfig returns the example with its CSRF placeholder replaced, the
// one value an operator must fill in before the file loads.
func exampleConfig(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "configs", "tunneld.example.yaml"))
	require.NoError(t, err)
	body := string(raw)
	require.Contains(t, body, csrfPlaceholder)
	return strings.Replace(body, csrfPlaceholder, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", 1)
}

const csrfPlaceholder = "REPLACE_WITH_OUTPUT_OF_TUNNELD_ADMIN_GEN_CSRF_KEY"

func TestExampleConfigLoads(t *testing.T) {
	cfg := mustLoad(t, exampleConfig(t))
	assert.NotEmpty(t, cfg.Database.URL)
}

// The installer writes the example with its own database URL into the
// database block; that file must load as well.
func TestExampleConfigWithTheInstallersDatabaseURLLoads(t *testing.T) {
	body := exampleConfig(t)
	lines := strings.Split(body, "\n")
	inDatabase, replaced := false, false
	for i, l := range lines {
		if l != "" && l[0] != ' ' && l[0] != '\t' && l[0] != '#' {
			inDatabase = strings.HasPrefix(l, "database:")
		}
		if inDatabase && !replaced && strings.HasPrefix(strings.TrimLeft(l, " \t"), "url:") {
			lines[i] = `  url: "postgres://tunneld:Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA@127.0.0.1:5432/tunneld?sslmode=disable"`
			replaced = true
		}
	}
	require.True(t, replaced, "the installer needs a url: line in the database block")
	mustLoad(t, strings.Join(lines, "\n"))
}

// knownKeys returns the yaml names of all fields of Config, at any depth.
func knownKeys() map[string]bool {
	keys := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || typ.PkgPath() != reflect.TypeOf(Config{}).PkgPath() {
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if name == "" || name == "-" {
				continue
			}
			keys[name] = true
			walk(f.Type)
		}
	}
	walk(reflect.TypeOf(Config{}))
	return keys
}

// commentedKeyRE matches a commented-out entry such as "#   max_conns: 512".
var commentedKeyRE = regexp.MustCompile(`^\s*#\s*([a-z_]+):(\s|$)`)

func commentedKey(line string) (string, bool) {
	m := commentedKeyRE.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Every key the example shows in a comment exists: uncommenting a documented
// entry must not be refused as an unknown key.
func TestEveryCommentedKeyInTheExampleExists(t *testing.T) {
	known := knownKeys()
	for i, line := range strings.Split(exampleConfig(t), "\n") {
		key, ok := commentedKey(line)
		if !ok {
			continue
		}
		assert.True(t, known[key], "line %d: commented key %q is not a config key", i+1, key)
	}
}

// ---- decode errors do not quote values (a misplaced secret) ----

func TestDecodeErrorsDoNotQuoteTheValue(t *testing.T) {
	body := staticBase + "tcp:\n  enabled: true\n  port_range: {low: s3cr3t-pass-word, high: 2000}\n"
	err := requireRefused(t, body, "line 11")
	assert.NotContains(t, err.Error(), "s3cr3t")
	assert.Contains(t, err.Error(), "int", "the expected type stays in the message")

	err = requireRefused(t, staticBase+"tunnel:\n  verify_timeout: hunter2\n", "line 10")
	assert.NotContains(t, err.Error(), "hunter2")

	// A value with a backtick of its own.
	err = requireRefused(t, staticBase+"tunnel:\n  verify_timeout: \"ab`cdef\"\n", "line 10")
	assert.NotContains(t, err.Error(), "ab`")
	assert.NotContains(t, err.Error(), "cdef")

	// Values that span a line: a block scalar and a quoted value with a
	// newline.
	err = requireRefused(t, staticBase+"tunnel:\n  verify_timeout: |\n    hunter2\n", "line 10")
	assert.NotContains(t, err.Error(), "hunter")
	err = requireRefused(t, staticBase+"tunnel:\n  verify_timeout: \"a\\nhunter2\"\n", "line 10")
	assert.NotContains(t, err.Error(), "hunt")
	assert.NotContains(t, err.Error(), "a\n")

	// An unquoted value that starts with "*" is an alias; the decoder names
	// it in its error.
	err = requireRefused(t, strings.Replace(staticBase, "[twbl_static_token_0001]", "[*Xy9-s3cret-token]", 1), "unknown anchor")
	assert.NotContains(t, err.Error(), "Xy9")
	assert.NotContains(t, err.Error(), "s3cret")

	// Two type errors and an unknown key: every one keeps its line, the
	// unknown key its name.
	err = requireRefused(t, staticBase+"tunnel:\n  verify_timeout: abc\n  handshake_timeout: def\n  max_sesions: 3\n", "line 10")
	assert.Contains(t, err.Error(), "line 11")
	assert.Contains(t, err.Error(), "line 12")
	assert.Contains(t, err.Error(), "max_sesions")
	assert.NotContains(t, err.Error(), "abc")
	assert.NotContains(t, err.Error(), "def")
}

// ---- metrics.addr: absent and null select the default, "" disables ----

func TestMetricsAddressNullIsTheDefault(t *testing.T) {
	for _, section := range []string{"metrics:\n  addr:\n", "metrics:\n  addr: ~\n", "metrics:\n  addr: null\n", "metrics: {}\n"} {
		cfg := mustLoad(t, staticBase+section)
		assert.Equal(t, DefaultMetricsAddr, cfg.Metrics.Address(), "%q", section)
	}
	for _, section := range []string{"metrics:\n  addr: \"\"\n", "metrics:\n  addr: ''\n"} {
		cfg := mustLoad(t, staticBase+section)
		assert.Empty(t, cfg.Metrics.Address(), "%q", section)
	}
}

// ---- domain and ACME names ----

func TestDomainMustBeAHostName(t *testing.T) {
	for _, bad := range []string{"tunnel_localhost", "tunnel.localhost:443", "1.2.3.4", "-bad.example", "bad-.example", "a..b", "tunnel localhost", "*.tunnel.localhost"} {
		body := strings.Replace(staticBase, "domain: tunnel.localhost", "domain: \""+bad+"\"", 1)
		requireRefused(t, body, "domain")
	}
	for _, ok := range []string{"localhost", "Tunnel.Localhost", "tunnel.localhost."} {
		mustLoad(t, strings.Replace(staticBase, "domain: tunnel.localhost", "domain: \""+ok+"\"", 1))
	}
}

func TestACMEDomainsAreHostNamesAndCoverTheServer(t *testing.T) {
	withDomains := func(domains string) string {
		return strings.Replace(dbBase, `["example.org", "*.example.org"]`, domains, 1)
	}
	for _, bad := range []string{
		`["example.org", "*example.org"]`, `["example.org:443", "*.example.org"]`, `["example.org", "*.*.example.org"]`,
		`["example.org", "exa mple.org", "*.example.org"]`, `["example.org", "*.example.org", ""]`, `["example.org", "*.example.org", "1.2.3.4"]`,
	} {
		requireRefused(t, withDomains(bad), "tls.acme.domains")
	}
	// The certificate must be valid for the apex and for the web UI.
	err := requireRefused(t, withDomains(`["example.org"]`), "app.example.org")
	assert.Contains(t, err.Error(), "tls.acme.domains")
	err = requireRefused(t, withDomains(`["*.example.org"]`), "example.org")
	assert.Contains(t, err.Error(), "tls.acme.domains")
	requireRefused(t, withDomains(`["example.org", "*.other.example.net"]`), "app.example.org")

	for _, ok := range []string{`["example.org", "app.example.org"]`, `["EXAMPLE.org", "*.Example.ORG"]`, `["example.org.", "*.example.org"]`} {
		mustLoad(t, withDomains(ok))
	}
}

func TestACMECacheDirMustBeAbsolute(t *testing.T) {
	for _, bad := range []string{"certs", "./certs", "var/lib/tunneld/certs"} {
		requireRefused(t, strings.Replace(dbBase, `"/var/lib/tunneld/certs"`, `"`+bad+`"`, 1), "tls.acme.cache_dir")
	}
}
