# Server configuration

`configs/tunneld.example.yaml` documents every key of the server with its
default; copy it and change what you need. The rules:

- The file is decoded strictly: an unknown or misplaced key stops the server
  (and every `tunneld admin` command) with the name of the key. Durations
  need a unit (`10s`, `5m`, `168h`).
- For the limits and timeouts, a missing key or zero (`0`; for a duration
  `0s`, since a bare `0` has no unit) selects the default; a negative value
  switches a limit off where the example says so.
- At start-up the server logs warnings for a config file that other users
  can read, a self-signed certificate together with a database,
  `mail.smtp.allow_plaintext`, a metrics address that other hosts can
  reach, and every protection that a negative value switches off (the keys
  of `tunnel`, `edge`, `http_server`, `frontend` and `limits`, and
  `mail.smtp.dial_timeout`), one line per key (`<key> is negative, which
  switches off …`). The `tunneld admin` commands print the same warnings on
  stderr.
- `tunneld serve` also warns when the worst case of the configured limits is
  larger than the Go memory limit in force (`GOMEMLIMIT`, set by the systemd
  unit), or when a limit that bounds memory is switched off; the line names
  each term with its count and cost, largest first. See
  [Memory sizing](deployment.md#memory-sizing).
- Keys that size an allocation have upper bounds: `tunnel.accept_backlog` and
  `udp.flow_buffer_size` at most 256, `http_server.max_header_bytes` at most
  1048576, `mail.queue_size` at most 4096.

## Key groups

| Key | What it configures |
|---|---|
| `domain`, `listen` | The tunnel domain (`<name>.<domain>`; the web UI is on `app.<domain>`), the tunnel listener and the public HTTPS listener (`host:port` with a numeric port). |
| `tls` | Exactly one certificate source: `self_signed_hosts` (dev), `cert_file` + `key_file`, or `acme`. The server logs which one is active. |
| `auth`, `database` | Static `auth.tokens` (at least 16 characters each) or `database.url` with `auth.csrf_key`, and `auth.signup` (`open`, `approval` or `closed`, see [Web UI and accounts](accounts-and-web-ui.md#sign-up-modes-and-approval)). |
| `mail` | Sender, background queue and SMTP (`mail.smtp.*`, see [Email](accounts-and-web-ui.md#email-transactional)). |
| `frontend` | `public_base_url` for links in mails (`https`; `http` only for localhost), and the web UI's rate limits (failed and successful logins, sign-ups, reset requests, user actions), the size of their tables, the request size and the budget of audit rows from requests without a login. |
| `tcp`, `udp` | TCP and UDP tunnels: on/off, port ranges, UDP flow idle timeout and buffer. |
| `metrics` | The Prometheus endpoint: `addr` (default `127.0.0.1:9090`; `""` switches it off), `allow_non_loopback`. |
| `http_server` | The public HTTPS listener: header and idle timeouts, header size, connection limits, read and write deadlines of web UI requests. |
| `tunnel` | The tunnel listener and the client sessions: handshake and token check timeouts, unauthenticated connections, frame sizes, streams per session and per user, control message rate, sessions per user and in total, `revalidate_interval`. |
| `edge` | Visitor connections to the tunnels: limits per tunnel, per visitor address and in total, idle timeouts, UDP flows, reply credit and queue budgets. |
| `limits` | Accounts: reservations and tokens per user, password lengths, concurrent password hashes and how many of them one client address may have in flight, the optional deletion of unused unverified accounts, and the deletion of accounts that wait too long for approval (`pending_account_ttl`). |
| `services`, `service_api` | Registered services on `<subdomain>.<domain>` behind the token check, and the loopback API through which they set the holders of their TCP ports. See [Services](services.md). |

## Keys that need more words

Some keys need more words than the example has room for (the rule above
applies to all of them: missing or zero selects the default, negative
switches the limit off):

| Key | Default | What it bounds |
|---|---|---|
| `tunnel.max_streams_per_user` | 256 | The streams of all tunnel sessions of one account together (HTTP connections, TCP connections and UDP flows). Database mode only; with static tokens a session has no account, and `tunnel.max_streams_per_session` (512) is the bound. Over it a visitor is refused as at the per-session limit. |
| `limits.hash_per_ip` | half of `limits.hash_concurrency`, at least 1 and at most 2 (2 at the default of 4; 2 when `hash_concurrency` is switched off) | Web requests with password-hash work that one client address (IPv6: one /64) has in flight. A set positive value must be lower than the effective `hash_concurrency`, or the server does not start. |
| `frontend.logins_per_account` | 30 in `frontend.login_failure_window` (15 minutes) | Successful logins of one address: only a login whose password matched and whose session was stored counts, wrong passwords never do. |
| `frontend.user_actions_per_hour` | 120 per signed-in user | `POST /tokens`, `/tokens/{id}/revoke`, `/reservations`, `/reservations/{subdomain}/release` and `/settings/password` together, whatever their outcome. |
| `frontend.unauthenticated_audit_rows_per_minute` | 120 | Audit rows of failed logins and password-reset requests, together per minute; the rest is counted in one summary row a minute. |

## Values that stop the start

These values stop the server at start-up (and every `tunneld admin`
command, which validates the same file), with a message that names the key:

- a static token in `auth.tokens` that is empty or shorter than 16
  characters;
- `frontend.public_base_url` with `http` for a host other than localhost or
  a loopback address, or with user info, a query or a fragment;
- `metrics.addr` on an address that is not loopback (`0.0.0.0:9090`,
  `:9090`) without `metrics.allow_non_loopback: true`, or one that cannot be
  bound;
- a listen address with a named port (`:https`);
- `tcp.port_range` or `udp.port_range` below 1024, or containing the tunnel
  port, the HTTPS port or the metrics port (default 9090);
- an `acme:` block without `email`, with a provider other than `ionos`, with
  a relative `cache_dir`, or with `domains` that do not cover `domain` and
  `app.<domain>`;
- `cert_file` without `key_file`, or the other way round;
- a `domain` that is not a host name;
- a `database.url` that cannot be parsed (the message does not quote the
  URL; percent-encode `#`, `/`, `?` and `@` in the password);
- the out-of-range values the example names (for example
  `tunnel.revalidate_interval` between 0 and 1 s,
  `http_server.max_header_bytes` below 4096,
  `limits.unverified_account_ttl` between 0 and 1 h, a negative
  `http_server.read_header_timeout`);
- `tunnel.accept_backlog` or `udp.flow_buffer_size` above 256,
  `http_server.max_header_bytes` above 1048576, `mail.queue_size` above
  4096;
- with `mail.smtp.host` set: a `mail.smtp.port` outside 1 to 65535, no
  `mail.from`, or a `mail.from` that is not a plain address (for example
  `Tunnel <noreply@example.com>`);
- a negative `mail.smtp.send_timeout`;
- a `limits.hash_per_ip` that is not lower than `limits.hash_concurrency`.

## ACME (Let's Encrypt wildcard via DNS-01)

For a real public deployment, obtain a wildcard cert via DNS-01. Currently
supports the IONOS DNS provider. Set the IONOS API key in the environment:

```bash
export IONOS_API_KEY="public_prefix.private_secret"
```

And in config:

```yaml
tls:
  acme:
    email: "you@example.org"
    dns_provider: "ionos"
    domains:              # must cover domain and app.<domain>
      - "example.org"
      - "*.example.org"
    cache_dir: "/var/lib/tunneld/certs"   # absolute and writable
    staging: false   # set true while testing to avoid rate-limits
```

Certificate, key and ACME account are cached in `<cache_dir>/production`, or
in `<cache_dir>/staging` with `staging: true`. A cached certificate is used
only if it was issued by the configured directory, is valid now and covers
every configured domain; with such a certificate the server starts without
contacting Let's Encrypt. Renewal is checked at start-up and every 12 hours
(hourly in the last three days) and happens 30 days before expiry; a failed
renewal keeps the current certificate. `tunneld_cert_not_after_unix` reports
the expiry for alerting.

When no usable certificate exists and Let's Encrypt or IONOS cannot be
reached, the server does not exit. It waits and tries again after 1 minute,
then 2, 4, … up to 1 hour between attempts, without listening on any port
meanwhile. See [Troubleshooting](deployment.md#troubleshooting).

## More keys by topic

- TCP and UDP port ranges: [TCP and UDP tunnels](tcp-udp.md).
- `mail.*`: [Email](accounts-and-web-ui.md#email-transactional).
- `auth.signup`: [Sign-up modes and approval](accounts-and-web-ui.md#sign-up-modes-and-approval).
- `services` and `service_api`: [Services](services.md).
- Memory limits and the defaults of the limits: [Memory sizing](deployment.md#memory-sizing).
