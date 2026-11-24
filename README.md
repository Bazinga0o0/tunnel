# tunnel

Self-hosted tunneling service for HTTP, TCP and UDP.

## What tunnel does

tunnel makes a service on your own machine reachable from the internet
through a server you run yourself. The client `tunnel` opens a TLS
connection to the server `tunneld`, which serves the local port on
`https://<name>.<domain>` or on a public TCP or UDP port. It is meant for
people and small teams who want their own tunnel endpoint, with accounts, a
web UI and an admin panel, instead of a hosted tunnel service.

## Features

**Tunnels**

- HTTPS tunnels on `<name>.<domain>`, with a requested or a random subdomain;
  WebSocket upgrades pass through.
- TCP and UDP tunnels on public ports from configurable port ranges, picked
  by the server or reserved for an account.
- `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` set by the
  server; `X-Real-IP`, `Forwarded` and similar headers from visitors removed.
- Limits per tunnel, per visitor address, per account and in total, idle
  timeouts, and a start-up check of the limits against the memory limit.
- A single client binary for Linux, macOS and Windows that checks the server
  certificate (with `ca_file` for a private CA).

**Accounts and access**

- Two modes: static tokens without a database, or PostgreSQL with accounts.
- Self-service web UI on `app.<domain>`: sign-up, email verification, login,
  password reset, dashboard, API tokens, subdomain reservations, live tunnels
  page and settings.
- Sign-up modes `open`, `approval` (an admin approves new accounts) and
  `closed`.
- Admin panel: users (verify, disable, promote, set a password, revoke
  tokens), live connections with a kill button, reservations of subdomains,
  TCP and UDP ports, and approvals.
- Admin CLI (`tunneld admin`) for accounts, tokens, reservations and
  approvals.
- argon2id passwords, API tokens and sessions stored as hashes, CSRF tokens,
  a CSP with a per-request nonce, and rate limits for logins, sign-ups,
  password resets and user actions.
- An audit log of every change made in the web UI, the admin panel or the
  CLI.
- Mail over SMTP with TLS: verification, password reset and approval
  notices, sent from a background queue.

**Services**

- Registered services: programs on the server machine served on
  `<subdomain>.<domain>` behind the API token check, with the account passed
  on in headers, and a loopback service API through which a service decides
  which account holds its TCP ports.

**Operations**

- TLS from Let's Encrypt wildcard certificates via DNS-01 (IONOS) with
  automatic renewal, from certificate files, or self-signed for development.
- A strictly validated YAML config; warnings at start-up for settings that
  weaken a protection.
- Prometheus metrics on a loopback address.
- An hourly reaper for expired sessions, verification links and reset
  links, optionally also for unused unverified accounts.
- Release archives built with GoReleaser, an installer for Ubuntu hosts, a
  sandboxed systemd unit, a deploy script for updates and a nightly
  `pg_dump` backup.

## Quick start

A first tunnel on one machine, with static tokens and no database. You need
Go 1.27 (`go.mod` names the toolchain; Go 1.21 or newer downloads it).

```bash
go build -o bin/tunneld ./cmd/tunneld
go build -o bin/tunnel ./cmd/tunnel
cp configs/tunneld.example.yaml configs/tunneld.yaml
cp configs/tunnel.example.yaml configs/tunnel.yaml
```

Edit the two copies:

- `configs/tunneld.yaml`: delete the `database:` block, set
  `auth.tokens: [twbl_dev_token_0123456789]`, and use ports above 1024:
  `listen.tunnel_addr: ":17443"`, `listen.http_addr: ":18443"`.
- `configs/tunnel.yaml`: `server: tunnel.localhost:17443`,
  `token: twbl_dev_token_0123456789` and, for the self-signed certificate of
  the dev server only, `insecure_skip_verify: true`.

```bash
./bin/tunneld serve --config configs/tunneld.yaml

# In a second terminal: a backend and the client.
python3 -m http.server 8080
./bin/tunnel http 8080 --config configs/tunnel.yaml
#   tunnel up: https://a3kp9x.tunnel.localhost → http://127.0.0.1:8080

# In a third terminal (use the name the client printed):
curl --resolve a3kp9x.tunnel.localhost:18443:127.0.0.1 \
     -k https://a3kp9x.tunnel.localhost:18443/
```

The same with PostgreSQL, accounts and the web UI:
[Getting started](docs/getting-started.md).

## Examples

### Client

```bash
tunnel config init                    # writes a config template; set server and token
tunnel http 3000 --subdomain myapp    # https://myapp.<domain> → localhost:3000
tunnel tcp 22                         # a public TCP port that the server picks
tunnel udp 7000 --port 35000          # public UDP port 35000, reserved for the account
```

See [The tunnel client](docs/client.md).

### Server

A server with accounts, a Let's Encrypt wildcard certificate and TCP
tunnels (`/etc/tunneld/config.yaml`):

```yaml
domain: example.org
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  acme:
    email: "ops@example.org"
    dns_provider: "ionos"            # IONOS_API_KEY in /etc/tunneld/env
    domains: ["example.org", "*.example.org"]
    cache_dir: "/var/lib/tunneld/certs"
auth:
  csrf_key: "<output of tunneld admin gen-csrf-key>"
  signup: approval
database:
  url: "postgres://tunneld:<password>@127.0.0.1:5432/tunneld?sslmode=disable"
frontend:
  public_base_url: "https://app.example.org"
tcp:
  enabled: true
  port_range: {low: 10000, high: 20000}
```

Install it from an unpacked release archive and create the first admin:

```bash
sudo ./scripts/install-server.sh
sudo /opt/tunneld/tunneld admin gen-csrf-key
sudoedit /etc/tunneld/config.yaml
sudo systemctl start tunneld
sudo /opt/tunneld/tunneld admin create-admin --config /etc/tunneld/config.yaml \
    --email you@example.org --allow-unverified
```

See [Deployment](docs/deployment.md) and
[Server configuration](docs/server-config.md).

## Status

HTTP, TCP and UDP tunnels, accounts with the web UI and the admin panel,
mail, ACME certificates, registered services and the deployment files are
complete. The server runs in production on a Linux host under the shipped
systemd unit. Not yet exercised end to end: the installer on a fresh host
and the GoReleaser release pipeline with the GitHub workflows. Open items
are listed under [Roadmap](docs/security-model.md#roadmap).

## Documentation

| Page | Contents |
|---|---|
| [Getting started](docs/getting-started.md) | Build, a first tunnel, the dev database and the web UI on one machine. |
| [The tunnel client](docs/client.md) | Commands, config file, certificate checks. |
| [TCP and UDP tunnels](docs/tcp-udp.md) | Port ranges, reserved ports, UDP flows. |
| [Server configuration](docs/server-config.md) | Every key of `tunneld`, the values that stop the start, ACME. |
| [Accounts and web UI](docs/accounts-and-web-ui.md) | Sign-up modes and approval, the admin panel, mail, the reaper. |
| [Admin CLI](docs/admin-cli.md) | `tunneld admin` commands. |
| [Services](docs/services.md) | Registered services, the service API and its secrets. |
| [Deployment](docs/deployment.md) | Installer, systemd unit, memory sizing, metrics, backups, updates, troubleshooting. |
| [Security](docs/security-model.md) | What the server protects and how, known limits, roadmap. |
| [Development](docs/development.md) | Tests with the database, generated code, CI, source layout. |

## License

Elastic License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
