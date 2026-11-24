# Getting started

Build both binaries from source and run a first tunnel on one machine:
first with static tokens and no database, then with PostgreSQL and the web
UI. To run the server on a host of its own, see [Deployment](deployment.md).

## Build and first run

Requirements: Go 1.27 (`go.mod` names the toolchain `go1.27.4`; Go 1.21 or
newer downloads it by itself), `make` (optional — you can run `go` commands
directly instead).

```bash
# Build both binaries
go build -o bin/tunneld ./cmd/tunneld
go build -o bin/tunnel ./cmd/tunnel

# Run tests
go test ./...
go test -race ./...   # needs a C toolchain (gcc) for -race

# Prepare dev configs
cp configs/tunneld.example.yaml configs/tunneld.yaml
cp configs/tunnel.example.yaml configs/tunnel.yaml
```

The server runs either with static tokens (no database) or with PostgreSQL
(accounts, web UI); exactly one of `auth.tokens` and `database.url` may be
set. For a first run without a database:

```bash
# configs/tunneld.yaml: delete the database: block and set a token of at
# least 16 characters; put the same value into configs/tunnel.yaml:
#   configs/tunneld.yaml → auth:
#                            tokens: [twbl_dev_token_0123456789]
#   configs/tunnel.yaml  → token: twbl_dev_token_0123456789
#
# The dev server presents a self-signed certificate that is generated anew on
# every start. In your copy configs/tunnel.yaml set
#   insecure_skip_verify: true
# The client then prints a warning on every start; never do this against a
# real server (use ca_file for a server with a certificate from a private CA).

# Start the server. Default example binds :7443 / :443 — use high ports
# (see below) unless you run with sudo or CAP_NET_BIND_SERVICE.
./bin/tunneld serve --config configs/tunneld.yaml

# In another terminal, start a backend and the client:
python3 -m http.server 8080
./bin/tunnel http 8080 --config configs/tunnel.yaml
```

The client prints something like:

    tunnel up: https://a3kp9x.tunnel.localhost → http://127.0.0.1:8080
      (Ctrl+C to stop)

`tunnel version` and `tunneld version` print the build version, commit and
date.

### Unprivileged dev ports

Edit `configs/tunneld.yaml` so both addresses use ports ≥1024 (and point
`server:` in `configs/tunnel.yaml` at the new tunnel port):

```yaml
listen:
  tunnel_addr: ":17443"
  http_addr: ":18443"
```

Listen addresses must have a numeric port; `:https` is refused.

## Testing the tunnel

On macOS and modern Linux, `*.localhost` resolves to `127.0.0.1` automatically.
Hit the edge explicitly (replace subdomain + port):

```bash
curl --resolve a3kp9x.tunnel.localhost:18443:127.0.0.1 \
     -k https://a3kp9x.tunnel.localhost:18443/
```

`-k` skips cert validation (dev uses a self-signed cert). `--resolve` forces
the DNS lookup for that specific host:port to the tunnel server. A request
for an IP address instead of a host name gets `400`.

## First run with a database

```bash
# Start Postgres in Docker (loopback-only at 127.0.0.1:5432). docker compose
# refuses to start it without POSTGRES_PASSWORD; make passes the dev password.
make db-up         # or: POSTGRES_PASSWORD=tunneld_dev_password docker compose up -d postgres

# configs/tunneld.yaml: keep database.url of the example (it points at this
# database) and leave auth.tokens out. auth.csrf_key is required with a
# database; generate one and paste it in:
./bin/tunneld admin gen-csrf-key
#
# On first server start, migrations run automatically. You can also migrate
# manually with `make db-migrate`.

# Bootstrap a user + issue yourself a tunnel-client token. create-user asks
# for the password twice (at least 12 characters for a password set here).
./bin/tunneld admin create-user --config configs/tunneld.yaml --email you@example.com
./bin/tunneld admin issue-token --config configs/tunneld.yaml --email you@example.com --name laptop
# Copy the printed `token` field into configs/tunnel.yaml as `token:`.

# Optional: reserve a subdomain for yourself so nobody else can claim it.
./bin/tunneld admin reserve-subdomain --config configs/tunneld.yaml --email you@example.com --subdomain myapp
```

All `tunneld admin` commands are described in [Admin CLI](admin-cli.md).

## Web UI

### First-time setup

```bash
# 1. Generate a CSRF signing key (32 random bytes, base64-encoded).
./bin/tunneld admin gen-csrf-key
# → paste the output into configs/tunneld.yaml as:
#   auth:
#     csrf_key: "<paste here>"

# 2. Build the frontend assets (templ + Tailwind). One-time install of the
#    tools — see tools/README.md.
templ generate
tools/tailwindcss -i web/src/app.css -o internal/server/frontend/web/static/app.css --minify
# or: make web-gen

# 3. Start the server. The log should have a line "db-backed auth enabled"
#    with frontend=enabled.
make db-up
./bin/tunneld serve --config configs/tunneld.yaml
```

### Local browser access

Use a dev port ≥1024 in the config and visit:

```
https://app.tunnel.localhost:18443/signup
```

(Most OSes resolve `*.localhost` to 127.0.0.1. Accept the self-signed cert
warning — dev certs are regenerated every server start.)

Signing up does not log you in: the page sends you to `/login`. With mail
configured, the verification link opens a confirmation page, and the button
on it verifies the address; creating tokens and reservations needs a verified
address. Without mail, mark the address verified with
`tunneld admin mark-verified`. Create a token on `/tokens`, paste it into
`configs/tunnel.yaml`, then run `./bin/tunnel http <port>` — the active tunnel
appears live on `/tunnels` (HTMX polls every 3 seconds).

What the web UI and the admin panel offer, and how sign-up works, is in
[Accounts and web UI](accounts-and-web-ui.md).
