# Development

How to build and run tunnel locally is in [Getting started](getting-started.md).

## Running tests with the DB

```bash
make db-up
make test-db   # sets TUNNELD_TEST_DATABASE_URL, runs ./... with -p 1
```

DB-dependent tests skip when `TUNNELD_TEST_DATABASE_URL` is unset — plain
`go test ./...` remains green even without Docker. The tests empty the tables
of the database they are given (`make test-db` uses the local dev database),
and the database tests of all packages take turns on it through an advisory
lock. `make test-db` and CI therefore run the packages one after another
(`go test -count=1 -p 1 -timeout 600s ./...`).

## Regenerating templates + CSS

```bash
make templ-gen        # templ generate
make tailwind-gen     # CSS rebuild
make web-gen          # both, in order
```

Commit the generated `*_templ.go` and `app.css` — production builds don't need
the `templ` or `tailwindcss` binaries.

The pinned versions of `tailwindcss`, `templ` and `sqlc` and where to get
them are listed in [tools/README.md](../tools/README.md).

## CI

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests:
`go vet`, the full test suite against a PostgreSQL service
(`go test -count=1 -p 1 -timeout 600s ./...`), drift checks that
regenerate the `sqlc` and `templ` output and compare it with the committed
files, and `govulncheck`. It checks that Go is the toolchain named in
`go.mod`. `.github/workflows/release.yml` builds the release archives
with GoReleaser when a version tag is pushed.

## Layout

```
cmd/
├── tunneld/       # server binary (serve, admin CLI, wiring)
└── tunnel/        # client binary
internal/
├── protocol/         # shared wire protocol (messages, framing, yamux, streams)
├── server/
│   ├── acceptor/     # TLS listener + auth handshake + session limits
│   ├── acme/         # Let's Encrypt certificates (DNS-01), cache, renewal
│   ├── audit/        # append-only audit log
│   ├── auth/         # static + DB token verifiers, argon2id password hashing
│   ├── config/       # YAML config loader and validation
│   ├── db/           # pgxpool + goose migrations + sqlc-generated queries
│   │   ├── dbtest/       # integration-test helper
│   │   ├── migrations/   # goose SQL files (embedded)
│   │   ├── queries/      # sqlc input SQL
│   │   └── sqlcgen/      # sqlc output (committed)
│   ├── edgeguard/    # connection limits, idle timeouts, backoff for the edges
│   ├── edgehttp/     # public HTTPS edge (http.Handler with Hijacker)
│   ├── edgetcp/      # TCP edge and port pool
│   ├── edgeudp/      # UDP edge, flows and port pool
│   ├── frontend/     # HTMX web UI and admin panel (chi + templ + Tailwind + HTMX)
│   │   ├── templates/    # templ components (generated .go committed)
│   │   └── web/static/   # app.css (Tailwind) + htmx/alpine (embedded)
│   ├── mail/         # SMTP mailer and mail templates
│   ├── metrics/      # Prometheus metrics
│   ├── passwordreset/ # password reset links
│   ├── reaper/       # hourly clean-up of expired rows
│   ├── registry/     # in-memory registry of tunnel sessions
│   ├── reservations/ # DB-backed subdomain and port ownership, name rules
│   ├── services/     # registered services: token-checking proxy, service API
│   ├── sessions/     # browser session service
│   ├── tlsutil/      # dev-only self-signed cert generator
│   ├── tokens/       # API tokens (issue/verify/revoke)
│   ├── users/        # user accounts service
│   └── verifications/ # email verification links
├── client/
│   ├── config/    # client YAML config
│   ├── connector/ # forward incoming streams to local port
│   └── dialer/    # TLS+yamux connect + handshake
└── testports/     # free loopback port ranges for tests
tests/
├── e2e/             # smoke + full round-trip tests
└── integration/     # DB auth + reservations + frontend full-flow tests
configs/             # example configs
web/src/             # Tailwind source (app.css)
tools/               # dev-only binaries (tailwindcss, gitignored)
docker-compose.yml   # Postgres (requires POSTGRES_PASSWORD)
```
