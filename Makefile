.PHONY: build build-server build-client test test-race test-db lint fmt clean tools db-up db-down dev-up dev-down db-migrate sqlc-gen templ-gen tailwind-gen web-gen

GO ?= go
BIN_DIR = bin
TAILWIND ?= tools/tailwindcss$(if $(filter Windows_NT,$(OS)),.exe,)

# Pinned tool versions. sqlc and templ must match the versions CI uses for
# its drift checks (.github/workflows/ci.yml); goose must match the goose
# library version in go.mod.
SQLC_VERSION  ?= v1.30.0
TEMPL_VERSION ?= v0.3.1001
GOOSE_VERSION ?= v3.27.0

# Development database password. docker-compose.yml has no default for
# POSTGRES_PASSWORD, so every compose call below passes this one explicitly.
# Never use it on a server: scripts/install-server.sh generates a random one.
DEV_DB_PASSWORD ?= tunneld_dev_password
COMPOSE = POSTGRES_PASSWORD="$(DEV_DB_PASSWORD)" docker compose

# Local dev DB URL (matches DEV_DB_PASSWORD and docker-compose.yml).
DB_URL ?= postgres://tunneld:$(DEV_DB_PASSWORD)@127.0.0.1:5432/tunneld?sslmode=disable

build: web-gen build-server build-client

build-server:
	$(GO) build -o $(BIN_DIR)/tunneld ./cmd/tunneld

build-client:
	$(GO) build -o $(BIN_DIR)/tunnel ./cmd/tunnel

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

# Run full suite incl. DB-dependent integration tests (requires docker postgres up).
# The database tests of all packages take turns on one advisory lock, so the
# packages run one after another (-p 1), as in CI.
test-db:
	TUNNELD_TEST_DATABASE_URL="$(DB_URL)" $(GO) test -count=1 -p 1 -timeout 600s ./...

lint:
	$(GO) vet ./...
	@echo "For full lint, install golangci-lint and run: golangci-lint run"

fmt:
	$(GO) fmt ./...

clean:
	rm -rf $(BIN_DIR)

# Install the code generators at the pinned versions (into GOBIN).
tools:
	$(GO) install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)
	$(GO) install github.com/a-h/templ/cmd/templ@$(TEMPL_VERSION)

# --- Database ---

db-up:
	$(COMPOSE) up -d postgres

db-down:
	$(COMPOSE) down

# Dev stack: postgres + mailhog (SMTP catcher at http://127.0.0.1:8025).
dev-up:
	$(COMPOSE) -f docker-compose.yml -f docker-compose.dev.yml up -d

dev-down:
	$(COMPOSE) -f docker-compose.yml -f docker-compose.dev.yml down

db-migrate:
	TUNNELD_TEST_DATABASE_URL="$(DB_URL)" \
	$(GO) run github.com/pressly/goose/v3/cmd/goose@$(GOOSE_VERSION) \
		-dir internal/server/db/migrations \
		postgres "$(DB_URL)" up

sqlc-gen:
	sqlc generate

# --- Frontend (P3) ---

templ-gen:
	templ generate

tailwind-gen:
	$(TAILWIND) -i web/src/app.css -o internal/server/frontend/web/static/app.css --minify

web-gen: templ-gen tailwind-gen
