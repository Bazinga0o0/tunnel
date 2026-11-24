-- +goose Up
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id                  BIGSERIAL PRIMARY KEY,
    email               CITEXT UNIQUE NOT NULL,
    password_hash       TEXT NOT NULL,
    email_verified_at   TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at         TIMESTAMPTZ
);

-- +goose Down
DROP TABLE users;
DROP EXTENSION citext;
