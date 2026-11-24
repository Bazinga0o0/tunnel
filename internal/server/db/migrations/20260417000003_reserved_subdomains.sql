-- +goose Up
CREATE TABLE reserved_subdomains (
    subdomain   TEXT PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX reserved_subdomains_user_id_idx ON reserved_subdomains (user_id);

-- +goose Down
DROP TABLE reserved_subdomains;
