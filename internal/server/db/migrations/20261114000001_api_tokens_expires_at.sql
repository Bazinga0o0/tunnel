-- +goose Up
-- Optional expiry for API tokens. NULL means the token does not expire.
ALTER TABLE api_tokens ADD COLUMN expires_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE api_tokens DROP COLUMN expires_at;
