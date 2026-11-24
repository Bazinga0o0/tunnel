-- +goose Up
CREATE TABLE email_verifications (
    token_hash  BYTEA PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX email_verifications_user_id_idx ON email_verifications (user_id);
CREATE INDEX email_verifications_expires_at_idx ON email_verifications (expires_at);

-- +goose Down
DROP TABLE email_verifications;
