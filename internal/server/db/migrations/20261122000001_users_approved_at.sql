-- +goose Up
-- approved_at is set when an admin approves the account. It is checked only
-- while auth.signup is "approval" or "closed"; NULL then means: waits for
-- approval.
ALTER TABLE users ADD COLUMN approved_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE users DROP COLUMN approved_at;
