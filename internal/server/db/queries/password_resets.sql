-- The expiry is counted from the database clock, the clock every query
-- compares it with.
-- name: CreatePasswordReset :exec
INSERT INTO password_resets (token_hash, user_id, expires_at)
VALUES (
    sqlc.arg(token_hash),
    sqlc.arg(user_id),
    now() + sqlc.arg(ttl_seconds)::double precision * interval '1 second'
);

-- GetPasswordResetByHash returns a reset token only while it can be used:
-- not expired and owned by an account that is not disabled.
-- name: GetPasswordResetByHash :one
SELECT pr.token_hash, pr.user_id, pr.expires_at
FROM password_resets pr
JOIN users u ON u.id = pr.user_id
WHERE pr.token_hash = $1 AND pr.expires_at > now() AND u.disabled_at IS NULL;

-- TakePasswordReset uses the token up: the row is deleted and its owner
-- returned in one statement, so of two concurrent callers only one gets a row.
-- name: TakePasswordReset :one
DELETE FROM password_resets
WHERE token_hash = $1 AND expires_at > now()
RETURNING user_id;

-- name: DeletePasswordResetsForUser :exec
DELETE FROM password_resets WHERE user_id = $1;

-- name: DeleteExpiredPasswordResets :exec
DELETE FROM password_resets WHERE expires_at <= now();
