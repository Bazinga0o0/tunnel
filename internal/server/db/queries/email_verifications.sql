-- The expiry is counted from the database clock, the clock every query
-- compares it with.
-- name: CreateEmailVerification :exec
INSERT INTO email_verifications (token_hash, user_id, expires_at)
VALUES (
    sqlc.arg(token_hash),
    sqlc.arg(user_id),
    now() + sqlc.arg(ttl_seconds)::double precision * interval '1 second'
);

-- name: GetEmailVerificationByHash :one
SELECT token_hash, user_id, expires_at
FROM email_verifications
WHERE token_hash = $1 AND expires_at > now();

-- name: DeleteEmailVerificationsForUser :exec
DELETE FROM email_verifications WHERE user_id = $1;

-- name: DeleteExpiredEmailVerifications :exec
DELETE FROM email_verifications WHERE expires_at <= now();
