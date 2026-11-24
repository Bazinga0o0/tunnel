-- The expiry is counted from the database clock, the clock every query
-- compares it with.
-- name: CreateSession :one
INSERT INTO sessions (id, user_id, expires_at, user_agent, ip)
VALUES (
    sqlc.arg(id),
    sqlc.arg(user_id),
    now() + sqlc.arg(ttl_seconds)::double precision * interval '1 second',
    sqlc.arg(user_agent),
    sqlc.arg(ip)
)
RETURNING id, user_id, created_at, last_seen_at, expires_at, user_agent, ip;

-- GetSessionByID returns a session only while it can be used: not expired
-- and owned by an account that is not disabled.
-- name: GetSessionByID :one
SELECT s.id, s.user_id, s.created_at, s.last_seen_at, s.expires_at, s.user_agent, s.ip
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.id = $1 AND s.expires_at > now() AND u.disabled_at IS NULL;

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = now() WHERE id = $1;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;

-- name: DeleteSessionsByUser :exec
DELETE FROM sessions WHERE user_id = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at <= now();

-- name: CountActiveSessionsByUser :one
SELECT count(*) FROM sessions WHERE user_id = $1 AND expires_at > now();

-- name: LastSeenByUser :one
SELECT max(last_seen_at) FROM sessions WHERE user_id = $1;
