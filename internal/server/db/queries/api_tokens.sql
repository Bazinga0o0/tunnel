-- name: CreateAPIToken :one
INSERT INTO api_tokens (user_id, name, token_hash, token_prefix)
VALUES ($1, $2, $3, $4)
RETURNING id, user_id, name, token_hash, token_prefix, created_at, last_used_at, revoked_at, expires_at;

-- GetAPITokenByHash returns a token only while it can be used: not revoked,
-- not expired, and owned by an account that is not disabled and, when
-- require_approved is true (auth.signup: approval or closed), approved.
-- name: GetAPITokenByHash :one
SELECT t.id, t.user_id, t.name, t.token_hash, t.token_prefix, t.created_at, t.last_used_at, t.revoked_at, t.expires_at
FROM api_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.token_hash = sqlc.arg(token_hash)
  AND t.revoked_at IS NULL
  AND (t.expires_at IS NULL OR t.expires_at > now())
  AND u.disabled_at IS NULL
  AND (u.approved_at IS NOT NULL OR NOT sqlc.arg(require_approved)::bool);

-- name: GetAPITokenByID :one
SELECT id, user_id, name, token_hash, token_prefix, created_at, last_used_at, revoked_at, expires_at
FROM api_tokens
WHERE id = $1;

-- name: ListAPITokensByUser :many
SELECT id, user_id, name, token_prefix, created_at, last_used_at, revoked_at, expires_at
FROM api_tokens
WHERE user_id = $1
ORDER BY created_at DESC;

-- RevokeAPIToken is the admin variant: it does not look at the owner.
-- name: RevokeAPIToken :execrows
UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- RevokeAPITokenForUser revokes a token only for its owner.
-- name: RevokeAPITokenForUser :execrows
UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;

-- name: TouchAPITokenUsage :exec
UPDATE api_tokens SET last_used_at = now() WHERE id = $1;

-- ListUsableAPITokenIDs returns those of the given token ids that can still
-- be used, by the same rule as GetAPITokenByHash: not revoked, not expired,
-- owned by an account that is not disabled and, when require_approved is
-- true, approved. A deleted token is not returned.
-- name: ListUsableAPITokenIDs :many
SELECT t.id
FROM api_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.id = ANY(@ids::bigint[])
  AND t.revoked_at IS NULL
  AND (t.expires_at IS NULL OR t.expires_at > now())
  AND u.disabled_at IS NULL
  AND (u.approved_at IS NOT NULL OR NOT sqlc.arg(require_approved)::bool);

-- Active means usable: not revoked and not expired.
-- name: CountActiveTokensByUser :one
SELECT count(*) FROM api_tokens
WHERE user_id = $1
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());
