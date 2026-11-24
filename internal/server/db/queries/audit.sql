-- name: InsertAuditEntry :exec
INSERT INTO audit_log (user_id, action, metadata, ip)
VALUES ($1, $2, $3, $4);

-- name: ListAuditByUser :many
SELECT id, user_id, action, metadata, ip, created_at
FROM audit_log
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2;
