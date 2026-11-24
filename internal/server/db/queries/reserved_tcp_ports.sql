-- name: CreateReservedTCPPort :one
INSERT INTO reserved_tcp_ports (port, user_id)
VALUES ($1, $2)
RETURNING port, user_id, created_at;

-- name: GetReservedTCPPort :one
SELECT port, user_id, created_at
FROM reserved_tcp_ports
WHERE port = $1;

-- name: ListReservedTCPPortsByUser :many
SELECT port, user_id, created_at
FROM reserved_tcp_ports
WHERE user_id = $1
ORDER BY port;

-- name: DeleteReservedTCPPortForUser :exec
DELETE FROM reserved_tcp_ports WHERE port = $1 AND user_id = $2;

-- name: ListAllReservedTCPPorts :many
SELECT port, user_id, created_at
FROM reserved_tcp_ports
ORDER BY port;

-- name: DeleteReservedTCPPort :exec
DELETE FROM reserved_tcp_ports WHERE port = $1;

-- name: CountReservedTCPPorts :one
SELECT count(*) FROM reserved_tcp_ports;

-- name: CountReservedTCPPortsByUser :one
SELECT count(*) FROM reserved_tcp_ports WHERE user_id = $1;

-- name: LockReservedTCPPort :one
SELECT user_id FROM reserved_tcp_ports WHERE port = $1 FOR UPDATE;

-- name: UpsertReservedTCPPort :exec
INSERT INTO reserved_tcp_ports (port, user_id)
VALUES ($1, $2)
ON CONFLICT (port) DO UPDATE SET user_id = EXCLUDED.user_id, created_at = now();

-- name: DeleteReservedTCPPortReturningOwner :one
DELETE FROM reserved_tcp_ports WHERE port = $1 RETURNING user_id;
