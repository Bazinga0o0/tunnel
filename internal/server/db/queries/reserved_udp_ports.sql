-- name: CreateReservedUDPPort :one
INSERT INTO reserved_udp_ports (port, user_id)
VALUES ($1, $2)
RETURNING port, user_id, created_at;

-- name: GetReservedUDPPort :one
SELECT port, user_id, created_at
FROM reserved_udp_ports
WHERE port = $1;

-- name: ListReservedUDPPortsByUser :many
SELECT port, user_id, created_at
FROM reserved_udp_ports
WHERE user_id = $1
ORDER BY port;

-- name: DeleteReservedUDPPortForUser :exec
DELETE FROM reserved_udp_ports WHERE port = $1 AND user_id = $2;

-- name: ListAllReservedUDPPorts :many
SELECT port, user_id, created_at
FROM reserved_udp_ports
ORDER BY port;

-- name: DeleteReservedUDPPort :exec
DELETE FROM reserved_udp_ports WHERE port = $1;

-- name: CountReservedUDPPorts :one
SELECT count(*) FROM reserved_udp_ports;

-- name: CountReservedUDPPortsByUser :one
SELECT count(*) FROM reserved_udp_ports WHERE user_id = $1;
