-- name: CreateReservedSubdomain :one
INSERT INTO reserved_subdomains (subdomain, user_id)
VALUES ($1, $2)
RETURNING subdomain, user_id, created_at;

-- name: GetReservedSubdomain :one
SELECT subdomain, user_id, created_at
FROM reserved_subdomains
WHERE subdomain = $1;

-- name: ListReservedSubdomainsByUser :many
SELECT subdomain, user_id, created_at
FROM reserved_subdomains
WHERE user_id = $1
ORDER BY subdomain;

-- name: ListAllReservedSubdomains :many
SELECT subdomain, user_id, created_at
FROM reserved_subdomains
ORDER BY subdomain;

-- name: DeleteReservedSubdomainForUser :exec
DELETE FROM reserved_subdomains WHERE subdomain = $1 AND user_id = $2;

-- name: DeleteReservedSubdomain :exec
DELETE FROM reserved_subdomains WHERE subdomain = $1;

-- name: CountReservedSubdomains :one
SELECT count(*) FROM reserved_subdomains;

-- name: CountReservedSubdomainsByUser :one
SELECT count(*) FROM reserved_subdomains WHERE user_id = $1;
