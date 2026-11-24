-- name: CreateUser :one
INSERT INTO users (email, password_hash)
VALUES ($1, $2)
RETURNING id, email, password_hash, email_verified_at, created_at, disabled_at, is_admin, approved_at;

-- name: GetUserByEmail :one
SELECT id, email, password_hash, email_verified_at, created_at, disabled_at, is_admin, approved_at
FROM users
WHERE email = $1;

-- name: GetUserByID :one
SELECT id, email, password_hash, email_verified_at, created_at, disabled_at, is_admin, approved_at
FROM users
WHERE id = $1;

-- GetUserByIDForUpdate locks the row until the transaction ends.
-- name: GetUserByIDForUpdate :one
SELECT id, email, password_hash, email_verified_at, created_at, disabled_at, is_admin, approved_at
FROM users
WHERE id = $1
FOR UPDATE;

-- LockUserForChildInsert serialises transactions that count a user's rows in
-- another table and then insert one (per-user limits). FOR NO KEY UPDATE does
-- not block the foreign-key checks of unrelated inserts for the same user.
-- name: LockUserForChildInsert :one
SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE;

-- LockAdminUsers locks every admin row, in id order so that two callers
-- never wait on each other in a cycle. Demote and disable take these locks
-- before they check that an active admin remains.
-- name: LockAdminUsers :many
SELECT id, disabled_at
FROM users
WHERE is_admin = true
ORDER BY id
FOR UPDATE;

-- name: ListUsers :many
SELECT id, email, email_verified_at, created_at, disabled_at, is_admin, approved_at
FROM users
ORDER BY id ASC;

-- name: UpdateUserPassword :execrows
UPDATE users SET password_hash = $2 WHERE id = $1;

-- name: DisableUser :exec
UPDATE users SET disabled_at = now() WHERE id = $1;

-- name: MarkUserEmailVerified :exec
UPDATE users SET email_verified_at = now() WHERE id = $1;

-- name: SetUserAdmin :exec
UPDATE users SET is_admin = $2 WHERE id = $1;

-- name: CountAdmins :one
SELECT count(*) FROM users WHERE is_admin = true AND disabled_at IS NULL;

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: EnableUser :exec
UPDATE users SET disabled_at = NULL WHERE id = $1;

-- ApproveUser keeps the time of the first approval. It changes no row, and
-- reports 0, for an approved account and for an unknown id.
-- name: ApproveUser :execrows
UPDATE users SET approved_at = now() WHERE id = $1 AND approved_at IS NULL;

-- ApproveExistingUsers runs at every start in approval or closed mode. It
-- approves the accounts that are in use already: admins and every account
-- that holds an API token (revoked and expired ones count) or a reservation.
-- Approved accounts are left alone, so a second run changes nothing.
-- name: ApproveExistingUsers :execrows
UPDATE users u SET approved_at = now()
WHERE u.approved_at IS NULL
  AND (u.is_admin
    OR EXISTS (SELECT 1 FROM api_tokens t WHERE t.user_id = u.id)
    OR EXISTS (SELECT 1 FROM reserved_subdomains r WHERE r.user_id = u.id)
    OR EXISTS (SELECT 1 FROM reserved_tcp_ports r WHERE r.user_id = u.id)
    OR EXISTS (SELECT 1 FROM reserved_udp_ports r WHERE r.user_id = u.id));

-- ListPendingUsers lists the accounts that wait for approval and that an
-- admin can approve or reject. approved_at NULL means "waits" only in
-- approval and closed mode (auth.signup); in open mode it means nothing.
-- Left out are admins, disabled accounts and accounts in use: those
-- that hold an API token (revoked and expired ones count) or a
-- reservation. ApproveExistingUsers approves the last ones at the server's
-- start, but until the server has started in approval or closed mode they
-- still have approved_at NULL.
-- name: ListPendingUsers :many
SELECT u.id, u.email, u.email_verified_at, u.created_at
FROM users u
WHERE u.approved_at IS NULL AND NOT u.is_admin AND u.disabled_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM api_tokens t WHERE t.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_subdomains r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_tcp_ports r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_udp_ports r WHERE r.user_id = u.id)
ORDER BY u.created_at, u.id;

-- CountPendingUsers counts the accounts of ListPendingUsers; the conditions
-- must stay the same.
-- name: CountPendingUsers :one
SELECT count(*) FROM users u
WHERE u.approved_at IS NULL AND NOT u.is_admin AND u.disabled_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM api_tokens t WHERE t.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_subdomains r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_tcp_ports r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_udp_ports r WHERE r.user_id = u.id);

-- DeletePendingUser is the rejection: it deletes the account only if it is
-- one that ListPendingUsers lists (the conditions must stay the same). Its
-- sessions and the rest go with it (ON DELETE CASCADE). The caller locks
-- the row first (GetUserByIDForUpdate) in the same transaction, for the
-- reason given with LockStaleUnverifiedUsers: on its own, this DELETE
-- can wait for a transaction that adds the account's first token and then
-- delete the account, and the token with it.
-- name: DeletePendingUser :execrows
DELETE FROM users u
WHERE u.id = $1 AND u.approved_at IS NULL AND NOT u.is_admin AND u.disabled_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM api_tokens t WHERE t.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_subdomains r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_tcp_ports r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_udp_ports r WHERE r.user_id = u.id);

-- name: ListAdminEmails :many
SELECT email FROM users WHERE is_admin AND disabled_at IS NULL ORDER BY id;

-- The search term must arrive with \, % and _ escaped by a backslash (the
-- users service does that), so that it is matched as text.
-- name: ListUsersWithSearch :many
SELECT id, email, email_verified_at, created_at, disabled_at, is_admin, approved_at
FROM users
WHERE ($1::text = '' OR email ILIKE '%' || $1 || '%' ESCAPE '\')
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountUsersWithSearch :one
SELECT count(*) FROM users
WHERE ($1::text = '' OR email ILIKE '%' || $1 || '%' ESCAPE '\');

-- name: GetUserEmailsByIDs :many
SELECT id, email FROM users WHERE id = ANY($1::bigint[]);

-- The two queries below delete accounts that were never used: the email
-- address is unverified, the account is older than max_age_seconds by the
-- database clock, it is neither an admin nor disabled, and it owns no API
-- token (revoked and expired ones count) and no reservation. An account that
-- holds a token or a reservation is in use by a tunnel client, verified or
-- not, and is kept.
--
-- They run in one transaction, the lock first, and the DELETE gets the ids
-- the lock returned. A DELETE on its own is not enough: a transaction that
-- is inserting the first token or reservation of an account holds a lock on
-- the account row; the DELETE waits for it and then deletes by what it saw
-- before the wait — the account, and with it the row that was just
-- committed.
--
-- What the pair guarantees: the DELETE touches only rows this transaction
-- has locked. While a row is locked nobody else can change it or add a
-- token or reservation to it; such an insert waits for the transaction.
-- Whatever was committed for the row before the lock was granted, the
-- DELETE sees, because it is a statement of its own that starts after the
-- lock, and it checks every condition again. An account that meets the
-- conditions only after the lock query has looked is not locked and not
-- deleted; a later sweep decides about it.

-- LockStaleUnverifiedUsers locks the accounts that meet the conditions and
-- returns their ids.
-- name: LockStaleUnverifiedUsers :many
SELECT u.id FROM users u
WHERE u.email_verified_at IS NULL
  AND u.is_admin = false
  AND u.disabled_at IS NULL
  AND u.created_at < now() - sqlc.arg(max_age_seconds)::double precision * interval '1 second'
  AND NOT EXISTS (SELECT 1 FROM api_tokens t WHERE t.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_subdomains r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_tcp_ports r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_udp_ports r WHERE r.user_id = u.id)
FOR UPDATE OF u;

-- DeleteStaleUnverifiedUsers deletes those of the accounts in ids, the ones
-- LockStaleUnverifiedUsers has locked in this transaction, that still meet
-- every condition. The conditions are the ones of the lock query and must
-- stay the same.
-- name: DeleteStaleUnverifiedUsers :execrows
DELETE FROM users u
WHERE u.id = ANY(sqlc.arg(ids)::bigint[])
  AND u.email_verified_at IS NULL
  AND u.is_admin = false
  AND u.disabled_at IS NULL
  AND u.created_at < now() - sqlc.arg(max_age_seconds)::double precision * interval '1 second'
  AND NOT EXISTS (SELECT 1 FROM api_tokens t WHERE t.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_subdomains r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_tcp_ports r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_udp_ports r WHERE r.user_id = u.id);

-- The pair below does the same for accounts that were never approved
-- (approval or closed mode, limits.pending_account_ttl): approved_at takes
-- the place of email_verified_at; everything else, the reasoning above
-- included, is as for the unverified accounts.

-- LockStalePendingUsers locks the accounts that meet the conditions and
-- returns their ids.
-- name: LockStalePendingUsers :many
SELECT u.id FROM users u
WHERE u.approved_at IS NULL
  AND u.is_admin = false
  AND u.disabled_at IS NULL
  AND u.created_at < now() - sqlc.arg(max_age_seconds)::double precision * interval '1 second'
  AND NOT EXISTS (SELECT 1 FROM api_tokens t WHERE t.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_subdomains r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_tcp_ports r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_udp_ports r WHERE r.user_id = u.id)
FOR UPDATE OF u;

-- DeleteStalePendingUsers deletes those of the accounts in ids, the ones
-- LockStalePendingUsers has locked in this transaction, that still meet
-- every condition. The conditions are the ones of the lock query and must
-- stay the same.
-- name: DeleteStalePendingUsers :execrows
DELETE FROM users u
WHERE u.id = ANY(sqlc.arg(ids)::bigint[])
  AND u.approved_at IS NULL
  AND u.is_admin = false
  AND u.disabled_at IS NULL
  AND u.created_at < now() - sqlc.arg(max_age_seconds)::double precision * interval '1 second'
  AND NOT EXISTS (SELECT 1 FROM api_tokens t WHERE t.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_subdomains r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_tcp_ports r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_udp_ports r WHERE r.user_id = u.id);

-- CountStalePendingUsers counts the accounts LockStalePendingUsers would
-- lock, without locking them. The reaper logs the number at start, when it
-- leaves the rule for the first hourly sweep. The conditions are the ones
-- of the lock query and must stay the same.
-- name: CountStalePendingUsers :one
SELECT count(*) FROM users u
WHERE u.approved_at IS NULL
  AND u.is_admin = false
  AND u.disabled_at IS NULL
  AND u.created_at < now() - sqlc.arg(max_age_seconds)::double precision * interval '1 second'
  AND NOT EXISTS (SELECT 1 FROM api_tokens t WHERE t.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_subdomains r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_tcp_ports r WHERE r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM reserved_udp_ports r WHERE r.user_id = u.id);
