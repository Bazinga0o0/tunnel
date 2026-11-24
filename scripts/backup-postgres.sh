#!/usr/bin/env bash
# backup-postgres.sh — nightly pg_dump for the tunneld Postgres container.
#
# Writes gzipped custom-format dumps to $BACKUP_DIR, rotates after $RETAIN_DAYS.
# Designed to run from /etc/cron.d/tunneld-backup (see backup-postgres.cron).
#
# Dumps hold password hashes and token hashes: they are created with mode
# 0600. A dump is written to a temporary file first and only renamed to its
# final name when pg_dump and gzip both succeeded, so an aborted run never
# leaves a truncated file that looks like a backup.

set -euo pipefail
umask 077

BACKUP_DIR="${BACKUP_DIR:-/var/backups/postgres}"
RETAIN_DAYS="${RETAIN_DAYS:-7}"
CONTAINER="${CONTAINER:-tunneld-postgres}"
DB_USER="${DB_USER:-tunneld}"
DB_NAME="${DB_NAME:-tunneld}"

mkdir -p "$BACKUP_DIR"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out="$BACKUP_DIR/tunneld-$ts.sql.gz"
tmp="$(mktemp "$BACKUP_DIR/.tunneld-$ts.tmp.XXXXXX")"
trap 'rm -f -- "$tmp"' EXIT

docker exec "$CONTAINER" pg_dump -U "$DB_USER" -Fc "$DB_NAME" | gzip -9 > "$tmp"
mv -f -- "$tmp" "$out"

find "$BACKUP_DIR" -name 'tunneld-*.sql.gz' -type f -mtime +"$RETAIN_DAYS" -delete
# Temporary files of runs that were killed before they could clean up.
find "$BACKUP_DIR" -name '.tunneld-*.tmp.*' -type f -mtime +1 -delete

size="$(du -h "$out" | cut -f1)"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) OK  $size  $out"
