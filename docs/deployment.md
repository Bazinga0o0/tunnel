# Deployment

Releases live at `https://github.com/Bazinga0o0/tunnel/releases`. Download the
server archive of a release on an Ubuntu host (22.04 / 24.04), compare it with
the release's `checksums.txt`, unpack it and run the installer from the
unpacked directory.

```bash
# On the server:
VERSION=X.Y.Z   # the release tag without the leading "v"
BASE="https://github.com/Bazinga0o0/tunnel/releases/download/v${VERSION}"
curl --proto '=https' --tlsv1.2 -fLO "${BASE}/tunneld-${VERSION}-linux-amd64.tar.gz"
curl --proto '=https' --tlsv1.2 -fLO "${BASE}/checksums.txt"
sha256sum -c --ignore-missing checksums.txt

mkdir "tunneld-${VERSION}"
tar xzf "tunneld-${VERSION}-linux-amd64.tar.gz" -C "tunneld-${VERSION}"
cd "tunneld-${VERSION}"
sudo ./scripts/install-server.sh

# Generate a CSRF key and paste it into /etc/tunneld/config.yaml:
sudo /opt/tunneld/tunneld admin gen-csrf-key

# Edit /etc/tunneld/config.yaml (tls.acme.*, mail.*, frontend.public_base_url;
# database.url is already filled in on a first install). Unknown keys and
# invalid values stop the server with a message naming the key.
# Set secrets in /etc/tunneld/env (IONOS_API_KEY="public.private" for ACME)

sudo systemctl start tunneld
sudo systemctl status tunneld
journalctl -u tunneld -f
```

The checksum file comes from the same release as the archive. It shows that the
download is complete, not that the release is genuine: releases are not signed
yet. While the repository is private, the two `curl` downloads need an
authenticated client instead, for example
`gh release download "v${VERSION}" --repo Bazinga0o0/tunnel`.

`scripts/install-server.sh` is idempotent. It expects the layout of the release
archive (`tunneld`, `docker-compose.yml`, `systemd/tunneld.service` and
`configs/tunneld.example.yaml` next to `scripts/`) and stops before changing
anything if one of these files is missing. What it sets up:

- With apt: `ufw`, `docker.io` and the compose plugin. The plugin is
  `docker-compose-plugin` when apt offers it (hosts with Docker's own apt
  repository) and Ubuntu's `docker-compose-v2` otherwise; the installer stops
  if neither is available or `docker compose version` does not work
  afterwards. It also creates the system account `tunneld` (no login shell).
- `/opt/tunneld` (root): binary, `docker-compose.yml` and `.env`.
- `/etc/tunneld` (`root:tunneld`, 0750) with `config.yaml` and `env`
  (`root:tunneld`, 0640). The service can read them but not change them.
  An existing `config.yaml` or `env` is never overwritten.
- `/var/lib/tunneld/certs` (`tunneld`, 0700): the certificate cache and the
  only directory the service may write to. `tls.acme.cache_dir` must point
  there.
- The PostgreSQL password: generated at random on the first install, stored in
  `/opt/tunneld/.env` (root, 0600, read by `docker compose`) and written into
  `database.url` of the new `config.yaml`. An existing password is never
  changed.
- Firewall: `22/tcp`, `443/tcp` and `7443/tcp` are allowed. Existing rules are
  kept; nothing is reset. The port ranges for TCP and UDP tunnels are not
  opened for you. Open the ranges you configured, for example
  `sudo ufw allow 10000:20000/tcp` and `sudo ufw allow 30000:40000/udp`.
- The systemd unit `tunneld.service`, enabled but not started. It runs the
  server as `tunneld` with a read-only file system, a system call filter, at
  most 2 GiB of memory (`MemoryMax=2G`), a soft limit for the Go runtime
  256 MiB below it (`Environment=GOMEMLIMIT=1792MiB`) and 65536 file
  descriptors. To change the memory, change both together; see
  [Memory sizing](#memory-sizing).
- Not the nightly backup: the installer creates `/var/backups/postgres` but
  installs neither the backup script nor its cron file; see
  [Backups](#backups).
- Symbolic links are refused: when `/etc/tunneld/config.yaml`,
  `/etc/tunneld/env`, `/opt/tunneld/.env` or `/var/lib/tunneld/certs` is a
  link, the installer stops with a message that names the link and its
  target, before it changes anything (or, when the link turns up while it
  runs, at the step it has reached). Check the target and replace the link
  with a regular file or directory.

The server runs in production under this systemd unit; the installer has not
yet been run end to end on a fresh host. On the first start, read
`journalctl -u tunneld -e`: a sandbox option that gets in the way shows up
there (for example "operation not permitted").

## Memory sizing

The unit gives the service at most 2 GiB (`MemoryMax=2G`) and tells the Go
runtime to keep its memory below 1792 MiB (`GOMEMLIMIT`): as the process
comes near it, the garbage collector works harder, before the kernel would
end the process at `MemoryMax`. The 256 MiB between the two are for memory
outside the Go heap, above all the kernel's socket buffers, which cgroup v2
charges to the service as well. A `GOMEMLIMIT` in `/etc/tunneld/env`
overrides the unit's.

The default limits are sized so that their worst case stays below three
quarters of `MemoryMax` (1.5 GiB). Each limit bounds a number of things that
hold memory; the cost of one is what a measurement found for the worst case
it could produce, rounded up (measured on a development machine with Windows
and go1.27.4; the costs are not bounds that the code enforces). With a
database and TCP and UDP tunnels on:

| Limit | Default | Counted per unit | At the default |
|---|---|---|---|
| `edge.max_conns` (visitor connection with its tunnel stream, when the visitor does not read and the client writes as fast as it can) | 1000 | 704 KiB | 687.5 MiB |
| `http_server.max_conns` (public HTTPS connection) | 1100 | 40 KiB + 1.5 × `http_server.max_header_bytes`, at least 128 KiB (136 KiB at the default) | 146.1 MiB |
| `tunnel.max_sessions` (tunnel session) | 350 | 96 KiB | 32.8 MiB |
| the sessions' TCP ports (at most one each, and at most the port range) | 350 | 16 KiB | 5.5 MiB |
| the sessions' UDP ports (the same) | 350 | 80 KiB | 27.3 MiB |
| `tunnel.max_unauth_conns` (connection before the login, inside the TLS handshake) | 256 | 128 KiB | 32.0 MiB |
| `edge.udp.max_flows` (UDP flow) | 768 | 96 KiB | 72.0 MiB |
| `edge.udp.max_queued_bytes` (datagrams waiting for the tunnels) | 64 MiB | | 64.0 MiB |
| `limits.hash_concurrency` (password hash) | 4 | 64 MiB | 256.0 MiB |
| `frontend.rate_limit_max_keys` (key of the web UI's rate-limit tables, over all tables) | 1600 | 8.6 KiB | 13.4 MiB |
| the rest of the process (runtime, registry, database pool, mail queue, web UI requests) | | | 192.0 MiB |
| **total** | | | **1528.6 MiB (1.49 GiB)** |

A connection whose visitor has left keeps its term until its tunnel stream
is gone (see [Known limits](security-model.md#known-limits)); while the server drains it, it
costs less than a live one. A stream that the client did not take within the
write timeout would stay in the session outside every term, so the server
closes such a session (see [Tunnel listener](security-model.md#tunnel-listener)); a second
stream that the client opens ends the connection before yamux keeps it.
Not in the sum: the kernel's socket buffers, which nothing in the server
can measure or bound; a UDP flow whose reader gets no CPU time, or waits
for the port's writer while its client sends faster than the replies go
out, whose stream buffer can grow towards two stream windows (512 KiB)
until it catches up; a session's control stream, which can hold up to two
stream windows while one message is being handled (with all 350 sessions
at once about 175 MiB more, still below `GOMEMLIMIT`); and sessions that
have ended while a close timer of one of their streams was pending, which
stay in memory for up to five minutes without counting against any limit
(see [Known limits](security-model.md#known-limits)). Check the kernel's part on the running
host under load, for example with
`cat /sys/fs/cgroup/system.slice/tunneld.service/memory.stat` (fields
`sock`, `anon`, `kernel`) and `ss -tm state established`. The costs were
measured on Windows; if the numbers matter, measure again on the target
host: `TUNNELD_MEASURE_MEMORY=1 go test -count=1 -run '^TestMeasureMemory$' -v -timeout 30m ./cmd/tunneld/`.

When `tunneld serve` starts, it adds up the worst case of the configured
limits. When that is more than `GOMEMLIMIT`, or a limit that bounds memory is
switched off with a negative value, it logs a warning that names every term,
largest first. With `edge.max_conns: 2000` (and otherwise the defaults, a
database, TCP and UDP on) under the unit as shipped, for example:

    the configured limits allow the server to hold up to 2.16 GiB, more than
    the Go memory limit of 1.75 GiB (GOMEMLIMIT); under load the process can
    then run out of memory. Lower edge.max_conns (2000 x 704 KiB = 1.34 GiB),
    limits.hash_concurrency (4 x 64.0 MiB = 256.0 MiB), …, or raise
    GOMEMLIMIT together with MemoryMax of the systemd unit

(one line in the log). Without `GOMEMLIMIT` (outside the unit) it does not
warn.

**A bigger host.** Raise `MemoryMax` and `GOMEMLIMIT` together, and the
totals in proportion, so that the sum stays below about three quarters of
`MemoryMax`. For 4 GiB, for example:

```bash
sudo systemctl edit tunneld
# [Service]
# MemoryMax=4G
# Environment=GOMEMLIMIT=3584MiB
```

and twice the totals in `/etc/tunneld/config.yaml` (put the keys into the
blocks the file already has; a block may appear only once):

```yaml
http_server:
  max_conns: 2200
tunnel:
  max_sessions: 700
edge:
  max_conns: 2000
  udp:
    max_flows: 1536
frontend:
  rate_limit_max_keys: 3200
```

The worst case is then about 2.45 GiB. The shares (per tunnel, per address,
per account) can stay: they keep one tunnel, address or account from taking
everything. Restart and read the log: no memory warning means the limits fit
`GOMEMLIMIT`; a warning names the terms to lower first.

## Capacity of the defaults

What the default limits mean in practice:

- **Visitor connections** (HTTP and TCP tunnels together): 1000 at a time on
  the server, 256 per tunnel, 64 per visitor address and tunnel (one IPv4
  address or one IPv6 /64; users behind one NAT share them), and 256 per
  account over all its tunnels, UDP flows included (database mode). So the
  tunnels of four accounts at their limit fill the server (with static
  tokens: four tunnels), and four addresses fill one tunnel. HTTP visitors also use the public HTTPS port: 1100 connections in
  total, the web UI included, and 128 per client address.
- **UDP:** 256 flows (visitor address and port) per tunnel, 64 per visitor
  address, 768 on the server: the UDP tunnels of three accounts at their
  limit fill it (with static tokens: three tunnels).
- **Tunnel sessions:** 10 per account (database mode) and 350 on the server,
  so 35 accounts with 10 sessions each fill it; 256 connections may be in
  the login at a time, 16 per client address.
- **What a visitor sees** when a limit refuses: HTTP `503 Service
  Unavailable` "too many connections" over a connection limit, `502` "tunnel
  stream error" when the tunnel cannot take one more stream (its session's
  512 or its account's 256); TCP: the connection is accepted and closed at
  once, without data; UDP: the datagrams of a new flow are dropped. Over
  the limits of the public HTTPS port the connection is closed before TLS.
  The connection limits count their refusals in `tunneld_request_total`
  (statuses `limit_total`, `limit_tunnel`, `limit_ip`; `type="https"` for
  the public port); a stream the tunnel cannot take is logged (`open stream
  failed`, at most once per 5 s).
- **What a tunnel client sees:** `session limit reached` (10 sessions of the
  account), `server at capacity` (350 in total); a connection over the
  limits of the login phase is closed at once, and so is a session whose
  client does not take a new stream within 10 s.

## Rotating the database password

The password in `/opt/tunneld/.env` only takes effect when PostgreSQL
initialises an empty data volume. To change the password of an existing
database — in particular on a host that was installed before the installer
generated one, where the database most likely still has the development
default — change it in PostgreSQL first and then in both files:

```bash
# 1. A new random password (hex needs no escaping in the connection URL).
NEW_PW="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

# 2. Change it in PostgreSQL. Inside the container the local socket needs no
#    password, so the old one is not required.
printf "ALTER ROLE tunneld PASSWORD '%s';\n" "$NEW_PW" \
  | sudo docker exec -i tunneld-postgres psql -U tunneld -d tunneld -v ON_ERROR_STOP=1

# 3. Store it for docker compose: replace the POSTGRES_PASSWORD line and keep
#    every other line of /opt/tunneld/.env. The file stays readable by root
#    only, and the password is not part of any command line.
printf 'POSTGRES_PASSWORD=%s\n' "$NEW_PW" | sudo sh -c '
  umask 077
  f=/opt/tunneld/.env
  tmp="$(mktemp "$f.XXXXXX")" || exit 1
  { if [ -f "$f" ]; then grep -v "^POSTGRES_PASSWORD=" "$f"; fi; cat; } > "$tmp" \
    && chmod 600 "$tmp" && mv "$tmp" "$f" || { rm -f "$tmp"; exit 1; }'

# 4. Put the same value into database.url in /etc/tunneld/config.yaml:
#      url: "postgres://tunneld:<password>@127.0.0.1:5432/tunneld?sslmode=disable"
#    (print it with: sudo cat /opt/tunneld/.env)
sudoedit /etc/tunneld/config.yaml

# 5. Restart the service and check that it reaches the database.
sudo systemctl restart tunneld
sudo systemctl status tunneld
unset NEW_PW
```

## Upgrading a host set up by an older installer

1. Rotate the database password as described above.
2. Unpack the new release and run `sudo ./scripts/install-server.sh` again. It
   installs the new binary, `docker-compose.yml` and systemd unit, corrects
   ownership and modes of `/etc/tunneld` and `/var/lib/tunneld`, and leaves
   `config.yaml`, `env` and the database password alone. It stops at a
   symbolic link in place of `/etc/tunneld/config.yaml`, `/etc/tunneld/env`,
   `/opt/tunneld/.env` or `/var/lib/tunneld/certs`; on a host whose
   directories the service account owned before, check where such a link
   points before you replace it.
3. Make sure `tls.acme.cache_dir` is `/var/lib/tunneld/certs`; the service can
   no longer write anywhere else.
4. Check the config against the rules under
   [Configuration](server-config.md):
   `sudo /opt/tunneld/tunneld admin list-users --config /etc/tunneld/config.yaml`
   validates it without starting the server. (An admin command that changes
   something runs the database migration first, also while the old server
   still runs; that is harmless, the migration only adds a column the old
   version does not read.)
5. If you changed `MemoryMax` with a drop-in (`sudo systemctl edit
   tunneld`), set `Environment=GOMEMLIMIT=…` in the same drop-in, below it
   with room for memory outside the Go heap (the unit leaves 256 MiB at 2G,
   the 4 GiB example in [Memory sizing](#memory-sizing) 512 MiB), and size
   the limits to it. Without that, the unit's 1792 MiB apply.
6. Delete `/var/lib/tunneld/.ssh` if it exists:
   `sudo rm -rf /var/lib/tunneld/.ssh`. Older instructions had operators put
   SSH keys there to scrape the metrics as `tunneld`; the installer leaves
   the directory alone. Scrape through your own account instead (see
   [Metrics](#metrics)).
7. `sudo systemctl restart tunneld`, then read `journalctl -u tunneld -e`.
8. If the host runs the nightly backup (`/etc/cron.d/tunneld-backup` exists),
   re-install the backup script and its cron file from the unpacked archive.
   The installer does not touch either file, and the old cron line still
   writes its output to `/var/log/tunneld/backup.log`:

   ```bash
   sudo install -m 0755 -o root -g root scripts/backup-postgres.sh /opt/tunneld/backup-postgres.sh
   sudo install -m 0644 -o root -g root scripts/backup-postgres.cron /etc/cron.d/tunneld-backup
   ```

   The job then logs to the journal (`journalctl -t tunneld-backup`); see
   [Backups](#backups).
9. Optional clean-up of things the installer no longer manages: the Go
   toolchain under `/usr/local/go` with `/etc/profile.d/go.sh` (not needed on
   the server), the firewall rule for `80/tcp` (`sudo ufw delete allow 80/tcp`;
   nothing listens there), the rule for `10000:20000/tcp` if you do not use TCP
   tunnels, and the directory `/var/log/tunneld` — the last one only after
   step 8, or on a host without `/etc/cron.d/tunneld-backup`. As long as the
   old cron file is installed, it writes to that directory; once the directory
   is gone, the nightly backup no longer runs, usually without any visible
   error.

## Metrics

Loopback-only Prometheus endpoint at `http://127.0.0.1:9090/_tunneld/metrics`
(`metrics.addr`; `addr: ""` switches it off, a non-loopback address needs
`metrics.allow_non_loopback: true`). The server does not start when it cannot
bind the address. Scrape via an SSH tunnel with your own administrative
account. The `tunneld` service account has no login shell and must not be
given SSH keys.

```bash
ssh -N -L 9090:127.0.0.1:9090 <admin-user>@host
curl -s http://127.0.0.1:9090/_tunneld/metrics | grep tunneld_
```

Exposed metrics:
- `tunneld_active_sessions{type="http"|"tcp"|"udp"}` (gauge)
- `tunneld_request_total{type,status}` (counter); `type="https"` counts the
  connections the public listener refused over its limits, the statuses
  `limit_*`, `reply_limit`, `stream_rejected` and `bad_host` count refusals of
  the edges, `send_buffer_full` the UDP replies dropped because the port's
  socket could not send, `type="tunnel",status="ping_limit"` the tunnel
  connections closed for too many yamux pings,
  `type="tunnel",status="open_timeout"` the tunnel sessions closed because
  the client did not take a new stream in time, and
  `type="tunnel",status="second_stream"` the tunnel connections closed
  because the client opened a second stream
- `tunneld_auth_attempts_total{result}` (counter)
- `tunneld_cert_renewal_last_unix` (gauge)
- `tunneld_cert_not_after_unix` (gauge): expiry of the served certificate
  (ACME or certificate file), for an alert before it runs out
- plus Go runtime metrics (`go_goroutines`, `process_cpu_seconds_total`, …)

## Backups

A nightly `pg_dump` runs from cron once you install the script and the cron
file (from the unpacked release archive):

```bash
sudo install -m 0755 -o root -g root scripts/backup-postgres.sh /opt/tunneld/backup-postgres.sh
sudo install -m 0644 -o root -g root scripts/backup-postgres.cron /etc/cron.d/tunneld-backup
```

Dumps live under `/var/backups/postgres/tunneld-*.sql.gz`, retained 7 days by
default (override with `RETAIN_DAYS` env). They are readable by root only
(mode 0600), because they contain the password and token hashes. A dump is
written to a temporary file and renamed when it is complete, so an interrupted
run leaves no half-written backup. The dumps are not encrypted and stay on the
host; copy them elsewhere yourself.

The job logs to the journal instead of a file:

```bash
journalctl -t tunneld-backup
```

Restore the most recent dump:

```bash
gunzip -c /var/backups/postgres/tunneld-LATEST.sql.gz \
  | docker exec -i tunneld-postgres pg_restore -U tunneld -d tunneld --clean --if-exists
```

## Updating

```bash
sudo scripts/deploy.sh vX.Y.Z
```

Downloads the release tarball and `checksums.txt` from
`github.com/Bazinga0o0/tunnel` (HTTPS only), compares the checksum, swaps the
binary and restarts the service. The script exits with an error if the service
does not stay up for 15 seconds after the restart; the new binary is then
installed but not running, and `journalctl -u tunneld -e` shows why.

As with the first install, the checksum only detects a damaged download, and
the script downloads without authentication, so it needs release assets that
are publicly downloadable. `deploy.sh` replaces the binary only. To pick up a
changed systemd unit or `docker-compose.yml`, run `scripts/install-server.sh`
from the new archive instead.

## Troubleshooting

- **The server is "active" but nothing answers on 443 and 7443.** With ACME
  and no usable cached certificate, the server waits for its first
  certificate before it opens any listener. When Let's Encrypt or the IONOS
  API cannot be reached (or `IONOS_API_KEY` is wrong at the provider), it
  logs each failed attempt and waits before the next one: 1 minute, then 2,
  4, … up to 1 hour. systemd shows the unit as `active (running)` all the
  while; the log is the only signal:

  ```bash
  journalctl -u tunneld -e | grep acme
  ```

  Look for `acme: obtaining a certificate failed` and `acme: waiting before
  the next attempt`. The wait is kept across restarts in
  `obtain-backoff.json` in the cache directory (`<cache_dir>/production`, or
  `<cache_dir>/staging` with `staging: true`); a restart does not shorten it.
  Removing that file makes the next start try at once — mind the rate limits
  of Let's Encrypt. Faults that waiting cannot fix stop the start instead: a
  cache directory the service cannot write, an `account.json` that cannot be
  read or does not parse, a `certificate.json` that cannot be read (a
  permission error, a directory in its place), a missing `IONOS_API_KEY`. A
  `certificate.json` that can be read but does not parse (for example empty
  after a power loss) counts as no certificate: the server logs `acme: the
  cached certificate's metadata file does not parse; treating the cache as
  empty` and obtains a new one, which is one more order at Let's Encrypt.
  The cache files are written without `fsync`.
- **The server stops right after start with `config: ...`.** The message
  names the key; see [Configuration](server-config.md) for the values that are
  refused.
- **Tunnel connections end or are refused unexpectedly.** Idle HTTP tunnel
  connections end after 5 minutes, TCP after 30; many users behind one NAT
  address share the per-address limits (`edge.*.max_conns_per_ip`,
  `http_server.max_conns_per_ip`). The `tunneld_request_total` statuses
  `limit_*` show refusals. Tunnel streams that visitors left behind with a
  backend that keeps sending (server-sent events, live feeds, downloads)
  count against the same limits, per visitor address too, for up to about
  six minutes (see [Known limits](security-model.md#known-limits)); an account whose tunnels
  refuse every new visitor may be at its 256 streams (`open stream failed`
  in the log). The
  defaults are sized for 2 GiB; see [Capacity of the defaults](#capacity-of-the-defaults)
  and [Memory sizing](#memory-sizing) to raise them.
- **A tunnel client loses its connection, and the server logs `too many ping
  requests, closing tunnel connection`.** The client sent more yamux pings
  than the allowance (2 at once, one more per 15 s); the client of this
  project pings once every 30 s.
- **A tunnel client loses its connection, and the server logs `closing
  tunnel session: the client did not take a new stream in time`.** When a
  visitor arrived, the data queued towards the client needed more than 10 s,
  for example because visitors' uploads fill a slow downlink to the client
  (see [Tunnel listener](security-model.md#tunnel-listener)); its visitors lost their
  connections.
  The `tunnel` command ends with `accept stream: …`; start it again (a
  service manager can restart it).
- **`the configured limits allow the server to hold up to …` at start-up.**
  The limits can take more memory than `GOMEMLIMIT`; see
  [Memory sizing](#memory-sizing).
