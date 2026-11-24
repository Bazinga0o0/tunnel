# Security model

What the server does to protect itself, its users and the visitors of the
tunnels. The numbers are the defaults; the keys are in
`configs/tunneld.example.yaml`.

## Web UI and accounts

- **Sign-up and approval:** `auth.signup` decides how accounts start
  (`open`, `approval` or `closed`); see
  [Sign-up modes and approval](accounts-and-web-ui.md#sign-up-modes-and-approval).
- **Passwords:** argon2id (64 MiB, 3 passes, 4 lanes, 16-byte salt), compared
  in constant time. At most 4 hashes run at a time; a request waits at most 5 s
  for a slot and then gets `503`. One client address may have at most 2
  requests with hash work in flight (`limits.hash_per_ip`; login, sign-up,
  reset, password change, the admin's password re-entry); a third gets `429`
  at once ("Too many password checks from your network at the same time.
  Please try again in a moment.").
  Many users behind one NAT address who log in in the same second can see
  this. At least 8 characters for a user's own password and 12 for one an
  admin sets, counted in characters; at most 1024 bytes.
- **Login:** 10 failures per account and 30 per client address in 15 minutes;
  over a limit the answer is `429`, also for the correct password, until the
  oldest failure is 15 minutes old. The window slides and refused attempts do
  not count, so anybody who knows an address can keep that account out of the
  web UI for as long as they keep sending about ten wrong passwords per 15
  minutes (the tunnel tokens and the CLI are not affected); raise the limit or
  switch it off with `frontend.login_failures_per_account` if that is a
  problem. An unknown address costs the same password check as a known one.
  In addition, an address can log in successfully at most 30 times in 15
  minutes (`frontend.logins_per_account`); wrong passwords do not count
  there. Once it has reached that limit, every login with it gets `429`
  ("Too many logins for this email address. Please try again later.")
  before any password check,
  until the window has passed.
- **Rate-limit tables:** each limit keeps at most
  `frontend.rate_limit_max_keys` keys (1600; about 8.6 KiB a key over all
  tables, part of the [memory budget](deployment.md#memory-sizing)). A full counting table
  never refuses anybody: it evicts its oldest entry. The table of hash work
  per address (`limits.hash_per_ip`) holds only addresses with a request in
  flight; when it is full, a new address gets `429` at once. The table of
  failed logins per account makes room differently: it pushes out entries
  with few failures first, and only a final failure (a wrong password)
  changes it. A raised `frontend.rate_limit_max_keys` makes pushing entries
  out more expensive; raise the memory with it.
- **Sign-up and reset:** 5 sign-ups per client address and hour; 3 reset
  requests per client address and 3 per address per hour. Sign-up answers the
  same way for a new and a taken address (the owner of a taken address gets a
  notice mail), so every sign-up sends a mail to the address that was typed.
  Mail goes out from a background queue, so no response waits for SMTP. A
  reset request for an existing account still does a little more database
  work (it stores a reset token) than one for an unknown address. A reset link
  goes only to the address stored for the account, works once, and is void
  after any password change. A password reset, by link or by an admin, ends
  the web UI sessions but leaves the API tokens and the running tunnels alone;
  after a suspected take-over, revoke the tokens as well (see
  [Known limits](#known-limits)). Sign-up followed by a login, and the reset
  limit of a known address, can be used against users; see
  [Known limits](#known-limits).
- **Client address:** the address of the TCP connection; `X-Forwarded-For`
  and similar headers are ignored. IPv6 addresses count per /64.
- **Email verification:** the link opens a confirmation page; the address is
  verified only by the button on it, so a mail scanner that follows the link
  verifies nothing. Addresses are validated (a bare address, at most 254
  bytes, no control characters).
- **Sessions:** 24 random bytes, only their SHA-256 hash is stored, valid for
  30 days. The cookies are `__Host-tunneld_session` and `__Host-tunneld_csrf`
  (Secure, HttpOnly, SameSite=Lax, no Domain), so a tunnel on a subdomain
  cannot set them; a request with two cookies of one of these names is
  refused.
- **Password change** on the settings page: it needs the current password,
  and a wrong one counts as a failed login against the account and the
  client address, so the change shares the login limits above (over them:
  `429` with the login's text, nothing changed). Every change counts against
  `frontend.user_actions_per_hour`. The new password and the end of every
  session of the account, the current one included, are one transaction;
  the browser then gets a new session, so a copy of the old cookie stops
  working. If the new session cannot be stored, the password is changed and
  the browser is sent to the login page ("Your password was changed. Please
  log in with your new password."). API tokens are not revoked.
- **Requests:** CSRF token on every POST (gorilla/csrf, including its Origin
  check); request bodies at most 64 KiB, multipart refused.
- **Headers:** CSP with a per-request nonce (`default-src 'self'`, no
  `unsafe-inline`, `base-uri 'none'`, `form-action 'self'`,
  `object-src 'none'`), HSTS, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`, COOP and CORP
  `same-origin`, and `Cache-Control: no-store` on every page behind the login.
- **Disabled accounts and revoked tokens:** a disabled account's sessions
  end and its tokens stop working at once. Open tunnels of a disabled account
  or a revoked token are closed at once when the change is made in the web
  UI or the admin panel, and within `tunnel.revalidate_interval` (30 s) when
  it is made with the CLI. Enabling the account again (CLI or admin panel)
  makes every token that was not revoked work again, also tokens created
  while the account was compromised; revoke them before you enable it.
- **Quotas:** 25 active API tokens per user (names up to 64 characters), 10
  reserved subdomains per user in the web UI. Creating and revoking tokens,
  reserving and releasing names and changing the password count together
  against 120 actions per user and hour (`frontend.user_actions_per_hour`);
  over it the page shows "Too many changes in a short time. Please try again
  later." (`429`) and nothing is done. Revoking tokens and releasing names
  needs a login only; creating them needs a verified address.
- **Admin panel:** see [Admin panel](accounts-and-web-ui.md#admin-panel). Every `/admin` path
  answers non-admins like a missing page; password re-entry for promote,
  demote and password reset counts against the login failure limits of the
  admin's account and of the client address (over them: "Too many failed
  password attempts. Try again later. Nothing was changed."); the last active
  admin cannot be disabled or demoted; an unverified account cannot be
  promoted.
- **Audit log:** every action that changes something — in the web UI, the
  admin panel or the CLI — writes a row to `audit_log` (actor, action,
  target, client address). Rows hold no passwords or tokens. The rows that
  requests without a login can cause, failed logins and password-reset
  requests, are bounded to 120 a minute together
  (`frontend.unauthenticated_audit_rows_per_minute`); the rest of a minute
  is counted in one row `audit.unauthenticated.dropped` and one log line, so
  during a flood who failed and from where is not recorded. Rows of
  signed-in users, admins, successful logins, sign-ups, verifications and
  completed resets are never dropped. `audit_log` is never pruned.
- **Log lines:** failures that a client can cause at will (requests the
  server cannot answer, failed session lookups) are logged at most once per
  5 s, with the number of lines held back; a request whose client went away
  is not logged.

## Tunnel listener

- TLS handshake and login within 10 s; at most 256 connections that have not
  logged in, 16 per client address; the token check is bounded by 5 s.
  A connection gets one login attempt: a refused login closes it after a
  pause of 50 ms. Failed logins are logged with the client address, never
  with the token, but they are not counted (see [Known limits](#known-limits)).
- With a database the token is checked a second time once the session is
  registered (within the handshake deadline), so a login that races a
  disable of the account or a revoke of its token is refused with
  `invalid token` (log: `authentication failed at the second check`).
- Control frames up to 4 KiB before the login and 16 KiB after; 20 control
  messages at once and 5 per second after that; a client that opens a second
  stream or keeps sending unknown messages is disconnected. A client may open
  exactly one stream per connection, the control stream: the frame reader
  that counts ping requests (below) ends the connection at the client's
  second stream-opening frame, before yamux registers the stream, so
  nothing can wait in the accept backlog with a full window. The server logs
  `client opened a second stream, closing tunnel connection` (at most once a
  second, with the number of connections closed) and counts
  `tunneld_request_total{type="tunnel",status="second_stream"}`; a check in
  the acceptor stays as a second line.
- yamux ping requests: 2 at once and one more per 15 s (an honest client
  pings once every 30 s). A connection that asks for more is closed, before
  and after the login; the server logs `too many ping requests, closing
  tunnel connection` (at most once a second, with the number of connections
  closed) and counts `tunneld_request_total{type="tunnel",status="ping_limit"}`.
  Any read error of a tunnel connection ends its session.
- A client that does not take a new stream within the connection write
  timeout (10 s) loses its session, as after a failed keep-alive: its
  tunnels, ports and places go and every visitor of its tunnels loses the
  connection. A plain stall of the connection does not cause this (the
  keep-alive catches a stall); a queue towards the client that is longer
  than the write timeout does, for example visitors' uploads into a slow
  downlink. By reasoning from a probe, not a measurement on a real link: at
  most one frame per stream waits (32 KiB on TCP, up to 64 KiB for a UDP
  datagram), so the 256 streams of an account can queue about 8 or 16 MiB,
  enough against downlinks up to about 6.5 Mbit/s (TCP) or 13 Mbit/s (UDP).
  In that state yamux's own keep-alive would fail as well, up to 30 or 75 s
  later; the server ends the session about ten seconds into the flood.
  The `tunnel` command of this project does not reconnect by itself: it ends
  with `accept stream: …` and has to be started again (a service manager can
  do that). The visitor whose stream could not be opened gets
  `502` (HTTP), a closed connection (TCP) or nothing (UDP). The server logs
  `closing tunnel session: the client did not take a new stream in time` (at
  most once a second, with the number of sessions closed) and counts each
  closed session once in
  `tunneld_request_total{type="tunnel",status="open_timeout"}`. (yamux keeps
  such a stream in the session; without the close, the client could fill it
  later, outside every limit.) Other failed opens, at the stream limits of
  the session or the account, do not close the session.
- At most 10 sessions per user (database mode) and 350 in total; 512 streams
  per session, and 256 per user over all its sessions
  (`tunnel.max_streams_per_user`, database mode only). A client over the
  session limits gets `session limit reached` or `server at capacity`.
- Subdomains are lower-cased and must match `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`;
  names the service uses or a visitor would trust (`www`, `api`, `app`,
  `admin`, `login`, `mail`, …) are reserved for the system. With a database a
  specific TCP or UDP port needs a reservation for the user. A name the
  server draws at random is checked against the reservations before and
  after it is registered, a random port after it is registered (see
  [TCP tunneling](tcp-udp.md#tcp-tunneling)); one reserved for somebody else is given
  up and another drawn (names: at most 8 draws, then `internal error`). Every
  reservation lookup is bounded by `tunnel.verify_timeout` (5 s); a lookup
  that fails or runs out refuses the request with `internal error`.
- Clients get fixed error texts; internal errors go to the server log only.

## Public edges

- **Public HTTPS listener:** 10 s for the TLS handshake and the request head,
  120 s for an idle keep-alive connection, request heads up to 64 KiB (`431`
  above), 1100 connections in total and 128 per client address; a connection
  over these limits is closed right after it is accepted, before TLS. A
  `Host` that is not a valid host name (an IP address included) gets `400`.
- **Answers on the tunnel path:** an answer the server writes itself instead
  of passing the request to a tunnel (`400` for an invalid host, `404` for a
  host without a tunnel, `500`, `502` when the tunnel cannot take the
  stream, `503` over a connection limit) says `Connection: close`, and the
  connection is closed right after it: at once, or, when the request
  announced a body that was not read, after net/http's pause of half a
  second. Web UI answers keep the connection open.
- **HTTP tunnels:** every request on a connection is parsed and written anew.
  `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` are always set
  by the server; `X-Real-IP`, `Forwarded`, `True-Client-IP`, `X-Client-IP`
  and `Client-IP` are removed, in every spelling (also as trailers). Other
  headers that some proxies use for the client address (for example
  `CF-Connecting-IP`, `Fastly-Client-IP`, `X-Cluster-Client-IP`) are passed
  on as the visitor sent them: a backend should trust only the
  `X-Forwarded-For` the server sets. One connection serves one tunnel host.
  A connection switches to a raw copy only after the backend answered an
  upgrade with `101` (WebSocket); an `h2c` upgrade is never passed to the
  backend. An idle connection (no byte in either direction) is closed after
  5 minutes, WebSocket and SSE included.
- **TCP tunnels:** idle connections are closed after 30 minutes.
- **Connection limits** for HTTP and TCP tunnels: 256 per tunnel, 64 per
  visitor address and tunnel (many users behind one NAT address share them),
  1000 for HTTP and TCP together. A connection keeps its places until its
  tunnel stream is gone from the session, which can be later than the
  visitor (see [Known limits](#known-limits)): the server then reads and
  throws away what the tunnel client still sends, 512 KiB at full speed and
  then 128 KiB per 30 s. Once the tunnel session has ended, the rest is read
  at full speed, so the next session on the name or port (the restarted
  client, or a new owner) finds the places free.
- **UDP tunnels:** 256 flows per port, 64 per visitor address and port, 768
  in total; a flow ends 30 s after the visitor's last datagram; bounded
  queues per flow, port and server. Each datagram from a visitor allows 256
  replies (at most 4096 saved up). The credit counts datagrams, and one reply
  can be up to about 64 KiB, so one forged datagram can still make the
  tunnel send up to about 16 MiB to the forged sender: the credit bounds the
  number of replies per datagram, not the bytes. When the port's socket
  cannot send, replies are dropped instead of holding up the flows: a reply
  waits at most 50 ms for the port's writer (as long as a write may take)
  and at most 50 ms for room in the socket's send buffer, so a flow's reader
  is held up at most 100 ms per reply, however many flows the port has;
  after a write that ran out of time the port drops its replies for 20 ms
  without trying. A healthy socket loses no reply when the writer is held up
  for less than 50 ms (a garbage collection, a busy host). Such drops count as
  `tunneld_request_total{type="udp",status="send_buffer_full"}` (replies
  beyond the credit as `reply_limit`), and the server logs `udp replies
  dropped: the socket's send buffer stays full` at most once per 5 s.

## Operations

- Metrics listen on loopback only unless `metrics.allow_non_loopback` is set;
  the endpoint has no authentication.
- The systemd unit runs the service as `tunneld` in a tight sandbox: it can
  write only to its certificate cache, with a system call filter and a memory
  limit (`MemoryMax=2G`, `GOMEMLIMIT=1792MiB`; the default limits are sized
  to it, see [Memory sizing](deployment.md#memory-sizing)). Config and secrets are
  `root:tunneld` 0640.
- The installer generates the PostgreSQL password; `docker compose` refuses
  to start without one. Backups are 0600.
- CI runs `govulncheck`; actions are pinned to commit SHAs and the toolchain
  to the one in `go.mod`.

## Known limits

- Releases are not signed. `checksums.txt` comes from the same release as the
  archive and only shows that a download is complete.
- The server connects to PostgreSQL with the role that `docker-compose.yml`
  creates, which owns the database and is a superuser; there is no separate
  role with fewer rights for the running server.
- Tunnels live under the same registrable domain as the web UI. The
  `__Host-` cookies and the duplicate-cookie check protect the sessions;
  moving the tunnels to a domain of their own would be the structural fix.
- The per-account login limit can be used to lock a known account out of the
  web UI for a while; the reset link still works. Password-reset requests
  for an address are limited per address, so they can be held at their limit
  in the same way; the owner still receives the mails that are sent.
- Sign-up and login responses can reveal whether an address already has an
  account. The sign-up limit (`frontend.signups_per_ip`) slows this down but
  does not remove it.
- Per-account counters (successful logins, user actions per hour) are shared
  by everyone who can use the account. Someone holding a copy of a session
  cookie can use up the action budget, which delays a password change by the
  owner; the reset link and an admin (password reset, disable) remain.
- The password-hash slots (`limits.hash_per_ip` and the global limit) can
  be kept busy by many sources. Web login, sign-up, reset and password change
  then answer `503` after a short wait; tunnels, their token check (no
  password hash) and the CLI are not affected.
- Revoked API tokens and audit rows are never deleted, and the live web
  sessions of an account are not capped. Growth is bounded by the rate limits
  and the reaper removes expired sessions; a password change, an admin
  password reset or a disable deletes all sessions of the account.
- When a visitor leaves, the server can only half-close the tunnel stream;
  the tunnel client then half-closes its connection to the local service
  and goes on passing on what the service sends. A backend that keeps
  writing after that (server-sent events, live feeds, a WebSocket server that
  does not read, a TCP service that pushes, or the rest of a download) keeps
  the stream open until the local service ends or yamux's close timer
  resets it, about five minutes after the edge closed its side. Backends
  that end the response when their client half-closes are not affected.
  Such a lingering stream keeps its places in `edge.max_conns`, in the
  tunnel's stream limit, in the per-address limit on that tunnel and in the
  owner's stream limit, so a busy address (for example an office NAT) can
  reach its per-address limit and be refused (`503 too many connections`).
  The levers are `edge.http.max_conns_per_ip` and `edge.tcp.max_conns_per_ip`.
  The clean fix, telling the tunnel client that the visitor is gone, is not
  done: yamux v0.1.2 offers the server no way to reset a stream, so it needs
  an adapted yamux or a message of its own in the protocol.
- A tunnel session that ends while one of its streams has a close timer
  pending stays in memory until that timer has run out, up to five minutes.
  This memory grows with the rate at which such sessions end, not with the
  configured limits, and is outside the memory sum. It can only be caused by
  an authenticated account holder, not by an outsider. Not built: keeping a
  closed session's places until its timers have run out, a limit on tunnel
  logins per account and address, and a yamux that stops the timers when
  the session closes.
- The `tunnel` client does not reconnect: it ends on any error of its loop
  that accepts streams (`accept stream: ...`), whenever the server closes its
  session, and when its own acknowledgement of a new stream runs out of the
  write timeout on a congested uplink. Run the client under a service manager
  that restarts it (for example systemd with `Restart=`). Meanwhile an
  unreserved name or port is free for anyone.
- A reservation made with the admin CLI (`reserve-subdomain`,
  `reserve-udp-port`) ends no running tunnel of another user on that name or
  port, and the periodic check of the server looks at tokens only: such a
  tunnel keeps the name or port until it disconnects or is killed on the
  Connections page. A grant in the admin panel and a user's own reservation
  in the web UI close such tunnels at once.
- Client-address headers that the edge does not know (for example
  `CF-Connecting-IP`) reach the backend as the visitor sent them, and the UDP
  reply credit counts datagrams, not bytes (see [Public edges](#public-edges)).
- Not in the memory sum (see [Memory sizing](deployment.md#memory-sizing)): the kernel's
  socket buffers; UDP flow stream buffers (up to about two stream windows
  each); a session's control stream while a message is being handled; and
  sessions that ended with a close timer pending (above).
- On the tunnel port, failed logins are not counted per address or per token,
  and there is no limit on the rate of new connections from one address;
  only the 16 unauthenticated connections per address at a time, one attempt
  per connection, bound how fast tokens can be tried. API tokens are random
  values of about 190 bits, and static tokens need at least 16 characters;
  choose static tokens at random.
- The server warns about a config file that other users can read, not about
  one the group can read (the installer sets `root:tunneld` 0640 on purpose),
  and it does not check the file's owner.
- A password change or reset (settings page, mail link, admin) ends the web
  sessions only: API tokens stay valid until they are revoked, so the
  running tunnels stay up. After a suspected take-over of an account, revoke
  its tokens: the user on the `/tokens` page, an admin with "Revoke all API
  tokens and close tunnels" on the user's page in the admin panel, or with
  the CLI (`tunneld admin list-tokens --email ...`, then `tunneld admin
  revoke-token --id ...` for each token). `tunneld admin disable-user`
  refuses the account and all its tokens for new logins at once; its running
  tunnels are closed within `tunnel.revalidate_interval` (30 s by default).
  `enable-user` (or Enable in the admin panel) makes every token that was not
  revoked work again.
- Subdomain reservations stored by older versions in another spelling (with
  capital letters, for example `MyApp`) do not protect the lower-case name,
  which is the only form a tunnel client can use. `tunneld admin
  list-reservations --config ...` lists every reservation; release such a name
  exactly as listed (`release-subdomain --subdomain MyApp`) and reserve the
  lower-case form for its owner (`reserve-subdomain --email OWNER
  --subdomain myapp`). A name that stays invalid in lower case can only be
  released; the admin panel's Reservations page can also revoke it.
- Unverified accounts that were never used are kept unless
  `limits.unverified_account_ttl` is set.

## Roadmap

Planned work, in no particular order:

- An end-to-end run of the installer on a fresh host and of the release
  pipeline.
- Signed releases.
- A PostgreSQL role with fewer rights for the running server.
- Tunnels on a registrable domain of their own.
- A reconnect loop in the client.
- Pruning of old API tokens and audit rows.
- Telling the tunnel client when a visitor is gone, so that streams end at
  once.
