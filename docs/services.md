# Services

A registered service is a program on the server machine that the accounts of
the tunnel use with their API token. HTTPS requests to
`<subdomain>.<domain>` go to the service once the server has checked the
token, and the service learns whose token it was. A service can also own TCP
ports of `tcp.port_range` and decide, through the service API, which account
holds them. Services need `database.url`; with static `auth.tokens` there
are no accounts to pass on, and the config is refused.

```yaml
services:
  - name: myservice
    subdomain: myservice
    upstream: "http://127.0.0.1:8080"
    secret_file: "/etc/tunneld/services/myservice.secret"
    tcp_ports: [20000]
    max_request_body_bytes: 0
    directory:
      listed: true
      title: "My service"
      description: "What the service is for."
service_api:
  addr: "127.0.0.1:9100"
```

| Key | Rule |
|---|---|
| `name` | 1 to 32 characters of `a-z`, `0-9` and `-`, unique. Names the service in logs, audit rows and the service API. |
| `subdomain` | One DNS label in lower case, not `app`, unique. With `tls.acme`, `tls.acme.domains` must cover `<subdomain>.<domain>` (the name itself or `*.<domain>`). |
| `upstream` | `http://` with a loopback host (`127.0.0.1`, `::1` or `localhost`) and a port; no path, query, user name or password. |
| `secret_file` | Required. Absolute path of the file with the service's secret for the service API; see [Service secret](#service-secret). |
| `tcp_ports` | Optional. Ports of `tcp.port_range` whose holder the service sets; a port belongs to one service only. They need `tcp.enabled: true` and `service_api.addr`. |
| `max_request_body_bytes` | Largest request body to the service. Missing or `0` selects 67108864 (64 MiB), at most 268435456 (256 MiB); a negative value is refused. |
| `directory` | Optional. `listed`, `title` and `description`; see [Directory](#directory). A service is not listed by default. |
| `service_api.addr` | Bind address of the service API, `host:port` with a loopback host and a port from 1 to 65535. Unlike `metrics.addr` there is no way around the loopback rule. Required as soon as a service has `tcp_ports`; its port must not lie in `tcp.port_range` or `udp.port_range`. Without any service the API is not started (the log says so). |

The subdomain of a service is reserved for the system at start-up, and by
the `tunneld admin` commands: no tunnel and no reservation can take it. A
reservation an account made before the service was added stays in the
database, but the requests go to the service, and the server logs a warning
at every start that names the command to release it
(`tunneld admin release-subdomain --config <file> --subdomain <name>`).

A reservation of one of the `tcp_ports` is logged as a warning at every
start as well, with the account (`user_id`): that account may host on the
port until the service sets another holder or clears it. The holder the
service set is such a reservation too, so the warning also appears for it;
the server cannot tell it from a port an admin granted in the panel. If the
service did not set that holder, remove it with `DELETE` on the service API
or in the admin panel (Reservations).

**Requests to a service.**

- A request needs `Authorization: Bearer <token>` with a tunnel API token
  that the tunnel listener would accept (the same check: the token is not
  revoked and not expired, the account is not disabled and, with
  `auth.signup: approval` or `closed`, approved). Without one it gets 401
  with `WWW-Authenticate: Bearer` and does not reach the service. The token
  check and the account lookup have 5 seconds together; when they have not
  finished by then, or the lookup fails, the request gets 503 (the token may
  be valid; try again).
- A request to switch protocols (an `Upgrade` or `HTTP2-Settings` header, or
  `upgrade` in `Connection`: WebSocket, h2c) gets 400. After the switch the
  client would talk to the service past the checks below.
- A body larger than `max_request_body_bytes` gets 413, also when it is sent
  without a length. Every request has 5 minutes to send its body and receive
  its answer; a service that has not answered by then is given up (504). A
  service that cannot be reached or fails gets 502. These failures, and those
  of the account lookup, are logged, at most one line every 5 seconds per
  service.

**What the service gets.** The request as the client sent it (method, path,
query, body) goes to `upstream`, with these changes to the headers:

| Header | |
|---|---|
| `X-Tunnel-Account-Id` | The account of the token, in decimal. Set by the server only. |
| `X-Tunnel-Account-Email` | The address of that account. Set by the server only. |
| `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` | Set by the server from the connection: the visitor's address, the public host `<subdomain>.<domain>` (lower case, without a port or a trailing dot, whatever the client wrote) and `https`. `Host` is the one of `upstream`. |
| `Authorization` | Never passed on, neither as a header nor as a trailer. |
| any `X-Tunnel-*` from the client | Dropped, in any spelling, also with `_` for `-` (`x_tunnel_account_id`), as headers and as announced trailers. |
| `X-Real-IP`, `Forwarded`, `True-Client-IP`, `X-Client-IP`, `Client-IP` and the client's `X-Forwarded-*` | Dropped, as at the tunnel edge. |

The two identity headers can be trusted only on requests that came through
the server. Bind the service to the loopback address of `upstream` and let
nothing else on the machine reach that port; anything that can connect to it
directly can set the headers itself.

**Service API.** It listens on `service_api.addr` and lets a service set
the holder of its `tcp_ports`:

```
PUT    /v1/tcp-ports/{port}/holder  {"account_id": N}  → 200 {"account_id": N, "sessions_closed": k}
DELETE /v1/tcp-ports/{port}/holder                     → 200 {"sessions_closed": k}
GET    /v1/tcp-ports/{port}/holder                     → 200 {"account_id": N}, 404 without holder
```

- Every call carries `Authorization: Bearer <secret>` with the content of the
  service's `secret_file`; otherwise it gets 401. The secret decides which
  service is calling.
- 400 for a port that is not a number from 1 to 65535, or a `PUT` body that
  is not `{"account_id": N}` with N > 0 (at most 4 KiB). 403 for a port that
  is not one of the calling service's `tcp_ports`. 404 on `PUT` for an
  account that does not exist, is disabled or, with `auth.signup: approval`
  or `closed`, waits for approval. 500 for a database error, which is
  logged. Errors have the body `{"error": "..."}`.
- A `PUT` or `DELETE` that has reached the database is carried out even when
  the caller goes away (within 10 seconds). A 500 does not say whether the
  change was made: the server closes the session that holds the port all the
  same, so that a holder who lost the port does not keep it. Repeat the call
  until it gets 200; both are idempotent.
- The holder is an ordinary TCP port reservation of the account; the admin
  panel shows it under Reservations. Change it through the service API: the
  service is not told about changes made in the panel.
- `PUT` and `DELETE` close the tunnel session that holds the port, whoever's
  it is: also a session of the new holder on another computer, and also when
  `PUT` names the account that already holds the port. The whole session
  ends, with its other tunnels. `sessions_closed` is 0 or 1.
- Every successful `PUT`, and every `DELETE` that removed a holder or closed
  a session, is written to the audit log as `service.port.holder.set` or
  `service.port.holder.clear`, and logged. The rows have no acting account;
  their metadata are `service`, `port`, `account_id` (set only),
  `previous_account_id` (`null` without one) and `sessions_closed`, never a
  secret. `previous_account_id` is read in the same step as the change. A
  call that ends in 500 writes no row; its error line in the log names the
  closed session (`sessions_closed`).

## Directory

A service can list itself in a directory that signed-in accounts can read,
so that clients can offer the services of a server without being told their
addresses. Nothing is listed by default.

```yaml
services:
  - name: myservice
    # ...
    directory:
      listed: true                       # default false
      title: "My service"                # required when listed; at most 80 characters
      description: "What it is for."     # optional; at most 400 characters
```

`title` and `description` are plain text: valid UTF-8 without control,
formatting or line-separator characters (no line breaks, no bidirectional
overrides) and without leading or trailing white space. They are checked
when the config is loaded, also for a service that is not listed, and a
client must never insert them into a page as HTML.

**`GET /api/v1/directory`** is served on the web UI hosts: the apex domain
and `app.<domain>`, for example `https://app.example.org/api/v1/directory`.

- It needs `Authorization: Bearer <token>` with a tunnel API token that the
  tunnel listener would accept (not revoked, not expired, account not
  disabled and, with `auth.signup: approval` or `closed`, approved). Without
  one, or with a token that is not valid, it answers 401 with
  `WWW-Authenticate: Bearer`; when the token check fails or takes longer
  than 5 seconds it answers 503.
- The answer lists the services with `directory.listed: true`, in config
  order, and nothing else about them (no upstream, port or account):

  ```json
  {"services":[{"name":"myservice","title":"My service","description":"What it is for.","url":"https://myservice.example.org"}]}
  ```

  `url` is `https://<subdomain>.<domain>`. With nothing listed the list is
  empty. The answer has `Cache-Control: no-store`.
- Every request counts against a limit of 60 per minute and client address
  (IPv6: per /64), whatever its outcome; over it the answer is 429 with
  `Retry-After`.
- The path exists only when at least one service is registered.

**Reloading.** `SIGHUP` applies a changed `directory` of a service
without a restart, as for `tcp_ports` below. A service whose other fields
changed at the same time keeps its old directory until the restart.

## Service secret

**Reloading `tcp_ports`.** Send `SIGHUP` (`sudo systemctl reload tunneld`)
to apply a changed `tcp_ports` list without a restart; no tunnel or
connection is closed. The server re-reads and validates the config file; if
that fails it logs the error and keeps the running config. Then:

- A port added to a service is no longer drawn at random and becomes one the
  service can set a holder for.
- A port removed from a service becomes an ordinary pool port again. A
  tunnel that holds it keeps running, and a holder reservation of the port
  stays in the database until you release it in the admin panel
  (Reservations); the service can no longer change it (403).
- A changed `directory` takes effect at once (see [Directory](#directory)),
  as long as the service is otherwise unchanged.
- Every other difference from the running config (listen addresses, TLS,
  database, limits, `tcp.port_range`, a service that is added, removed or
  changed in another field, ...) is ignored and logged as
  `config change requires a restart and is ignored`. A `tcp_ports` entry
  outside the running `tcp.port_range` is ignored the same way. `SIGHUP` is
  not available on Windows.

The server reads the secret files when `tunneld serve` starts, not when a
`tunneld admin` command loads the config; after changing a secret, restart
the service. White space around the secret, such as the newline `openssl`
writes, is not part of it. The server does not start when a file cannot be
read, when a secret has fewer than 32 characters, or when two services have
the same secret. Each service needs one of its own, even one without
`tcp_ports`.

```bash
sudo install -d -o root -g tunneld -m 0750 /etc/tunneld/services
sudo sh -c 'umask 027; openssl rand -hex 32 > /etc/tunneld/services/myservice.secret'
sudo chown root:tunneld /etc/tunneld/services/myservice.secret
sudo chmod 0640 /etc/tunneld/services/myservice.secret
sudo systemctl restart tunneld
```

The file is `root:tunneld` 0640 like `config.yaml` and `env`: the server can
read it but not change it. The systemd unit needs no change for this:
`ProtectSystem=strict` leaves `/etc` readable, but the service runs without a
capability that bypasses file permissions, so the group `tunneld` must be
able to read the file and enter its directory. The service itself needs the
same value; give it a copy that only its own account can read, rather than
adding that account to the group `tunneld` (which would let it read
`config.yaml` and `env` as well).
