# Admin CLI

`tunneld admin` works on the database of the server and needs the same
config file (`--config`). It manages accounts, tokens, reservations and
approvals, and can be used while the server runs.

```
tunneld admin create-user         --config PATH --email EMAIL [--password-file PATH | --password-stdin]
tunneld admin create-admin        --config PATH --email EMAIL --allow-unverified [--password-file PATH | --password-stdin]
tunneld admin list-users          --config PATH
tunneld admin mark-verified       --config PATH --email EMAIL
tunneld admin disable-user        --config PATH --email EMAIL
tunneld admin enable-user         --config PATH --email EMAIL
tunneld admin promote-user        --config PATH --email EMAIL [--allow-unverified]
tunneld admin demote-user         --config PATH --email EMAIL
tunneld admin issue-token         --config PATH --email EMAIL --name NAME
tunneld admin list-tokens         --config PATH --email EMAIL
tunneld admin revoke-token        --config PATH --id TOKEN_ID
tunneld admin reserve-subdomain   --config PATH --email EMAIL --subdomain NAME
tunneld admin release-subdomain   --config PATH --subdomain NAME
tunneld admin list-reservations   --config PATH [--email EMAIL]
tunneld admin reserve-udp-port    --config PATH --email EMAIL --port PORT
tunneld admin release-udp-port    --config PATH --port PORT
tunneld admin list-udp-ports      --config PATH [--email EMAIL]
tunneld admin list-pending        --config PATH
tunneld admin approve-user        --config PATH --email EMAIL
tunneld admin reject-user         --config PATH --email EMAIL
tunneld admin send-test-email     --config PATH --to EMAIL
tunneld admin gen-csrf-key        # prints base64-encoded 32-byte key for auth.csrf_key
```

Notes:

- **Passwords** never go on the command line. `create-user` and
  `create-admin` read them from `--password-file` (the whole file, one line),
  from `--password-stdin` (one line from a pipe; refused when standard input
  is a terminal), or, without either flag, interactively: twice without echo
  on a terminal, or as two lines (password and confirmation) from a pipe. A
  password set here needs `limits.min_admin_password_length` characters
  (default 12). `--password-file` warns when the file is readable by group or
  others.
- **Admins:** `promote-user` refuses an account whose address is not
  verified unless `--allow-unverified` is given. `create-admin` always needs
  `--allow-unverified`, because a new account is not verified.
  `disable-user` and `demote-user` refuse the last active admin.
- **Open tunnels:** the CLI runs in its own process and cannot reach the
  tunnels of the running server. After `disable-user` or `revoke-token` the
  server closes the affected tunnels at its next check, within
  `tunnel.revalidate_interval` (default 30 s); the admin panel closes them at
  once. A tunnel of another user on a name or UDP port granted with
  `reserve-subdomain` or `reserve-udp-port` is not closed by that check; close
  it on the Connections page of the admin panel.
- **Reservations:** `reserve-subdomain` lower-cases the name and refuses
  invalid and system-reserved names; it is not bound by the per-user limit of
  the web UI. `reserve-udp-port` takes a decimal port inside `udp.port_range`.
  TCP ports are granted in the admin panel.
- **Approval** (`auth.signup: approval` or `closed`, see
  [Web UI and accounts](accounts-and-web-ui.md#sign-up-modes-and-approval)): `list-pending` lists the
  accounts that wait, oldest first, with ID, address, whether the address is
  verified and the creation time; accounts in use (an API token of any state
  or a reservation) are not among them. `approve-user` approves one; with
  mail set up (`mail.smtp.host` and `frontend.public_base_url`) the owner
  gets a mail that says so, unless the account is disabled or `auth.signup`
  is `open`. `reject-user` deletes an account that waits, with its sessions
  and everything else it owns; it refuses approved accounts, admins,
  disabled accounts and accounts in use, and every account while
  `auth.signup` is `open`. In `approval` and `closed` mode every command that
  changes state first approves the accounts in use, as the server does at
  start, and says so on stderr when there were any; so the CLI can be used
  between switching the config and restarting the server. Every command that
  gives an account something only an approved account can use approves it
  first: `create-user`, `create-admin`, `promote-user`, `issue-token`,
  `reserve-subdomain` and `reserve-udp-port`. Such an approval of an account
  that waited writes its own row `cli.approve-user` with `via` set to the
  command, also when the rest of the command then fails.
- **Enabling an account:** `enable-user` makes every API token of the
  account that was not revoked work again, including tokens created while
  the account was compromised. When the account was disabled, it prints a
  note on stderr that says so and how to list (`list-tokens`) and revoke
  (`revoke-token`) them, or to use "Revoke all API tokens" on the account's
  page in the admin panel.
- **Lists** (`list-users`, `list-tokens`, `list-reservations`,
  `list-udp-ports`, `list-pending`) do not run migrations. `list-tokens`
  shows the active tokens with their IDs for `revoke-token`; the token itself
  is never shown again. On a database that the new version has not migrated
  yet, a list can fail because a column is missing (`api_tokens.expires_at`,
  `users.approved_at`). Every command that changes something runs the
  migrations first, and so does the server at start.
- Every command that changes something writes an `audit_log` row
  (`cli.<command>`).
- The CLI reads and validates the same config as the server (it stops on the
  same errors), applies the `limits.*` settings and prints the config
  warnings on stderr.
