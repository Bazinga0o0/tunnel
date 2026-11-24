# Accounts and web UI

When `database.url` is configured, `tunneld serve` also mounts the self-service
web UI on `app.<domain>` (and the apex). Users can sign up, log in, manage API
tokens, reserve subdomains, watch live tunnels, and change their password.
Ports cannot be reserved in the web UI; an admin grants them (see below).

## Sign-up modes and approval

`auth.signup` decides how accounts start.

- `open` (the default): anybody signs up and verifies the address.
- `approval`: as `open`, and then the account waits until an admin
  approves it. It can log in to the web UI, where a banner says that it
  waits, but it cannot create tokens or reservations, its API tokens are
  refused at the tunnel login, and the periodic check
  (`tunnel.revalidate_interval`) closes tunnels of an account that waits.
  When an address is verified and its account waits, every admin gets a
  mail (with mail set up) with the link to the approvals page. Admins
  approve or reject in the admin panel ("Freischaltungen", see
  [Admin panel](#admin-panel)) or with `tunneld admin approve-user` and
  `reject-user`; rejecting deletes the account. The owner gets a mail after
  the approval.
- `closed`: no sign-up (`/signup` answers 404); only an admin creates
  accounts, with the CLI. Accounts that wait stay waiting as in
  `approval`: closing the sign-up approves nobody.

At every start in `approval` or `closed` mode, the server approves the
accounts that are in use: admins and every account that holds an API token
(of any state) or a reservation; the log line `signup approval: existing
accounts approved` gives their number. All other accounts wait from then
on. Granting an account a token, a reservation or the admin role (CLI or
admin panel) approves it. Accounts that wait longer than
`limits.pending_account_ttl` (30 days) are deleted by the
[reaper](#reaper). The sign-up form also has a field that people do not
see; a sign-up that fills it is answered like a success, and nothing is
created or sent (`auth.signup.honeypot` in the audit log). Before you
switch back to `open`, reject the accounts that wait and that you do not
want (bots, for example): in `open` mode every account can be used, so
they would be in at once.

## Admin panel

Admins (see `promote-user` and `create-admin`) reach the admin panel at
`https://app.<domain>/admin`: an overview, the user list with actions
(verify, disable and enable, promote and demote, set a password, revoke all
API tokens and close the user's tunnels), the live connections with a kill
button, and the reservations of subdomains, TCP ports and UDP ports (grant
and revoke). Promote, demote and setting a password ask for the admin's own
current password. Disabling a user, revoking the tokens and granting a name
or port close the affected tunnels at once. Enabling a disabled user makes
the API tokens that were not revoked work again; the page says so next to
the Enable button. Setting a password does not revoke the user's API tokens;
after a suspected take-over of the account use "Revoke all API tokens and
close tunnels" as well. To everybody who is not a logged-in,
active admin, every `/admin` path answers like a page that does not exist
(404, no redirect to the login page).

With `auth.signup: approval` or `closed` the menu has an item
"Freischaltungen (n)", n being the number of accounts that wait for
approval. Its page lists them (address, whether it is verified, how long the
account has waited) with a checkbox each, "alle auswählen" and two buttons:
"Freischalten" approves the checked accounts, "Ablehnen (löscht)" asks once
more and deletes them. The page then says, per account, what was done and
what was skipped: an account that is approved or gone already, and, when
rejecting, the admin's own account, every admin, and accounts that are
disabled or in use (an API token of any state or a reservation). Each
approval and rejection writes `admin.user.approve` or `admin.user.reject`,
and an approval sends the owner a mail when mail is set up and the account
is not disabled. The detail page of an account that waits shows its state
and, unless the account is disabled, a "Freischalten" button. Promoting an
account that waits approves it first (a row `admin.user.approve` of its own,
with `via: promote`), and so does granting it a name or port. With
`auth.signup: open` neither the item nor the page exists.

## Email (transactional)

Set `mail.smtp.*` in your YAML config. Mail is sent only over TLS (STARTTLS,
or TLS from the first byte on port 465) with a verified certificate; with
`auth_required: true` a server that offers no AUTH is refused as well. Every
delivery is bounded by `dial_timeout` (10 s) and `send_timeout` (30 s), and the
web UI hands mail to a background queue (`mail.queue_size`, default 256, at
most 4096), so no page waits for SMTP. With `mail.smtp.host` set, the server
does not start without a `mail.smtp.port` from 1 to 65535 and a `mail.from`
that is a plain address (`noreply@example.com`, no display name);
`send_timeout` cannot be negative, a negative `dial_timeout` leaves the
connect to `send_timeout`.

For local dev, bring up Mailhog and point at its SMTP. Mailhog speaks no TLS,
so it needs `allow_plaintext: true` (the server logs a warning when it is
set; use it only for a mail catcher on the same machine):

```bash
make dev-up            # starts postgres + mailhog
# configs/tunneld.yaml:
# mail:
#   from: "noreply@tunnel.localhost"
#   smtp:
#     host: "127.0.0.1"
#     port: 1025
#     auth_required: false
#     allow_plaintext: true
```

Then sign up at `https://app.tunnel.localhost:18443/signup` — the verification
email lands in Mailhog's web UI at http://127.0.0.1:8025.

For production, point at a transactional service (Resend, Postmark, Mailgun,
IONOS SMTP, …) with `auth_required: true` + credentials.

Confirm SMTP is reachable before relying on it:

```bash
./bin/tunneld admin send-test-email --config configs/tunneld.yaml --to you@example.com
```

## Reaper

Runs in the server process, sweeps every hour, deletes expired sessions /
email verifications / password resets; automatic when `database.url` is set.
It deletes no account unless `limits.unverified_account_ttl` is set (at least
`1h`; the example suggests `168h`). Then it deletes accounts that are older
than that and were never used: address not verified, not an admin, not
disabled, no API token (of any state) and no reservation. A web session does
not count as use, so the rule also deletes an account that only logs in to
the web UI, and one created with `tunneld admin create-user` that was never
verified; mark such accounts verified (`mark-verified`) before you switch the
rule on.

With `auth.signup: approval` or `closed` it also deletes the accounts that
have waited for approval longer than `limits.pending_account_ttl` (default
`720h`, 30 days; at least `1h`; a negative value switches this off): not
approved, not an admin, not disabled, no API token (of any state) and no
reservation, verified or not. When you switch an existing server to one of
these modes, every account that is neither an admin nor holds a token or a
reservation starts to wait, with its old creation time. The sweep right at
start does not delete them: it only logs how many are due (`reaper: accounts
waiting for approval are not deleted at start`, a warning with `count_due`
when there are any). The next sweep, an hour later, deletes those older
than the TTL. To look through them first, set
`limits.pending_account_ttl: -1s` for the switch, go through `tunneld admin
list-pending` or the admin panel, and remove the setting afterwards.

How the web UI protects accounts (passwords, login limits, sessions,
headers) is described under [Web UI and accounts](security-model.md#web-ui-and-accounts).
