# The tunnel client

`tunnel` connects to a `tunneld` server with an API token (or a static token
of the server) and forwards what visitors send to a public name or port to a
port on the local machine.

## Commands

```
tunnel http PORT        [--config PATH] [--subdomain NAME]
tunnel tcp LOCAL_PORT   [--config PATH] [--port PORT]
tunnel udp LOCAL_PORT   [--config PATH] [--port PORT]
tunnel config init      # writes a config template to the default path (safe to re-run)
tunnel config path      # prints the default config path
tunnel version          # build version, commit and date
```

- `http` serves the local port on `https://<name>.<domain>`. `--subdomain`
  asks for a name; without it the server picks a random one.
- `tcp` and `udp` open a public port of the server's port range. `--port`
  asks for a specific port (`0`, the default, lets the server pick); with a
  database the port must be reserved for the account. See
  [TCP and UDP tunnels](tcp-udp.md).
- The client does not reconnect by itself: it ends when its session ends.
  Run it under a service manager that restarts it (see
  [Known limits](security-model.md#known-limits)).

## Configuration

Without `--config` the client reads `$XDG_CONFIG_HOME/tunnel/config.yaml`
(or `~/.config/tunnel/config.yaml`) on Linux and macOS and
`%APPDATA%\tunnel\config.yaml` on Windows; `tunnel config init` writes a
template there. `configs/tunnel.example.yaml` shows every key:

| Key | Meaning |
|---|---|
| `server` | `host:port` of the server's tunnel listener (`listen.tunnel_addr`; port 7443 in the example config). |
| `token` | An API token of the account (web UI or `tunneld admin issue-token`), or a static token of the server. |
| `insecure_skip_verify` | Keep it `false`. `true` switches the check of the server certificate off; only a local dev server with a throw-away self-signed certificate needs it. |
| `ca_file` | PEM file with the CA of a server certificate from a private CA; only CAs in this file are trusted then. A relative path is resolved against the directory of the config file. |

## Status output and certificate checks

`tunnel http` prints a single status line on start-up. The web dashboard
(`/tunnels`, HTMX live-polled) is the primary monitoring surface.

The client checks the server certificate. For a server whose certificate
comes from a private CA, set `ca_file` in the client config (only the CAs in
that file are trusted); `insecure_skip_verify: true` switches the check off
and makes the client print a warning on every start. On Unix the client also
warns when its config file (it holds the token) is readable by group or
others. Text the server sends is shown without control characters and cut to
256 characters.
