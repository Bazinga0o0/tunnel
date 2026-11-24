# TCP and UDP tunnels

Besides HTTPS on subdomains, the server can forward TCP connections and UDP
datagrams from public ports of a configured range to the client.

## TCP tunneling

Enable in config:

```yaml
tcp:
  enabled: true
  port_range:
    low: 10000
    high: 20000
```

Port ranges start at 1024 or above and must not contain the server's own
ports (`listen.*`, `metrics.addr`, `service_api.addr`). Open the port range
in your firewall.
Then from a client:

```bash
./bin/tunnel tcp 22               # server picks a public port
./bin/tunnel tcp 22 --port 15042  # request a specific reserved port
```

With a database, a specific port can only be requested when it is reserved
for your account (`port not reserved` otherwise, `port reserved` when it
belongs to somebody else). An admin grants TCP ports in the admin panel
(Reservations); there is no CLI command for TCP ports. A port the server
draws at random that is reserved for somebody else is released and drawn
again; it is open only for the moment of the database lookup that finds the
reservation. Without a database (static tokens) there are no reservations,
and a client can request any free port of the range.

The `tcp_ports` of a registered service (see [Services](services.md)) are
never drawn at random, not even while they have no holder. The service, not
an admin, decides who holds them, through the service API; the holder is an
ordinary TCP port reservation of that account, and its client asks for the
port with `--port` as above. When the holder changes, the server closes the
session that holds the port. A client that connects right after the change
can get `port unavailable` until the old session is gone.

## UDP tunneling

Enable in config:

```yaml
udp:
  enabled: true
  port_range:
    low: 30000
    high: 40000
  flow_idle_timeout: 60s   # default 30s
```

Open the port range in your firewall (UDP). Then from a client:

```bash
./bin/tunnel udp 7000               # server picks a public UDP port
./bin/tunnel udp 7000 --port 35000  # request a specific reserved port
```

Admins can reserve a fixed UDP port for a user in the admin panel or with
the CLI:

```bash
# Reserve port 35000 for a user:
./bin/tunneld admin reserve-udp-port --config configs/tunneld.yaml \
    --email user@example.com --port 35000

# Release a reserved UDP port:
./bin/tunneld admin release-udp-port --config configs/tunneld.yaml \
    --port 35000

# List all reserved UDP ports (or filter by user):
./bin/tunneld admin list-udp-ports --config configs/tunneld.yaml
./bin/tunneld admin list-udp-ports --config configs/tunneld.yaml \
    --email user@example.com
```

The same rule as for TCP applies: with a database a specific port needs a
reservation for your account. A flow ends `flow_idle_timeout` after the last
datagram from the visitor; datagrams from the backend do not keep it alive,
and each datagram from the visitor allows at most 256 replies.

The limits of the TCP and UDP edges are listed under
[Public edges](security-model.md#public-edges).
