#!/usr/bin/env bash
# install-server.sh — idempotent bootstrap for a tunneld host.
#
# Designed for Ubuntu 22.04 / 24.04, run as root (or via sudo) from an
# extracted release archive. Installs docker + ufw, creates the tunneld system
# user, populates directories with correct ownership + perms, generates the
# PostgreSQL password on first install, drops the systemd unit, starts
# Postgres via docker compose, and enables the tunneld service.
#
# Re-running this script is safe — every step guards against already-done
# state. It never changes an existing database password and never overwrites
# an existing /etc/tunneld/config.yaml or /etc/tunneld/env.

set -euo pipefail

usage() {
    cat <<'EOF'
usage: sudo ./scripts/install-server.sh

Install tunneld on an Ubuntu host. Idempotent — safe to re-run.

Run it from an extracted release archive. Expected layout (as produced by
.goreleaser.yaml), relative to the archive root:

  tunneld                        server binary
  docker-compose.yml             PostgreSQL service definition
  systemd/tunneld.service        systemd unit
  configs/tunneld.example.yaml   config template
  scripts/install-server.sh      this file

The script aborts before changing anything if one of these files is missing,
or if /etc/tunneld/config.yaml, /etc/tunneld/env, /opt/tunneld/.env or the
certificate cache /var/lib/tunneld/certs is a symbolic link.

On the first install it generates a random PostgreSQL password, stores it in
/opt/tunneld/.env (root, 0600) and writes it into database.url of the new
/etc/tunneld/config.yaml. Afterwards edit /etc/tunneld/config.yaml, set
secrets in /etc/tunneld/env (e.g. IONOS_API_KEY), then:

    systemctl start tunneld
    systemctl status tunneld
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

if [[ $# -gt 0 ]]; then
    echo "error: unexpected argument: $1" >&2
    usage >&2
    exit 2
fi

if [[ $EUID -ne 0 ]]; then
    echo "error: install-server.sh must run as root (use sudo)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The archive puts this script into scripts/, everything else is addressed
# relative to the archive root one level up.
ARCHIVE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TUNNELD_USER="tunneld"
TUNNELD_GROUP="tunneld"
INSTALL_DIR="/opt/tunneld"
CONFIG_DIR="/etc/tunneld"
STATE_DIR="/var/lib/tunneld"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
SERVICE_ENV_FILE="$CONFIG_DIR/env"
# Read by `docker compose` in $INSTALL_DIR; holds POSTGRES_PASSWORD.
COMPOSE_ENV_FILE="$INSTALL_DIR/.env"
# Fixed names from docker-compose.yml.
PG_CONTAINER="tunneld-postgres"
PG_VOLUME_KEY="tunneld-pg-data"

SRC_BINARY="$ARCHIVE_ROOT/tunneld"
SRC_COMPOSE="$ARCHIVE_ROOT/docker-compose.yml"
SRC_UNIT="$ARCHIVE_ROOT/systemd/tunneld.service"
SRC_CONFIG="$ARCHIVE_ROOT/configs/tunneld.example.yaml"

missing=0
for f in "$SRC_BINARY" "$SRC_COMPOSE" "$SRC_UNIT" "$SRC_CONFIG"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required file not found: $f" >&2
        missing=1
    fi
done
if [[ $missing -ne 0 ]]; then
    echo "error: run this script from an extracted tunneld release archive" \
         "(tunneld-<version>-linux-<arch>.tar.gz); nothing was changed." >&2
    exit 1
fi

# The installer writes these files ($CONFIG_FILE, $SERVICE_ENV_FILE,
# $COMPOSE_ENV_FILE) and sets their owner and mode, and that of the
# directory $STATE_DIR/certs; writes, chown, chmod and install -d follow a
# symbolic link to its target.
# Older versions let the service account own /etc/tunneld and
# /var/lib/tunneld, so a link there may have been planted to make root write
# the target or hand it to the service account. A link is refused instead of
# followed: chown -h would change only the link, chmod has no such option,
# and the service would still read the target.
#
# refuse_link stops the installer when $1 is a symbolic link; $2 says how far
# it got. It runs once here, for a clean abort before anything changes, and
# again directly before each write, chown, chmod and install -d of these
# paths: the directories are taken from the service account only minutes
# later, after the packages are installed.
refuse_link() {
    if [[ -L "$1" ]]; then
        echo "error: $1 is a symbolic link (to $(readlink "$1")); the installer" \
             "does not write or change owner or mode through a link. Check the link" \
             "and its target, replace the link with a regular file or directory and" \
             "run the installer again; $2." >&2
        exit 1
    fi
}
for f in "$CONFIG_FILE" "$SERVICE_ENV_FILE" "$COMPOSE_ENV_FILE" "$STATE_DIR/certs"; do
    refuse_link "$f" "nothing was changed"
done

# Messages that need the operator's attention; printed again at the end.
notes=()

# apt_candidate prints the version apt would install for a package, or
# nothing when apt does not know the package or has no candidate for it.
apt_candidate() {
    LC_ALL=C apt-cache policy "$1" 2>/dev/null \
        | awk '$1 == "Candidate:" && $2 != "(none)" { print $2 }'
}

# read_compose_password prints the POSTGRES_PASSWORD stored in
# $COMPOSE_ENV_FILE, or nothing when the file or the entry does not exist.
read_compose_password() {
    [[ -f "$COMPOSE_ENV_FILE" ]] || return 0
    local line value
    line="$(grep -m1 -E '^POSTGRES_PASSWORD=' "$COMPOSE_ENV_FILE" || true)"
    value="${line#POSTGRES_PASSWORD=}"
    # Compose strips one pair of surrounding quotes; do the same.
    if [[ ${#value} -ge 2 ]]; then
        if [[ "$value" == \"*\" || "$value" == \'*\' ]]; then
            value="${value:1:${#value}-2}"
        fi
    fi
    printf '%s' "$value"
}

# generate_password prints 32 random bytes as 64 hex characters. Hex needs no
# escaping in .env, in YAML or inside a connection URL.
generate_password() {
    local pw
    pw="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    if [[ ! "$pw" =~ ^[0-9a-f]{64}$ ]]; then
        echo "error: could not generate a database password" >&2
        return 1
    fi
    printf '%s' "$pw"
}

# existing_database reports whether PostgreSQL data from an earlier
# installation exists: the container (running or stopped) or its data volume.
existing_database() {
    if docker container inspect "$PG_CONTAINER" >/dev/null 2>&1; then
        return 0
    fi
    local volumes
    volumes="$(docker volume ls -q --filter "label=com.docker.compose.volume=$PG_VOLUME_KEY")"
    [[ -n "$volumes" ]]
}

# render_config prints the config template with database.url pointing at the
# local PostgreSQL container. The password is passed through the environment
# so that it never shows up in a process list.
render_config() {
    TUNNELD_DB_PASSWORD="$1" awk '
        BEGIN {
            url = "postgres://tunneld:" ENVIRON["TUNNELD_DB_PASSWORD"] "@127.0.0.1:5432/tunneld?sslmode=disable"
        }
        /^[^ \t#]/ { in_database = ($0 ~ /^database:/) }
        in_database && !done && /^[ \t]+url:/ {
            match($0, /^[ \t]+/)
            print substr($0, 1, RLENGTH) "url: \"" url "\""
            done = 1
            next
        }
        { print }
    ' "$SRC_CONFIG"
}

echo "==> apt: installing base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# The compose plugin has two package names: docker-compose-plugin in Docker's
# own apt repository and docker-compose-v2 in Ubuntu's. Take the one that apt
# offers on this host; with both, Docker's.
compose_pkg=""
for candidate in docker-compose-plugin docker-compose-v2; do
    if [[ -n "$(apt_candidate "$candidate")" ]]; then
        compose_pkg="$candidate"
        break
    fi
done
if [[ -z "$compose_pkg" ]]; then
    echo "error: apt offers neither docker-compose-plugin (Docker's apt repository) nor" \
         "docker-compose-v2 (Ubuntu's 'universe' component). Enable one of the two" \
         "sources and re-run this script." >&2
    exit 1
fi
echo "    compose plugin package: $compose_pkg"

apt-get install -y -qq \
    curl ca-certificates ufw \
    docker.io "$compose_pkg" \
    >/dev/null

if ! docker compose version >/dev/null 2>&1; then
    echo "error: 'docker compose version' fails after installing $compose_pkg;" \
         "the rest of this script needs it." >&2
    exit 1
fi

echo "==> user: creating ${TUNNELD_USER}"
if ! id "$TUNNELD_USER" >/dev/null 2>&1; then
    adduser --system --group \
        --home "$STATE_DIR" \
        --shell /usr/sbin/nologin \
        "$TUNNELD_USER"
fi

echo "==> directories"
install -d -m 0755 -o root -g root "$INSTALL_DIR"
# Config and state belong to root. The service account only gets read access
# through its group, plus its own certificate cache.
install -d -m 0750 -o root -g "$TUNNELD_GROUP" "$CONFIG_DIR"
install -d -m 0750 -o root -g "$TUNNELD_GROUP" "$STATE_DIR"
# install -d sets owner and mode of an existing directory through a link.
refuse_link "$STATE_DIR/certs" "the steps above this one were done"
install -d -m 0700 -o "$TUNNELD_USER" -g "$TUNNELD_GROUP" "$STATE_DIR/certs"
install -d -m 0750 -o root -g root /var/backups/postgres

echo "==> binary"
install -m 0755 -o root -g root "$SRC_BINARY" "$INSTALL_DIR/tunneld"

echo "==> docker-compose.yml"
install -m 0644 -o root -g root "$SRC_COMPOSE" "$INSTALL_DIR/docker-compose.yml"

echo "==> database password"
if ! docker info >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || true
fi
if ! docker info >/dev/null 2>&1; then
    echo "error: the docker daemon is not reachable; start it and re-run this script" >&2
    exit 1
fi

db_password="$(read_compose_password)"
db_password_generated=0
if [[ -n "$db_password" ]]; then
    echo "    keeping the password stored in $COMPOSE_ENV_FILE"
elif existing_database; then
    echo "    existing PostgreSQL data found, but $COMPOSE_ENV_FILE has no POSTGRES_PASSWORD"
    notes+=("PostgreSQL data from an earlier installation exists, but $COMPOSE_ENV_FILE has no POSTGRES_PASSWORD. This installer never changes the password of an initialised database, so PostgreSQL was left untouched. Rotate the password as described in docs/deployment.md (\"Rotating the database password\"); that also creates $COMPOSE_ENV_FILE. Until then 'docker compose' refuses to run in $INSTALL_DIR.")
else
    db_password="$(generate_password)"
    db_password_generated=1
    # Append instead of replace: the file may hold other compose variables.
    # An append follows a link.
    refuse_link "$COMPOSE_ENV_FILE" "the steps above this one were done"
    (
        umask 077
        printf 'POSTGRES_PASSWORD=%s\n' "$db_password" >> "$COMPOSE_ENV_FILE"
    )
    echo "    generated a new password and stored it in $COMPOSE_ENV_FILE"
fi
if [[ -f "$COMPOSE_ENV_FILE" ]]; then
    refuse_link "$COMPOSE_ENV_FILE" "the steps above this one were done"
    chown root:root "$COMPOSE_ENV_FILE"
    refuse_link "$COMPOSE_ENV_FILE" "the steps above this one were done"
    chmod 0600 "$COMPOSE_ENV_FILE"
fi

echo "==> config"
# A dangling link is not -e: the file would be written through it.
refuse_link "$CONFIG_FILE" "the steps above this one were done"
if [[ -e "$CONFIG_FILE" ]]; then
    echo "    keeping existing $CONFIG_FILE"
    if [[ $db_password_generated -eq 1 ]]; then
        notes+=("A new database password was generated, but the existing $CONFIG_FILE was not changed. Set the password in its database.url to the value of POSTGRES_PASSWORD in $COMPOSE_ENV_FILE.")
    fi
else
    if [[ -n "$db_password" ]]; then
        config_body="$(render_config "$db_password")"
        expected_url="postgres://tunneld:${db_password}@127.0.0.1:5432/tunneld?sslmode=disable"
        if [[ "$config_body" == *"url: \"${expected_url}\""* ]]; then
            echo "    installing $CONFIG_FILE with the database password (edit before starting)"
        else
            config_body="$(cat "$SRC_CONFIG")"
            notes+=("The config template has no 'database:' block with a 'url:' line, so the database password could not be written into $CONFIG_FILE. Set database.url yourself; the password is the value of POSTGRES_PASSWORD in $COMPOSE_ENV_FILE.")
        fi
        unset expected_url
    else
        config_body="$(cat "$SRC_CONFIG")"
        notes+=("$CONFIG_FILE was installed from the template without a database password. Set database.url to the credentials of the existing database.")
    fi
    # Written to a private temporary file first (mktemp creates it 0600) and
    # then moved into place, so the file never exists half-written or with a
    # wider mode.
    config_tmp="$(mktemp "$CONFIG_DIR/.config.yaml.XXXXXX")"
    printf '%s\n' "$config_body" > "$config_tmp"
    mv -f "$config_tmp" "$CONFIG_FILE"
    unset config_body
fi
refuse_link "$CONFIG_FILE" "the steps above this one were done"
chown root:"$TUNNELD_GROUP" "$CONFIG_FILE"
refuse_link "$CONFIG_FILE" "the steps above this one were done"
chmod 0640 "$CONFIG_FILE"

echo "==> env template"
# A dangling link is not -e: cat > would create the link's target.
refuse_link "$SERVICE_ENV_FILE" "the steps above this one were done"
if [[ ! -e "$SERVICE_ENV_FILE" ]]; then
    (
        umask 077
        cat > "$SERVICE_ENV_FILE" <<'EOF'
# Secrets for tunneld. systemd loads this file via EnvironmentFile=.
# Keep it root:tunneld with mode 0640.
#
# IONOS_API_KEY="public_prefix.private_secret"
EOF
    )
fi
refuse_link "$SERVICE_ENV_FILE" "the steps above this one were done"
chown root:"$TUNNELD_GROUP" "$SERVICE_ENV_FILE"
refuse_link "$SERVICE_ENV_FILE" "the steps above this one were done"
chmod 0640 "$SERVICE_ENV_FILE"

echo "==> firewall"
# Rules are only added (ufw skips rules that already exist); nothing is reset
# or removed, so rules you added yourself stay in place.
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw allow 7443/tcp >/dev/null
ufw --force enable >/dev/null
notes+=("Firewall: 22/tcp, 443/tcp and 7443/tcp are open (the defaults of listen.http_addr and listen.tunnel_addr). Tunnel port ranges are not opened automatically. If you enable them in $CONFIG_FILE, open them yourself, for example 'ufw allow 10000:20000/tcp' for tcp.port_range and 'ufw allow 30000:40000/udp' for udp.port_range.")

echo "==> docker compose (postgres)"
if [[ -n "$db_password" ]]; then
    (cd "$INSTALL_DIR" && POSTGRES_PASSWORD="$db_password" docker compose up -d postgres)
else
    echo "    skipped (see the notes at the end)"
fi
unset db_password

echo "==> systemd unit"
install -m 0644 -o root -g root "$SRC_UNIT" /etc/systemd/system/tunneld.service
systemctl daemon-reload
systemctl enable tunneld >/dev/null
if systemctl is-active --quiet tunneld; then
    notes+=("tunneld is running with the previous binary and unit. Apply the new ones with: systemctl restart tunneld")
fi

cat <<EOF

==> done.

Next steps:
  1. Edit $CONFIG_FILE
       - auth.csrf_key (run: $INSTALL_DIR/tunneld admin gen-csrf-key)
       - database.url (already set on a first install)
       - tls.acme.* (or tls.cert_file/key_file); tls.acme.cache_dir must be
         $STATE_DIR/certs, the only directory the service may write to
       - mail.*
       - frontend.public_base_url
  2. Edit $SERVICE_ENV_FILE, set IONOS_API_KEY if using ACME DNS-01.
  3. systemctl start tunneld
  4. systemctl status tunneld
  5. journalctl -u tunneld -f
  6. curl -s http://127.0.0.1:9090/_tunneld/metrics | head
EOF

if [[ ${#notes[@]} -gt 0 ]]; then
    echo
    echo "Notes:"
    for note in "${notes[@]}"; do
        echo "  * $note"
    done
fi
