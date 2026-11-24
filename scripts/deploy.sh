#!/usr/bin/env bash
# deploy.sh — pull a released tunneld binary, verify checksum, swap, restart.
#
# Usage:  sudo ./deploy.sh vX.Y.Z
#
# Assumes install-server.sh has already been run (systemd unit exists,
# /opt/tunneld/ is owned by root). Exits non-zero when the download, the
# checksum or the restart fails, or when the service does not stay up.
#
# The checksum file comes from the same release as the archive: it protects
# against a damaged download, not against a tampered release. Releases are
# not signed yet.

set -euo pipefail

TAG="${1:?usage: deploy.sh vX.Y.Z}"
# GoReleaser strips the `v` prefix from {{.Version}}, so the archive name uses
# the bare semver while the release URL path uses the full tag.
VERSION="${TAG#v}"
REPO="${REPO:-Bazinga0o0/tunnel}"
SERVICE="tunneld"
# How long the service has to stay active after the restart.
readonly START_CHECK_SECONDS=15

if [[ $EUID -ne 0 ]]; then
    echo "error: deploy.sh must run as root (use sudo)" >&2
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

# fetch downloads one release asset into the current directory. HTTPS with
# TLS 1.2 or newer only, also for the redirect to the asset storage host.
fetch() {
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fLOsS "$1"
}

archive="tunneld-${VERSION}-linux-amd64.tar.gz"
echo "==> downloading $archive"
fetch "https://github.com/${REPO}/releases/download/${TAG}/${archive}"
fetch "https://github.com/${REPO}/releases/download/${TAG}/checksums.txt"

echo "==> verifying checksum"
expected_line="$(grep " ${archive}\$" checksums.txt || true)"
if [[ -z "$expected_line" ]]; then
    echo "error: checksum for $archive not found in checksums.txt" >&2
    exit 1
fi
echo "$expected_line" | sha256sum -c -

echo "==> extracting"
tar xzf "$archive"

echo "==> installing to /opt/tunneld/tunneld"
install -m 0755 -o root -g root tunneld /opt/tunneld/tunneld

echo "==> restarting ${SERVICE}.service"
systemctl restart "$SERVICE"

# A unit of Type=simple counts as started as soon as the process exists. A
# binary that exits right away (bad config, database unreachable) drops out of
# the active state while systemd waits to restart it, so watch it for a while.
echo "==> checking that ${SERVICE}.service stays up (${START_CHECK_SECONDS}s)"
for ((i = 0; i < START_CHECK_SECONDS; i++)); do
    sleep 1
    if ! systemctl is-active --quiet "$SERVICE"; then
        echo "error: ${SERVICE}.service did not stay up after the restart" >&2
        systemctl status "$SERVICE" --no-pager --lines=20 >&2 || true
        echo "error: ${TAG} is installed but not running; see: journalctl -u ${SERVICE} -e" >&2
        exit 1
    fi
done
systemctl status "$SERVICE" --no-pager --lines=0 || true

echo "==> deployed ${TAG}"
