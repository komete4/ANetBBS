#!/bin/bash
# The web service can select a release, while root defines which sources it trusts.
set -eu -o pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

log()  { printf '[upgrade] %s\n' "$*"; }
fail() { printf '[upgrade] FAIL: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ "$#" -eq 3 ] || fail "usage: $0 <version> <url|local> <sha256>"
VERSION="$1"
URL="$2"
SHA="${3,,}"
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+([ab][0-9]+\.[0-9]+|\.[0-9]+)$ ]] ||
   ! [[ "$SHA" =~ ^[0-9a-f]{64}$ ]]; then
    fail "invalid release version or SHA-256"
fi

INSTALL_DIR=
SERVICE_USER=
REGISTRY_URL=
# This file is installed in /etc by the root-run installer/updater.
. /etc/anetbbs.install
[ -d "$INSTALL_DIR" ] && [ -n "$SERVICE_USER" ] && [ "$SERVICE_USER" != root ] ||
    fail "missing or invalid installation information"

if [ -z "${ANETBBS_UPGRADE_DETACHED:-}" ]; then
    exec systemd-run --unit=anetbbs-upgrade --collect --quiet --wait         --setenv=ANETBBS_UPGRADE_DETACHED=1 "$0" "$@"
fi

# Keep detached progress visible while opening the writable log as its owner.
if [ "${ANETBBS_UPGRADE_DETACHED:-}" = 1 ]; then
    exec > >(runuser -u "$SERVICE_USER" -- tee -a "$INSTALL_DIR/data/anetbbs_upgrade.log") 2>&1
fi

TMP=$(mktemp -d -t anetbbs-upgrade-XXXXXX)
trap 'rm -rf -- "$TMP"' EXIT
TARBALL="$TMP/ANetBBS-$VERSION.tar.gz"
if [ "$URL" = local ]; then
    # Only a root administrator can stage rollback releases in this directory.
    SOURCE="/usr/local/libexec/anetbbs/releases/ANetBBS-$VERSION.tar.gz"
    [ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] || fail "rollback release is not staged by the system administrator"
    cp -- "$SOURCE" "$TARBALL"
else
    REGISTRY_URL="${REGISTRY_URL:-https://bbs.a-net.fyi}"
    curl --disable --fail --silent --show-error --proto '=https' --noproxy '*'         --max-filesize 65536 --max-time 20 -o "$TMP/manifest.json"         "${REGISTRY_URL%/}/api/releases/latest" || fail "cannot fetch trusted release metadata"
    /usr/bin/python3 -I - "$TMP/manifest.json" "$REGISTRY_URL" "$VERSION" "$URL" "$SHA" <<'PY'
import json
import sys
from urllib.parse import urlsplit

manifest, registry, version, url, checksum = sys.argv[1:]
with open(manifest, 'rb') as source:
    payload = json.loads(source.read(65537))
origin = urlsplit(registry)
target = urlsplit(url)
if (origin.scheme != 'https' or not origin.hostname
        or origin.username is not None or origin.query or origin.fragment
        or target.scheme != 'https' or target.netloc != origin.netloc
        or target.username is not None or target.query or target.fragment
        or not target.path.endswith('/ANetBBS-' + version + '.tar.gz')
        or payload.get('version') != version or payload.get('url') != url
        or str(payload.get('sha256', '')).lower() != checksum):
    raise SystemExit('requested release does not match the trusted registry')
PY
    curl --disable --fail --silent --show-error --proto '=https' --noproxy '*'         --connect-timeout 15 --max-filesize 536870912 --max-time 600 -o "$TARBALL" -- "$URL" ||
        fail "release download failed"
fi

ACTUAL=$(sha256sum "$TARBALL" | awk '{print $1}')
[ "$ACTUAL" = "$SHA" ] || fail "release SHA-256 mismatch"
mkdir -m 0755 "$TMP/extracted"
tar -xzf "$TARBALL" -C "$TMP/extracted" --no-same-owner --no-same-permissions
INNER="$TMP/extracted/ANetBBS-$VERSION"
[ -d "$INNER" ] && [ ! -L "$INNER" ] && [ -f "$INNER/update.sh" ] &&
    [ ! -L "$INNER/update.sh" ] || fail "invalid release layout"
# Keep the privileged boundary in place when selecting older releases.
grep -Fq 'PRIVILEGED_DIR=/usr/local/libexec/anetbbs' "$INNER/update.sh" ||
    fail "this release predates privileged update hardening"
# update.sh also copies public release files as the service user.
chmod 0711 "$TMP"
chmod 0755 "$INNER"
cd "$INNER"
log "Installing $VERSION"
ANETBBS_UPGRADE_RUN=1 /bin/bash update.sh --install-dir "$INSTALL_DIR"
log "Upgrade to $VERSION complete"
