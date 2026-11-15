#!/bin/bash
# Backups and destinations are application data. Do their I/O as that user.
set -eu -o pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
fail() { printf '[restore] FAIL: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] && [ "$#" -eq 2 ] || fail "usage: $0 <env|db|delete> <backup-dir>"
INSTALL_DIR=
SERVICE_USER=
. /etc/anetbbs.install
[ -d "$INSTALL_DIR" ] && [ -n "$SERVICE_USER" ] && [ "$SERVICE_USER" != root ] ||
    fail "missing or invalid installation information"

KIND="$1"
BACKUP="$2"
BACKUP_ROOT="$INSTALL_DIR/data/backups"
NAME="${BACKUP#"$BACKUP_ROOT/"}"
[[ "$NAME" =~ ^anetbbs-backup-[0-9]{14}$ ]] || fail "invalid backup directory"

# Stop/start must happen out of the web service's own cgroup.
if [ "$KIND" = db ] && [ "${ANETBBS_RESTORE_DETACHED:-}" != 1 ]; then
    exec systemd-run --unit=anetbbs-restore-db --collect --quiet --wait \
        --setenv=ANETBBS_RESTORE_DETACHED=1 "$0" "$@"
fi

case "$KIND" in
    delete)
        runuser -u "$SERVICE_USER" -- /bin/rm -rf -- "$BACKUP_ROOT/$NAME"
        ;;
    env|db)
        RESTART=()
        if [ "$KIND" = db ]; then
            # Stop all writers before replacing SQLite and clearing its sidecars.
            for unit in anetbbs-web anetbbs anetbbs-binkp anetbbs-finger; do
                if systemctl is-active --quiet "$unit"; then RESTART+=("$unit"); fi
            done
            restart_services() {
                if [ "${#RESTART[@]}" -gt 0 ]; then systemctl start "${RESTART[@]}"; fi
            }
            trap restart_services EXIT
            if [ "${#RESTART[@]}" -gt 0 ]; then systemctl stop "${RESTART[@]}"; fi
        fi
        runuser -u "$SERVICE_USER" -- /usr/bin/python3 -I - "$INSTALL_DIR" "$NAME" "$KIND" <<'PY'
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

root, name, kind = sys.argv[1:]
root = Path(root)
backup = root / 'data' / 'backups' / name
source, destination = ((backup / '.env.bak', root / '.env') if kind == 'env'
                       else (backup / 'anetbbs.db.bak', root / 'data' / 'anetbbs.db'))
if backup.resolve() != backup or destination.parent.resolve() != destination.parent:
    raise SystemExit('backup and target parent must be inside the installation')
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd, 'rb') as src:
    if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
        raise SystemExit('backup source must be a regular file')
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as staged:
        try:
            shutil.copyfileobj(src, staged)
            staged.flush()
            os.fsync(staged.fileno())
            os.replace(staged.name, destination)
        finally:
            Path(staged.name).unlink(missing_ok=True)
if kind == 'db':
    for suffix in ('-wal', '-shm', '-journal'):
        Path(str(destination) + suffix).unlink(missing_ok=True)
PY
        printf '[restore] %s restored\n' "$KIND"
        ;;
    *) fail "unknown restore operation" ;;
esac
