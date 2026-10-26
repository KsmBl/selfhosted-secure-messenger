#!/usr/bin/env bash
# Restores an encrypted backup made by scripts/backup.sh (ssm-backup).
#
# Usage: scripts/restore.sh --identity KEYFILE [--yes] BACKUP.tar.age
#   --identity FILE   the age private key (ssm-backup-identity.txt)
#   --yes             do not ask for confirmation
#   -h, --help        show this help
#
# Steps: stop ssm-server, replace the database and the media files with the
# backup, then delete again everything the deletion journal lists (messages
# and accounts deleted after the backup was taken; FR-010), start ssm-server.
# The current /etc/ssm configuration is kept; the backup's copy is saved to
# /etc/ssm/restored-<date>/ for comparison.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

IDENTITY=""
YES=0
BACKUP=""
DB_NAME="ssm"
SERVICE_USER="ssm"
STATE_DIR="/var/lib/ssm"
CTL="/usr/local/bin/ssm-ctl"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --identity) IDENTITY="$2"; shift 2 ;;
        --yes) YES=1; shift ;;
        -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) die "unknown option: $1" ;;
        *) BACKUP="$1"; shift ;;
    esac
done

[[ -n "$IDENTITY" && -r "$IDENTITY" ]] || die "--identity KEYFILE is required and must be readable"
[[ -n "$BACKUP" && -r "$BACKUP" ]] || die "backup file not found: ${BACKUP:-<none>}"
need_cmd age
need_cmd systemctl

if [[ $YES -eq 0 ]]; then
    echo "This replaces the messenger database and media with $(basename "$BACKUP")."
    echo "Messages sent after the backup was taken are lost; deletions are re-applied."
    read -r -p "Type 'restore' to continue: " answer
    [[ "$answer" == "restore" ]] || die "aborted"
fi

work="$(as_root mktemp -d /var/tmp/ssm-restore.XXXXXX)"
trap 'as_root rm -rf "$work"' EXIT

log "Decrypting and unpacking"
age -d -i "$IDENTITY" "$BACKUP" | as_root tar -C "$work" -xf -
as_root test -f "$work/db.dump" || die "the backup contains no database dump"

log "Stopping ssm-server"
as_root systemctl stop ssm-server

log "Restoring database '$DB_NAME'"
as_postgres psql -q -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$DB_NAME' AND pid <> pg_backend_pid()" >/dev/null
as_postgres dropdb --if-exists "$DB_NAME"
as_postgres createdb -O "$SERVICE_USER" "$DB_NAME"
as_postgres psql -q -d "$DB_NAME" -c "DO \$\$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ssm_audit') THEN CREATE ROLE ssm_audit NOLOGIN; END IF;
END \$\$;"
as_root chmod 755 "$work"
as_root chmod 644 "$work/db.dump"
as_postgres pg_restore --exit-on-error --dbname="$DB_NAME" "$work/db.dump"

log "Restoring media files"
as_root rm -rf "$STATE_DIR/media.old"
if as_root test -d "$STATE_DIR/media"; then
    as_root mv "$STATE_DIR/media" "$STATE_DIR/media.old"
fi
if as_root test -d "$work/media"; then
    as_root mv "$work/media" "$STATE_DIR/media"
else
    as_root install -d "$STATE_DIR/media"
fi
as_root chown -R "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR/media"
as_root chmod 700 "$STATE_DIR/media"
as_root rm -rf "$STATE_DIR/media.old"

if as_root test -d "$work/ssm"; then
    saved="/etc/ssm/restored-$(date +%Y%m%d-%H%M%S)"
    as_root mv "$work/ssm" "$saved"
    as_root chmod -R go-rwx "$saved"
    log "Configuration from the backup saved to $saved (current /etc/ssm kept)"
fi

log "Re-applying deletions made after the backup"
if [[ -x "$CTL" ]]; then
    as_root "$CTL" replay-deletions
else
    warn "$CTL not found; run 'ssm-admin replay-deletions' as $SERVICE_USER before users connect"
fi

log "Starting ssm-server"
as_root systemctl start ssm-server
log "Restore complete"
