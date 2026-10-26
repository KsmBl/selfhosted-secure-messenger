#!/usr/bin/env bash
# Encrypted backups of the messenger server: database (pg_dump), media files
# and /etc/ssm, encrypted with age to a public key, so the backup files and
# the machine they are copied to never hold a decryption key.
#
# Setup (once, as a normal user with sudo):
#   scripts/backup.sh --install [--recipient AGE_PUBLIC_KEY] [--dir DIR] [--keep-days N]
#     Installs /usr/local/sbin/ssm-backup and a daily systemd timer. Without
#     --recipient a key pair is generated: the private key is written to
#     ./ssm-backup-identity.txt - move it OFF the server (password manager,
#     USB stick); it is needed for restores only.
#
# Run a backup now:   sudo ssm-backup
# Restore:            scripts/restore.sh --identity KEYFILE BACKUP.tar.age
#
# Defaults: /var/backups/ssm, kept for SSM_BACKUP_RETENTION_DAYS (30) days -
# the server reports deletions as fully purged only after that period.
# Copy the files to another machine as well (e.g. rsync in a cron job).
# The deletion journal is deliberately not part of the backup.

set -euo pipefail

CONFIG="/etc/ssm/backup.env"
SSM_ENV="/etc/ssm/ssm.env"
STATE_DIR="/var/lib/ssm"
DB_NAME="ssm"
INSTALLED="/usr/local/sbin/ssm-backup"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
as_root() { if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

ARGS=("$@")
INSTALL=0
RECIPIENT=""
DIR=""
KEEP=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install) INSTALL=1; shift ;;
        --recipient) RECIPIENT="$2"; shift 2 ;;
        --dir) DIR="$2"; shift 2 ;;
        --keep-days) KEEP="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

retention_from_server() {
    local days
    days="$(as_root sed -n 's/^SSM_BACKUP_RETENTION_DAYS=//p' "$SSM_ENV" 2>/dev/null | tail -1)"
    echo "${days:-30}"
}

install_age() {
    command -v age >/dev/null 2>&1 && return
    log "Installing age"
    if command -v pacman >/dev/null; then as_root pacman -S --needed --noconfirm age
    elif command -v apt-get >/dev/null; then as_root apt-get install -y age
    elif command -v dnf >/dev/null; then as_root dnf install -y age
    elif command -v zypper >/dev/null; then as_root zypper --non-interactive install age
    else die "install 'age' (https://age-encryption.org) and run again"; fi
}

if [[ $INSTALL -eq 1 ]]; then
    [[ $EUID -eq 0 ]] && die "run --install as a normal user (it uses sudo); the key file goes to the current directory"
    install_age
    if [[ -z "$RECIPIENT" ]]; then
        [[ -e ssm-backup-identity.txt ]] && die "ssm-backup-identity.txt exists; pass its public key with --recipient"
        (umask 077 && age-keygen -o ssm-backup-identity.txt 2>/dev/null)
        RECIPIENT="$(age-keygen -y ssm-backup-identity.txt)"
        warn "private backup key written to $PWD/ssm-backup-identity.txt - move it off this server now; without it backups cannot be restored"
    fi
    [[ "$RECIPIENT" =~ ^age1[0-9a-z]{58}$ ]] || die "not an age public key: $RECIPIENT"
    DIR="${DIR:-/var/backups/ssm}"
    KEEP="${KEEP:-$(retention_from_server)}"
    [[ "$KEEP" =~ ^[0-9]+$ ]] || die "--keep-days must be a number"

    log "Installing $INSTALLED"
    as_root install -Dm755 "${BASH_SOURCE[0]}" "$INSTALLED"
    as_root install -d -m 750 /etc/ssm
    printf 'BACKUP_DIR=%s\nBACKUP_KEEP_DAYS=%s\nBACKUP_RECIPIENT=%s\n' "$DIR" "$KEEP" "$RECIPIENT" \
        | as_root tee "$CONFIG" >/dev/null
    as_root chmod 640 "$CONFIG"

    log "Installing systemd timer ssm-backup.timer (daily)"
    as_root tee /etc/systemd/system/ssm-backup.service >/dev/null <<EOF
[Unit]
Description=Encrypted backup of the secure messenger server
After=postgresql.service

[Service]
Type=oneshot
ExecStart=$INSTALLED
Nice=10
IOSchedulingClass=idle
PrivateTmp=yes
EOF
    as_root tee /etc/systemd/system/ssm-backup.timer >/dev/null <<EOF
[Unit]
Description=Daily encrypted backup of the secure messenger server

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    as_root systemctl daemon-reload
    as_root systemctl enable --now ssm-backup.timer
    log "Running a first backup"
    as_root "$INSTALLED"
    cat <<EOF

Backups: $DIR (kept $KEEP days), daily via ssm-backup.timer.
Public key: $RECIPIENT
Test a restore regularly (scripts/restore.sh) and copy $DIR off this machine.
EOF
    exit 0
fi

# --- run a backup (root) ---
[[ $EUID -eq 0 ]] || exec sudo "$0" "${ARGS[@]}"
[[ -f "$CONFIG" ]] && source "$CONFIG"
DIR="${DIR:-${BACKUP_DIR:-/var/backups/ssm}}"
KEEP="${KEEP:-${BACKUP_KEEP_DAYS:-$(retention_from_server)}}"
RECIPIENT="${RECIPIENT:-${BACKUP_RECIPIENT:-}}"
[[ -n "$RECIPIENT" ]] || die "no age recipient configured; run: scripts/backup.sh --install"
command -v age >/dev/null || die "'age' is not installed"

install -d -m 700 "$DIR"
work="$(mktemp -d /var/tmp/ssm-backup.XXXXXX)"
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"

log "Dumping database '$DB_NAME'"
(cd / && runuser -u postgres -- pg_dump --format=custom --dbname="$DB_NAME") > "$work/db.dump"

name="ssm-$(date +%Y%m%d-%H%M%S).tar.age"
log "Writing $DIR/$name"
parts=(-C "$work" db.dump)
[[ -d "$STATE_DIR/media" ]] && parts+=(-C "$STATE_DIR" media)
[[ -d /etc/ssm ]] && parts+=(-C /etc --exclude=ssm/backup.env ssm)
tar -cf - "${parts[@]}" | age -r "$RECIPIENT" > "$DIR/$name.part"
mv "$DIR/$name.part" "$DIR/$name"

find "$DIR" -maxdepth 1 -name 'ssm-*.tar.age' -mtime +"$KEEP" -print -delete | sed 's/^/removed old backup: /'
find "$DIR" -maxdepth 1 -name 'ssm-*.tar.age.part' -mmin +60 -delete
log "Backup done: $DIR/$name ($(du -h "$DIR/$name" | cut -f1))"
