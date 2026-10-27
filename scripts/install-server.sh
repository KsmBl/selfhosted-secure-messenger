#!/usr/bin/env bash
# Builds and installs ssm-server and ssm-admin as a systemd service with a
# local PostgreSQL database (peer authentication over the Unix socket, so no
# database password is stored anywhere).
#
# Usage: scripts/install-server.sh [options]
#   --bind ADDR        listen address (default 127.0.0.1:8080; put a TLS
#                      reverse proxy such as Caddy or nginx in front)
#   --lan              listen on all interfaces (0.0.0.0:8080) so other devices
#                      in the local network can connect via http://<this-ip>:8080;
#                      clients from public internet addresses are still refused
#   --prefix DIR       binary install prefix (default /usr/local)
#   --skip-postgres    do not install/initialize PostgreSQL (database must exist)
#   --no-start         install everything but do not (re)start the service
#   --skip-build       use binaries already built in target/release (then the
#                      script may run as root, e.g. sudo scripts/install-server.sh --skip-build)
#   -h, --help         show this help

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BIND="127.0.0.1:8080"
BIND_GIVEN=0
PREFIX="/usr/local"
SKIP_POSTGRES=0
START=1
SKIP_BUILD=0
SERVICE_USER="ssm"
DB_NAME="ssm"
CONFIG_DIR="/etc/ssm"
UNIT="/etc/systemd/system/ssm-server.service"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bind) BIND="$2"; BIND_GIVEN=1; shift 2 ;;
        --lan) BIND="0.0.0.0:8080"; BIND_GIVEN=1; shift ;;
        --prefix) PREFIX="$2"; shift 2 ;;
        --skip-postgres) SKIP_POSTGRES=1; shift ;;
        --no-start) START=0; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

need_cmd systemctl "a systemd-based distribution is required"
if [[ $SKIP_BUILD -eq 1 ]]; then
    for bin in ssm-server ssm-admin; do
        [[ -x "$ROOT_DIR/target/release/$bin" ]] || die "target/release/$bin missing; build with: cargo build --release -p ssm-server --bins"
    done
else
    [[ $EUID -eq 0 ]] && die "run as a normal user; the script uses sudo for privileged steps (cargo must not run as root), or build first and use --skip-build"
    need_cargo
    log "Building release binaries"
    cargo build --release --locked --manifest-path "$ROOT_DIR/Cargo.toml" -p ssm-server --bins
fi

setup_postgres() {
    if ! command -v pg_ctl >/dev/null 2>&1 && ! command -v postgres >/dev/null 2>&1 \
        && ! ls /usr/lib/postgresql/*/bin/postgres >/dev/null 2>&1; then
        log "Installing PostgreSQL"
        install_packages postgresql postgresql postgresql-server postgresql-server
    fi

    case "$(detect_pkg_manager)" in
        pacman)
            if ! as_root test -f /var/lib/postgres/data/PG_VERSION; then
                log "Initializing PostgreSQL data directory"
                as_postgres initdb --locale=C.UTF-8 --encoding=UTF8 -D /var/lib/postgres/data
            fi ;;
        dnf)
            if ! as_root test -f /var/lib/pgsql/data/PG_VERSION; then
                log "Initializing PostgreSQL data directory"
                as_root postgresql-setup --initdb
            fi ;;
    esac
    as_root systemctl enable --now postgresql

    log "Creating database role and database '$DB_NAME'"
    if ! as_postgres psql -qtAc "SELECT 1 FROM pg_roles WHERE rolname = '$SERVICE_USER'" | grep -q 1; then
        as_postgres createuser "$SERVICE_USER"
    fi
    if ! as_postgres psql -qtAc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1; then
        as_postgres createdb -O "$SERVICE_USER" "$DB_NAME"
    fi
}

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    log "Creating system user '$SERVICE_USER'"
    as_root useradd --system --home-dir /var/lib/ssm --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

[[ $SKIP_POSTGRES -eq 1 ]] || setup_postgres

log "Installing binaries to $PREFIX/bin"
as_root install -Dm755 "$ROOT_DIR/target/release/ssm-server" "$PREFIX/bin/ssm-server"
as_root install -Dm755 "$ROOT_DIR/target/release/ssm-admin" "$PREFIX/bin/ssm-admin"

# ssm-tui (running as the service user) may change where the server listens
# (Server tab) only through this root-owned helper; the sudo rule allows
# nothing else.
log "Installing ssm-netconfig (Server tab in ssm-tui: port, LAN access)"
as_root install -Dm755 -o root -g root "$ROOT_DIR/scripts/ssm-netconfig" /usr/local/sbin/ssm-netconfig
sudo_rule="$(mktemp)"
echo "$SERVICE_USER ALL=(root) NOPASSWD: /usr/local/sbin/ssm-netconfig" > "$sudo_rule"
if as_root visudo -cqf "$sudo_rule"; then
    as_root install -m 440 -o root -g root "$sudo_rule" /etc/sudoers.d/ssm-netconfig
else
    warn "could not validate the sudo rule; the Server tab in ssm-tui cannot change settings"
fi
rm -f "$sudo_rule"

# Wrappers that run the management tools as the service user with its
# configuration (peer authentication needs the 'ssm' system user).
# Names must differ from the real binaries (ssm-server, ssm-admin).
for tool in tui ctl; do
    if [[ $tool == tui ]]; then cmd="$PREFIX/bin/ssm-server tui"; else cmd="$PREFIX/bin/ssm-admin"; fi
    as_root tee "$PREFIX/bin/ssm-$tool" >/dev/null <<WRAPPER
#!/bin/sh
# Runs the messenger management tool as '$SERVICE_USER' (start with sudo).
[ "\$(id -u)" -eq 0 ] || exec sudo "\$0" "\$@"
# STATE_DIRECTORY as under systemd: media files and the deletion journal.
exec runuser -u $SERVICE_USER -- env STATE_DIRECTORY=/var/lib/ssm sh -c 'set -a; . $CONFIG_DIR/ssm.env; set +a; exec "\$0" "\$@"' $cmd "\$@"
WRAPPER
    as_root chmod 755 "$PREFIX/bin/ssm-$tool"
done

log "Writing $CONFIG_DIR/ssm.env"
as_root install -d -m 750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
if ! as_root test -f "$CONFIG_DIR/ssm.env"; then
    as_root tee "$CONFIG_DIR/ssm.env" >/dev/null <<EOF
SSM_DATABASE_URL=postgres://$SERVICE_USER@localhost/$DB_NAME?host=/run/postgresql
SSM_BIND=$BIND
RUST_LOG=info
EOF
    as_root chown root:"$SERVICE_USER" "$CONFIG_DIR/ssm.env"
    as_root chmod 640 "$CONFIG_DIR/ssm.env"
elif [[ $BIND_GIVEN -eq 1 ]]; then
    log "Setting SSM_BIND=$BIND in the existing $CONFIG_DIR/ssm.env"
    if as_root grep -q '^SSM_BIND=' "$CONFIG_DIR/ssm.env"; then
        as_root sed -i "s|^SSM_BIND=.*|SSM_BIND=$BIND|" "$CONFIG_DIR/ssm.env"
    else
        echo "SSM_BIND=$BIND" | as_root tee -a "$CONFIG_DIR/ssm.env" >/dev/null
    fi
else
    warn "$CONFIG_DIR/ssm.env exists, leaving it unchanged (pass --bind/--lan to change the address)"
fi
BIND="$(as_root sed -n 's/^SSM_BIND=//p' "$CONFIG_DIR/ssm.env" | tail -1)"
PORT="${BIND##*:}"
LOCAL_URL="http://127.0.0.1:$PORT"

log "Installing systemd unit $UNIT"
as_root tee "$UNIT" >/dev/null <<EOF
[Unit]
Description=Self-hosted secure messenger server
After=network-online.target postgresql.service
Wants=network-online.target postgresql.service

[Service]
User=$SERVICE_USER
Group=$SERVICE_USER
EnvironmentFile=$CONFIG_DIR/ssm.env
ExecStart=$PREFIX/bin/ssm-server
Restart=on-failure
RestartSec=5

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
StateDirectory=ssm
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
as_root systemctl daemon-reload

if [[ $START -eq 1 ]]; then
    log "Starting ssm-server"
    as_root systemctl enable ssm-server
    as_root systemctl restart ssm-server
    sleep 2
    if curl -fsS "$LOCAL_URL/healthz" >/dev/null 2>&1; then
        log "ssm-server is healthy on $BIND"
    else
        warn "health check failed; see: journalctl -u ssm-server"
    fi
fi

# The audit log is append-only by trigger; additionally it is owned by a
# separate role, so the service role can only read and insert and cannot
# drop the trigger or alter the table (TDD §10.4). Runs after the server
# created the table. Future migrations touching this table must be applied
# by the database administrator.
protect_audit_log() {
    local i
    for i in $(seq 1 15); do
        as_postgres psql -d "$DB_NAME" -qtAc "SELECT to_regclass('admin_audit_events')" | grep -q admin_audit_events && break
        sleep 1
    done
    if ! as_postgres psql -d "$DB_NAME" -qtAc "SELECT to_regclass('admin_audit_events')" | grep -q admin_audit_events; then
        warn "audit table not found yet; rerun this script once ssm-server has started"
        return
    fi
    log "Protecting the audit log (owner role ssm_audit; $SERVICE_USER may only SELECT/INSERT)"
    as_postgres psql -d "$DB_NAME" -v ON_ERROR_STOP=1 -q <<SQL
DO \$\$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ssm_audit') THEN
        CREATE ROLE ssm_audit NOLOGIN;
    END IF;
END \$\$;
ALTER TABLE admin_audit_events OWNER TO ssm_audit;
ALTER FUNCTION admin_audit_events_append_only() OWNER TO ssm_audit;
REVOKE ALL ON admin_audit_events FROM $SERVICE_USER;
GRANT SELECT, INSERT ON admin_audit_events TO $SERVICE_USER;
GRANT USAGE ON SEQUENCE admin_audit_events_id_seq TO $SERVICE_USER;
SQL
}
if [[ $START -eq 1 && $SKIP_POSTGRES -eq 0 ]]; then
    protect_audit_log
fi

if [[ "$BIND" == 0.0.0.0:* || "$BIND" == "[::]:"* ]]; then
    lan_ips="$(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]}')"
    echo
    log "Reachable in the local network (plain HTTP; message contents stay end-to-end encrypted):"
    for ip in $lan_ips; do echo "      http://$ip:$PORT"; done
    echo "    On this computer: $LOCAL_URL. A firewall must allow TCP port $PORT from the LAN."
fi

cat <<EOF

Next steps:
  1. HTTPS for a domain (Caddy, Let's Encrypt):
         scripts/setup-https.sh --domain messenger.example.org --email you@example.org
     (only this computer uses the server? then $LOCAL_URL is enough)
  2. Daily encrypted backups:      scripts/backup.sh --install
  3. Manage the server:            sudo ssm-tui
     (create accounts with invite codes, approve devices, delete jobs, audit log)
  4. Command-line administration:  sudo ssm-ctl --help   (runs ssm-admin as '$SERVICE_USER')
EOF
