#!/usr/bin/env bash
# Builds and installs ssm-server and ssm-admin as a systemd service with a
# local PostgreSQL database (peer authentication over the Unix socket, so no
# database password is stored anywhere).
#
# Usage: scripts/install-server.sh [options]
#   --bind ADDR        listen address (default 127.0.0.1:8080; put a TLS
#                      reverse proxy such as Caddy or nginx in front)
#   --prefix DIR       binary install prefix (default /usr/local)
#   --skip-postgres    do not install/initialize PostgreSQL (database must exist)
#   --no-start         install everything but do not (re)start the service
#   -h, --help         show this help

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BIND="127.0.0.1:8080"
PREFIX="/usr/local"
SKIP_POSTGRES=0
START=1
SERVICE_USER="ssm"
DB_NAME="ssm"
CONFIG_DIR="/etc/ssm"
UNIT="/etc/systemd/system/ssm-server.service"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bind) BIND="$2"; shift 2 ;;
        --prefix) PREFIX="$2"; shift 2 ;;
        --skip-postgres) SKIP_POSTGRES=1; shift ;;
        --no-start) START=0; shift ;;
        -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] && die "run as a normal user; the script uses sudo for privileged steps (cargo must not run as root)"
need_cargo
need_cmd systemctl "a systemd-based distribution is required"

log "Building release binaries"
cargo build --release --locked --manifest-path "$ROOT_DIR/Cargo.toml" -p ssm-server --bins

# Runs a command as the postgres system user. runuser instead of su: Arch
# (and others) lock that account as expired, which su refuses.
as_postgres() {
    (cd / && as_root runuser -u postgres -- "$@")
}

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

# Wrappers that run the management tools as the service user with its
# configuration (peer authentication needs the 'ssm' system user).
for tool in tui admin; do
    if [[ $tool == tui ]]; then cmd="$PREFIX/bin/ssm-server tui"; else cmd="$PREFIX/bin/ssm-admin"; fi
    as_root tee "$PREFIX/bin/ssm-$tool" >/dev/null <<WRAPPER
#!/bin/sh
# Runs the messenger management tool as '$SERVICE_USER' (start with sudo).
[ "\$(id -u)" -eq 0 ] || exec sudo "\$0" "\$@"
exec runuser -u $SERVICE_USER -- sh -c 'set -a; . $CONFIG_DIR/ssm.env; set +a; exec "\$0" "\$@"' $cmd "\$@"
WRAPPER
    as_root chmod 755 "$PREFIX/bin/ssm-$tool"
done

log "Writing $CONFIG_DIR/ssm.env"
as_root install -d -m 750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
if ! as_root test -f "$CONFIG_DIR/ssm.env"; then
    as_root tee "$CONFIG_DIR/ssm.env" >/dev/null <<EOF
SSM_DATABASE_URL=postgres:///$DB_NAME?host=/run/postgresql
SSM_BIND=$BIND
RUST_LOG=info
EOF
    as_root chown root:"$SERVICE_USER" "$CONFIG_DIR/ssm.env"
    as_root chmod 640 "$CONFIG_DIR/ssm.env"
else
    warn "$CONFIG_DIR/ssm.env exists, leaving it unchanged"
fi

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
    if curl -fsS "http://$BIND/healthz" >/dev/null 2>&1; then
        log "ssm-server is healthy on $BIND"
    else
        warn "health check failed; see: journalctl -u ssm-server"
    fi
fi

cat <<EOF

Next steps:
  1. Make the server reachable over HTTPS: put a TLS reverse proxy in front of
     http://$BIND, e.g. Caddy with a domain:  messenger.example.org { reverse_proxy $BIND }
  2. Manage the server:            sudo ssm-tui
     (create accounts with invite codes, approve devices, delete jobs, audit log)
  3. Command-line administration:  sudo ssm-admin --help
EOF
