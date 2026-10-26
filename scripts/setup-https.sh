#!/usr/bin/env bash
# Puts Caddy in front of ssm-server: HTTPS with an automatic Let's Encrypt
# certificate for your domain, HTTP redirected to HTTPS, WebSockets passed
# through. Run after scripts/install-server.sh.
#
# Usage: scripts/setup-https.sh --domain messenger.example.org [options]
#   --domain NAME    public DNS name pointing to this server (required)
#   --email ADDR     contact address for Let's Encrypt (recommended)
#   --backend ADDR   ssm-server address (default: SSM_BIND from /etc/ssm/ssm.env,
#                    else 127.0.0.1:8080)
#   -h, --help       show this help
#
# Requirements: the domain's A/AAAA record points here and ports 80 and 443
# are reachable from the internet (router port forwarding, firewall).
# Afterwards clients use https://<domain> as server address.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DOMAIN=""
EMAIL=""
BACKEND=""
SITE_FILE="/etc/caddy/ssm.caddy"
CADDYFILE="/etc/caddy/Caddyfile"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --email) EMAIL="$2"; shift 2 ;;
        --backend) BACKEND="$2"; shift 2 ;;
        -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ -n "$DOMAIN" ]] || die "--domain is required (see --help)"
[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && "$DOMAIN" == *.* ]] || die "not a valid domain name: $DOMAIN"
[[ -z "$EMAIL" || "$EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+$ ]] || die "not a valid e-mail address: $EMAIL"
need_cmd systemctl

if [[ -z "$BACKEND" ]]; then
    BACKEND="$(as_root sed -n 's/^SSM_BIND=//p' /etc/ssm/ssm.env 2>/dev/null | tail -1)"
    BACKEND="${BACKEND:-127.0.0.1:8080}"
fi
# Listening on all interfaces (--lan): the proxy still connects locally.
BACKEND="${BACKEND/#0.0.0.0:/127.0.0.1:}"
[[ "$BACKEND" =~ ^[0-9A-Za-z.:\[\]-]+:[0-9]+$ ]] || die "not a valid backend address: $BACKEND"

if ! command -v caddy >/dev/null 2>&1; then
    log "Installing Caddy"
    install_packages caddy caddy caddy caddy
fi

# Quick DNS sanity check (warning only: the record may be fine for others).
if command -v getent >/dev/null 2>&1 && ! getent ahosts "$DOMAIN" >/dev/null 2>&1; then
    warn "$DOMAIN does not resolve yet; Caddy will retry obtaining the certificate"
fi

log "Writing $SITE_FILE"
as_root install -d -m 755 /etc/caddy
as_root tee "$SITE_FILE" >/dev/null <<EOF
# Secure Messenger (written by scripts/setup-https.sh)
$DOMAIN {
${EMAIL:+	tls $EMAIL
}	encode zstd gzip
	header {
		Strict-Transport-Security "max-age=31536000"
		X-Content-Type-Options nosniff
		Referrer-Policy no-referrer
		-Server
	}
	# Media uploads are up to 64 MiB (SSM_MAX_MEDIA_MB).
	request_body {
		max_size 80MB
	}
	reverse_proxy $BACKEND
}
EOF

if ! as_root test -f "$CADDYFILE"; then
    as_root tee "$CADDYFILE" >/dev/null <<EOF
import $SITE_FILE
EOF
elif ! as_root grep -qxF "import $SITE_FILE" "$CADDYFILE"; then
    log "Adding 'import $SITE_FILE' to $CADDYFILE"
    printf '\nimport %s\n' "$SITE_FILE" | as_root tee -a "$CADDYFILE" >/dev/null
fi

log "Checking the configuration"
as_root caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null

log "Starting Caddy"
as_root systemctl enable caddy >/dev/null 2>&1 || true
as_root systemctl reload-or-restart caddy

if command -v curl >/dev/null 2>&1; then
    log "Waiting for the certificate (up to 60 s)"
    for _ in $(seq 1 30); do
        if curl -fsS "https://$DOMAIN/healthz" >/dev/null 2>&1; then
            log "https://$DOMAIN is up"
            break
        fi
        sleep 2
    done
    curl -fsS "https://$DOMAIN/healthz" >/dev/null 2>&1 \
        || warn "https://$DOMAIN is not reachable yet; check DNS, ports 80/443 and: journalctl -u caddy"
fi

cat <<EOF

Clients now use the server address:  https://$DOMAIN
Keep ssm-server bound to $BACKEND (local only); Caddy is the only public entry.
EOF
