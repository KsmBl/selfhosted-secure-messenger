#!/usr/bin/env bash
# Builds and installs the GTK4 Linux client (crate `ssm-linux` in clients/linux).
#
# Usage: scripts/install-linux-client.sh [options]
#   --system         install to /usr/local (needs sudo) instead of ~/.local
#   --install-deps   install GTK4 build dependencies with the system package manager
#   -h, --help       show this help

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

PREFIX="$HOME/.local"
INSTALL_DEPS=0
CLIENT_DIR="$ROOT_DIR/clients/linux"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --system) PREFIX="/usr/local"; shift ;;
        --install-deps) INSTALL_DEPS=1; shift ;;
        -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] && die "run as a normal user; --system uses sudo for the install step"
[[ -f "$CLIENT_DIR/Cargo.toml" ]] || die "Linux client not found at clients/linux (planned for phase 3)"
need_cargo

if [[ $INSTALL_DEPS -eq 1 ]]; then
    log "Installing GTK4 build dependencies"
    install_packages "gtk4 pkgconf tpm2-tss" \
        "libgtk-4-dev pkg-config libtss2-dev" \
        "gtk4-devel pkgconf-pkg-config tpm2-tss-devel" \
        "gtk4-devel pkgconf-pkg-config tpm2-0-tss-devel"
fi

need_cmd pkg-config
pkg-config --exists gtk4 || die "GTK4 development files not found (run with --install-deps)"

log "Building ssm-linux (release)"
cargo build --release --locked --manifest-path "$ROOT_DIR/Cargo.toml" -p ssm-linux

install_file() {
    if [[ "$PREFIX" == "$HOME"* ]]; then install "$@"; else as_root install "$@"; fi
}

log "Installing to $PREFIX"
install_file -Dm755 "$ROOT_DIR/target/release/ssm-linux" "$PREFIX/bin/ssm-linux"
install_file -Dm644 /dev/stdin "$PREFIX/share/applications/ssm-linux.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Secure Messenger
Comment=Self-hosted end-to-end encrypted messenger
Exec=$PREFIX/bin/ssm-linux
Icon=mail-message-new
Terminal=false
Categories=Network;InstantMessaging;
EOF

if [[ "$PREFIX" == "$HOME/.local" && ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    warn "$HOME/.local/bin is not in your PATH"
fi
log "Installed: $PREFIX/bin/ssm-linux"
