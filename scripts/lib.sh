#!/usr/bin/env bash
# Shared helpers for the scripts in this directory. Source, don't execute.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT_DIR

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed${2:+ ($2)}"
}

# Runs a command as root, using sudo when not already root.
as_root() {
    if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi
}

# Prints pacman, apt, dnf or zypper; empty if none is found.
detect_pkg_manager() {
    local pm
    for pm in pacman apt-get dnf zypper; do
        if command -v "$pm" >/dev/null 2>&1; then
            echo "${pm%-get}"
            return
        fi
    done
}

# install_packages <pacman pkgs> <apt pkgs> <dnf pkgs> <zypper pkgs>
install_packages() {
    case "$(detect_pkg_manager)" in
        pacman) as_root pacman -S --needed --noconfirm $1 ;;
        apt)    as_root apt-get update -q && as_root apt-get install -y $2 ;;
        dnf)    as_root dnf install -y $3 ;;
        zypper) as_root zypper --non-interactive install $4 ;;
        *)      die "no supported package manager found; install manually: $1" ;;
    esac
}

need_cargo() {
    need_cmd cargo "install Rust from https://rustup.rs or your distribution"
}

# Runs a command as the postgres system user. runuser instead of su: Arch
# (and others) lock that account as expired, which su refuses.
as_postgres() {
    (cd / && as_root runuser -u postgres -- "$@")
}
