#!/usr/bin/env bash
# Builds the Android APK and copies it into the project root.
#
# Steps: compile the Rust FFI library (crates/ssm-ffi) for the Android ABIs
# with cargo-ndk, generate the UniFFI Kotlin bindings, run Gradle in
# clients/android, copy the APK to ./ssm-<variant>.apk.
#
# Usage: scripts/build-android-apk.sh [options]
#   --release        build a signed release APK (default: debug). Needs
#                    SSM_KEYSTORE, SSM_KEYSTORE_PASSWORD, SSM_KEY_ALIAS,
#                    SSM_KEY_PASSWORD in the environment.
#   --abi LIST       comma-separated ABIs (default arm64-v8a,armeabi-v7a,x86_64)
#   -h, --help       show this help
#
# Requires an Android SDK with NDK (ANDROID_HOME, default ~/Android/Sdk) and a
# JDK 17+. A user-local rustup in ~/.cargo/bin is preferred over the system
# Rust, because the Android targets come from rustup.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

VARIANT="debug"
ABIS="arm64-v8a,armeabi-v7a,x86_64"
ANDROID_DIR="$ROOT_DIR/clients/android"
FFI_CRATE="ssm-ffi"
MIN_SDK=26

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release) VARIANT="release"; shift ;;
        --abi) ABIS="$2"; shift 2 ;;
        -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ -f "$ANDROID_DIR/settings.gradle.kts" || -f "$ANDROID_DIR/settings.gradle" ]] \
    || die "Android project not found at clients/android (planned for phase 3)"
[[ -f "$ROOT_DIR/crates/$FFI_CRATE/Cargo.toml" ]] || die "FFI crate crates/$FFI_CRATE not found (planned for phase 2)"

if [[ -x "$HOME/.cargo/bin/rustup" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi
need_cargo
need_cmd java "install a JDK 17 or newer"
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
[[ -n "$ANDROID_HOME" && -d "$ANDROID_HOME" ]] || die "set ANDROID_HOME to your Android SDK"
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    ANDROID_NDK_HOME="$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
    export ANDROID_NDK_HOME
fi
[[ -n "$ANDROID_NDK_HOME" && -d "$ANDROID_NDK_HOME" ]] || die "no NDK found; install one with: sdkmanager 'ndk;<version>'"

if ! command -v cargo-ndk >/dev/null 2>&1; then
    log "Installing cargo-ndk"
    cargo install --locked cargo-ndk
fi

declare -A RUST_TARGET=(
    [arm64-v8a]=aarch64-linux-android
    [armeabi-v7a]=armv7-linux-androideabi
    [x86_64]=x86_64-linux-android
    [x86]=i686-linux-android
)
NDK_ARGS=()
IFS=',' read -ra ABI_LIST <<< "$ABIS"
for abi in "${ABI_LIST[@]}"; do
    target="${RUST_TARGET[$abi]:-}"
    [[ -n "$target" ]] || die "unsupported ABI: $abi"
    if command -v rustup >/dev/null 2>&1; then
        rustup target list --installed | grep -qx "$target" || rustup target add "$target"
    else
        rustc --print target-libdir --target "$target" >/dev/null 2>&1 \
            || die "Rust std for $target is missing (install via rustup or your distribution)"
    fi
    NDK_ARGS+=(-t "$abi")
done

JNI_DIR="$ANDROID_DIR/app/src/main/jniLibs"
log "Building $FFI_CRATE for: $ABIS"
cargo ndk --manifest-path "$ROOT_DIR/Cargo.toml" "${NDK_ARGS[@]}" --platform "$MIN_SDK" -o "$JNI_DIR" \
    build --release --locked -p "$FFI_CRATE"

log "Generating UniFFI Kotlin bindings"
rm -rf "$ANDROID_DIR/app/src/main/java/uniffi"
cargo build --release --locked --manifest-path "$ROOT_DIR/Cargo.toml" -p "$FFI_CRATE" --lib
LIB_NAME="lib${FFI_CRATE//-/_}.so"
cargo run --release --locked --manifest-path "$ROOT_DIR/Cargo.toml" -p "$FFI_CRATE" --bin uniffi-bindgen -- \
    generate --library "$ROOT_DIR/target/release/$LIB_NAME" --language kotlin \
    --out-dir "$ANDROID_DIR/app/src/main/java"

if [[ "$VARIANT" == "release" ]]; then
    for var in SSM_KEYSTORE SSM_KEYSTORE_PASSWORD SSM_KEY_ALIAS SSM_KEY_PASSWORD; do
        [[ -n "${!var:-}" ]] || die "$var must be set for --release"
    done
    GRADLE_TASK="assembleRelease"
else
    GRADLE_TASK="assembleDebug"
fi

log "Running Gradle ($GRADLE_TASK)"
(cd "$ANDROID_DIR" && ./gradlew --no-daemon -Pssm.abis="$ABIS" "$GRADLE_TASK")

APK="$(ls -t "$ANDROID_DIR"/app/build/outputs/apk/"$VARIANT"/*.apk 2>/dev/null | head -1 || true)"
[[ -n "$APK" ]] || die "Gradle finished but no APK was found"
cp "$APK" "$ROOT_DIR/ssm-$VARIANT.apk"
log "APK written to $ROOT_DIR/ssm-$VARIANT.apk"
