# Selfhosted Secure Messenger

Self-hosted, end-to-end encrypted messenger for Android and Linux. Specification and decisions (German):

- [PRD](docs/PRD.md) – product requirements
- [TDD](docs/TDD.md) – technical design
- [ADRs](docs/adr/README.md) – architecture decisions

## Layout

| Path | Content |
|---|---|
| `crates/ssm-core` | 5×5 unlock pattern, pattern-protected key container, lockout policy, Olm/Megolm E2EE store (vodozemac) |
| `crates/ssm-proto` | Shared API types and signed-message formats |
| `crates/ssm-client` | Device client library: enrollment, sync, messaging, deletion, wake-up channel |
| `server` | `ssm-server` (axum + PostgreSQL; `ssm-server tui` for management), `ssm-admin` CLI, `openapi.yaml` |
| `clients/linux` | GTK4 desktop client with a classic look (`ssm-linux`) |
| `scripts` | Install / build scripts |
| `clients/android`, `crates/ssm-ffi` | Planned |

## Status

| Phase | State |
|---|---|
| 0 ADRs, threat model | done (`docs/adr`, `docs/threat-model.md`) |
| 1 Server foundation | done: invites, enrollment, approval, sessions, admin API, audit log, events, WebSocket, OpenAPI |
| 2 Client core | done: pattern container, Olm/Megolm, client library, Android Keystore, optional TPM2 on Linux |
| 3 1:1 chats | done (Linux, Android) |
| 4 Deletion, retention | done, including media |
| 5 Groups | done (membership, admin role, session rotation) |
| 6 Media | done: per-file encryption, previews, open/save with warning (Linux, Android) |
| 7 Admin | done: `ssm-server tui`, `ssm-admin`, admin area in the Linux client |
| 8 Push, hardening | UnifiedPush/FCM, rate limits, audit role done; HTTPS setup, backups, release signing open |

## Development

```sh
cargo test --workspace     # server tests download a temporary PostgreSQL on first run
cargo clippy --workspace --all-targets
```

Run the server locally against your own PostgreSQL:

```sh
export SSM_DATABASE_URL=postgres://user@localhost/ssm
cargo run -p ssm-server --bin ssm-admin -- dev-keygen --out admin.key   # prints the admin public key
cargo run -p ssm-server --bin ssm-admin -- bootstrap --username root --admin-public-key <key>
SSM_BIND=127.0.0.1:8080 cargo run -p ssm-server
cargo run -p ssm-server -- tui  # management TUI (same SSM_DATABASE_URL, on the server host)
cargo run -p ssm-linux          # GTK client; accounts in ~/.local/share/ssm-messenger/profiles
cargo run -p ssm-linux -- --account alice   # open one account directly (several windows possible)
```

Demo data (two steps, approve the devices in between, e.g. via SQL in development):

```sh
cargo run -p ssm-client --example demo -- enroll <server> <dir> <invite> <device-name>
cargo run -p ssm-client --example demo -- chat <server> <alice-dir> <bob-dir> [<carol-dir>]
```

## Scripts

| Script | Purpose |
|---|---|
| `scripts/install-server.sh` | Build, install PostgreSQL + `ssm-server` + `ssm-admin`, systemd unit |
| `scripts/install-linux-client.sh` | Build and install the GTK4 client (`--install-deps`, `--system`) |
| `scripts/build-android-apk.sh` | Build the APK (`--release` for a signed build) into `./ssm-<variant>.apk` |

## Android notes

- Android 17+ asks for **nearby devices / local network** access at first start. It is needed to reach a
  server on the local network (home server, LAN IP); without it connections time out.
- Emulator testing: the host is `10.0.2.2` only on the emulator's mobile network. Disable emulator Wi-Fi
  (`adb shell svc wifi disable`), otherwise `10.0.2.2` is the virtual router.
- Debug builds allow screenshots when started with `--ez ssm.allowScreenshots true`; release builds always
  set `FLAG_SECURE`.

