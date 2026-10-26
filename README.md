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
| 0 ADRs, threat model | done (`docs/adr`) |
| 1 Server foundation | done: invites, enrollment, approval, sessions, admin API, audit log, events, WebSocket, OpenAPI |
| 2 Client core | done: pattern container, Olm/Megolm, client library; hardware binding (Keystore/TPM2) open |
| 3 1:1 chats | done on Linux; Android open |
| 4 Deletion, retention | done (media part follows phase 6) |
| 5 Groups | done (membership, session rotation) |
| 6 Media | open |
| 7 Admin | server done (incl. mass deletion); admin area in the clients open |
| 8 Push, hardening | notification hint done; UnifiedPush/FCM, pentest open |

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
