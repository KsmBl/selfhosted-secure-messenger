# Selfhosted Secure Messenger

Self-hosted, end-to-end encrypted messenger for Android and Linux. Specification and decisions (German):

- [PRD](docs/PRD.md) – product requirements
- [TDD](docs/TDD.md) – technical design
- [ADRs](docs/adr/README.md) – architecture decisions

## Layout

| Path | Content |
|---|---|
| `crates/ssm-core` | Client core: 5×5 unlock pattern, pattern-protected key container, lockout policy |
| `crates/ssm-proto` | Shared API types and signed-message formats |
| `server` | `ssm-server` (axum + PostgreSQL) and the `ssm-admin` CLI |
| `scripts` | Install / build scripts |
| `clients/linux`, `clients/android`, `crates/ssm-ffi` | Planned (phases 2–3) |

## Status

Phase 0 (ADRs) done. Phase 1 in progress: accounts and invites, device enrollment and approval,
device and admin sessions, admin API for devices and accounts, hash-chained audit log.

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
```

## Scripts

| Script | Purpose |
|---|---|
| `scripts/install-server.sh` | Build, install PostgreSQL + `ssm-server` + `ssm-admin`, systemd unit |
| `scripts/install-linux-client.sh` | Build and install the GTK4 client (`--install-deps`, `--system`) |
| `scripts/build-android-apk.sh` | Build the APK (`--release` for a signed build) into `./ssm-<variant>.apk` |
