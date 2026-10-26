# ADR-0009: Technologie-Stack

**Status:** Angenommen (2026-10-26)

## Entscheidung
| Bereich | Wahl |
|---|---|
| Server | Rust, axum, tokio, sqlx |
| Datenbank | PostgreSQL ≥ 15 |
| Medienspeicher | Dateisystem oder S3-kompatibel hinter Storage-Trait |
| Gemeinsamer Core | Rust-Crate `ssm-core` |
| E2EE | `vodozemac` |
| Lokale Kryptografie | `argon2`, `hkdf`, `sha2`, `chacha20poly1305`, `ed25519-dalek`, `zeroize` |
| Android | Kotlin, Jetpack Compose, UniFFI-Bindings an `ssm-core` |
| Linux | Rust, GTK4 (`gtk4-rs`) **ohne libadwaita**, klassisches Erscheinungsbild (Menüleiste, Werkzeugleiste, Statusleiste, WM-Titelleiste, Stil wie Thunar/ältere Windows-Versionen) |
| Admin-CLI | Rust-Binary `ssm-admin` |
| Versionsverwaltung | Git |

## Begründung
- Eine Sprache für Server, Core und Linux-Client; vodozemac ist Rust-nativ.
- GTK3-Bindings für Rust (gtk3-rs) sind archiviert und werden nicht mehr gepflegt; GTK4 ohne libadwaita erlaubt dennoch ein klassisches Layout.

## Verworfene Alternativen
- Go-Server; GTK3; Qt Widgets; Tauri; Compose Multiplatform für Linux.
