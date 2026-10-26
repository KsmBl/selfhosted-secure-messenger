# Technical Design Document (TDD)
## Self-hosted, Ende-zu-Ende-verschlüsselter Messenger für Android und Linux

**Status:** Technischer Entwurf – Phase 0 abgeschlossen, ADRs in `docs/adr/`  
**Version:** 1.2  
**Sprache:** Deutsch

## 1. Zweck und verbindliche Produktregeln

Dieses Dokument beschreibt die Zielarchitektur für Android- und Linux-Clients sowie den selbst gehosteten Server.

Verbindliche Regeln:
- Es gibt ausschließlich **Löschen für alle**. Jedes aktive Mitglied darf jede Nachricht seiner Unterhaltung löschen. Keine lokale Löschfunktion und kein API-Endpunkt „nur für mich".
- Der Client speichert keinen Nachrichtenverlauf, nur Schlüssel. Der Server hält den verschlüsselten Verlauf bis zum Ablauf der Aufbewahrungsfrist.
- Die Chat-App enthält einen eigenen Administrationsbereich für Clients mit Admin-Schlüsselpaar.
- Adminrechte gestatten die Verwaltung und Löschung serverseitiger Ciphertexte, aber keine Entschlüsselung. Der Betreiber ist für die Gerätefreigabe vertrauenswürdig (ADR-0003).
- Kryptografie wird aus geprüften Protokollen und Bibliotheken zusammengesetzt; keine selbst entworfenen Kryptoprimitiven.

## 2. Architekturübersicht

### 2.1 Komponenten
- **Gemeinsamer Core (`ssm-core`, Rust):** Schlüsselcontainer, Entsperrmuster, vodozemac-Integration, Schlüsselbund, Nachrichtenformat, API-Client. Wird von Linux direkt und von Android über UniFFI genutzt.
- **Android-Client:** Kotlin, Jetpack Compose, Android Keystore/StrongBox, UniFFI-Bindings an `ssm-core`, UnifiedPush/FCM.
- **Linux-Client:** Rust, GTK4 über `gtk4-rs`, **ohne libadwaita**. Klassisches Erscheinungsbild im Stil von Thunar bzw. älterer Windows-Oberflächen: Menüleiste, Werkzeugleiste, Statusleiste, Fenstertitel vom Window Manager (keine Header-Bar), schlichtes CSS. TPM2 über `tss-esapi`, Fallback Secret Service.
- **API-Server (`ssm-server`, Rust):** axum, tokio, REST über HTTPS plus WebSocket.
- **Datenbank:** PostgreSQL (sqlx, Migrationen im Repository).
- **Medienobjektspeicher:** Dateisystem oder S3-kompatibler Speicher hinter einer Storage-Abstraktion; nur Ciphertexte.
- **Push-Gateway:** im Server integriert; sendet leere Weck-Signale an UnifiedPush-Endpunkte bzw. FCM.
- **Admin-API:** eigener Router unter `/v1/admin`, eigene Authentisierung, eigenes Rate-Limit.
- **Admin-CLI (`ssm-admin`):** Bootstrap des ersten Admins und Notfallverwaltung direkt auf dem Server.
- **Verwaltungs-TUI (`ssm-server tui`):** Terminaloberfläche auf dem Server-Host mit direktem Datenbankzugriff: Übersicht, Gerätefreigabe/-sperre (widerrufene und abgelehnte Geräte werden gelöscht), Konten und Einladungen, Admin-Rolle, Konto sperren oder vollständig löschen, Massenlöschung, Löschjobs, Audit-Log mit Kettenprüfung. Alle Aktionen werden mit Herkunft „(tui)“ protokolliert. Änderungen erreichen den laufenden Server über PostgreSQL `LISTEN/NOTIFY` (Kanal `ssm_hub`), damit gesperrte Geräte sofort getrennt und Mitglieder geweckt werden. Massenlöschjobs sind per Advisory-Lock gegen Doppelbearbeitung geschützt; unterbrochene Jobs übernimmt der Server minütlich.

### 2.2 Vertrauensgrenzen
1. Endgerät ↔ Server: TLS schützt den Transport, E2EE schützt Inhalte.
2. Client-Speicher ↔ Betriebssystem: Entsperrmuster, Hardware-Key-Storage und Dateirechte schützen den Schlüsselcontainer.
3. Server ↔ Datenbank/Objektspeicher: Server sieht Ciphertexte, Routing-Metadaten, Benutzernamen und Verwaltungsdaten.
4. Admin-Client ↔ Admin-API: Admin-Schlüsselpaar, kurzlebige Tokens, Autorisierung pro Anfrage, Audit.
5. Push-Anbieter: erhält nur ein inhaltsloses Weck-Signal.
6. Betreiber ↔ Gerätefreigabe: Betreiber gilt als vertrauenswürdig (dokumentiertes Restrisiko).

## 3. Technologieauswahl (ADR-0009)

- Rust (stable) für Server, Core, Admin-CLI und Linux-Client; Cargo-Workspace.
- Kotlin für Android; UniFFI für die Bindings.
- PostgreSQL ≥ 15.
- E2EE: `vodozemac` (Olm/Megolm), ADR-0001.
- Lokale Kryptografie: `argon2`, `hkdf`/`sha2`, `chacha20poly1305` (XChaCha20-Poly1305), `zeroize`, `rand` (OS-RNG).
- Geräte- und Admin-Signaturen: Ed25519 (`ed25519-dalek`).

## 4. Schlüsselmodell und Entsperrmuster

### 4.1 Geräteschlüssel
Jedes Gerät erzeugt:
- einen **Geräte-Signaturschlüssel** (Ed25519) zur API-Authentisierung. Er liegt im Hardware-Key-Storage bzw. separat vom Musterschutz, damit Weck-Signale auch im gesperrten Zustand verarbeitet werden können;
- einen **Olm-Account** (Curve25519-Identität, Ed25519-Fingerprint, Einmalschlüssel). Er liegt verschlüsselt im Schlüsselcontainer.

Private Schlüssel verlassen das Gerät nicht.

### 4.2 Entsperrmuster (ADR-0005)
- Raster 5×5, Punkte 0–24 (zeilenweise). Eingabe ist eine Folge von Punktindizes; Wiederholungen sind erlaubt.
- Länge 6–64. Abgelehnt werden: nur ein einzelner Punkt; eine einzelne Zeile, Spalte oder Diagonale in Reihenfolge (vorwärts oder rückwärts); die vier Ecken in beliebiger Reihenfolge; Muster mit weniger als 3 verschiedenen Punkten.
- Kanonische Kodierung: `"ssm-pattern-v1" || len (u8) || indizes (je u8)`.

### 4.3 Schlüsselcontainer
1. Zufälliger Salt (16 Byte) pro Container.
2. `k_pattern = Argon2id(kodiertes Muster, salt, m, t, p)`; Parameter werden pro Gerät auf ≈3 s kalibriert, Untergrenze m = 64 MiB, t = 3.
3. Optionales Hardware-Geheimnis `hw` (32 Byte): Auf Android durch einen nicht exportierbaren Keystore-Schlüssel (StrongBox, falls vorhanden) verschlüsselt; unter Linux im TPM2 versiegelt. Fehlt Hardware, ist `hw` leer und das Restrisiko greift.
4. `KEK = HKDF-SHA256(ikm = k_pattern || hw, salt = salt, info = "ssm/kek/v1")`.
5. Zufälliger 256-Bit-MEK, mit XChaCha20-Poly1305 unter KEK verschlüsselt; Kopfdaten (Version, KDF-Parameter, Salt, Hardware-Flag) sind Associated Data.
6. Der MEK verschlüsselt den Container-Inhalt (Olm-Account, Megolm-Schlüsselbund, Einstellungen).
7. Falsches Muster ⇒ AEAD-Fehler. Fehlversuche erhöhen eine Wartezeit (ab dem 5. Fehlversuch exponentiell, max. 1 h); der Zähler liegt nach Möglichkeit in hardwaregeschütztem Zustand.
8. Muster, `k_pattern`, KEK und MEK werden nach Gebrauch mit `zeroize` überschrieben; best effort.

Das Admin-Schlüsselpaar liegt in einem zweiten, unabhängigen Container mit eigenem Muster.

## 5. Konten, Geräte-Onboarding und Authentisierung (ADR-0003, ADR-0007)

### 5.1 Kontoerstellung
1. Admin legt Konto (Benutzername) an; Server erzeugt einen zufälligen Einladungscode (128 Bit, Base32), speichert nur dessen Hash, Ablauf 7 Tage.
2. Der Code wird außerhalb der App übermittelt.

### 5.2 Gerätefreigabe
1. Client erzeugt Geräte-Signaturschlüssel und Olm-Account.
2. `POST /v1/devices/enroll/challenge` liefert eine Nonce; `POST /v1/devices/enroll` mit Einladungscode (erstes Gerät) oder Benutzername (weitere Geräte), Gerätebezeichnung, öffentlichen Schlüsseln und Signatur über eine Server-Challenge (Proof of Possession).
3. Gerät ist `pending`; es darf nur `GET /v1/devices/status` abfragen.
4. Admin sieht Benutzername, Gerätebezeichnung, Fingerprint und genehmigt oder lehnt ab.
5. Bei Freigabe: `active`; das Gerät lädt Einmalschlüssel hoch.

### 5.3 Sitzungen
- Alle signierten Nachrichten sind domänengetrennt und längenpräfixiert: `domain || (u32le len || feld)*` (Referenz: `crates/ssm-proto/src/signing.rs`). Die Enrollment-Signatur bindet Nonce, Signaturschlüssel und beide Olm-Schlüssel.
- `POST /v1/auth/challenge` liefert eine 32-Byte-Nonce (gültig 60 s, einmalig).
- `POST /v1/auth/session` mit Ed25519-Signatur über `"ssm-auth-v1"`, Felder `nonce`, `device_id` liefert ein Zugriffstoken (zufällig, 15 min, serverseitig gespeichert als Hash).
- Jede Anfrage prüft Token **und** aktuellen Gerätestatus. `disabled`/`revoked` beenden alle Tokens und WebSocket-Verbindungen sofort.

## 6. Client-Zustandsmodell und lokaler Schutz

- `locked`: keine Klartexte, Container geschlossen. Weck-Signale dürfen den Benachrichtigungshinweis abrufen.
- `unlocking`: Muster wird geprüft, Container geöffnet.
- `unlocked`: Chatliste (nur Metadaten) sichtbar.
- `chat_active`: Seiten des gewählten Chats werden geladen, im RAM entschlüsselt und angezeigt.
- `leaving_chat`: entschlüsselte Nachrichten, Vorschauen und Medienpuffer werden verworfen und – soweit möglich – überschrieben.
- `backgrounded`: Android deckt Inhalte ab (`FLAG_SECURE`); Linux best effort.
- `locked_after_timeout`: MEK und Schlüsselbund werden aus dem Speicher entfernt.

Es wird keine garantierte RAM-Löschung versprochen. Linux: Container-Verzeichnis mit Modus 0700, keine temporären Klartextdateien; `mlock` für Schlüsselmaterial, wo möglich. Swap, Crash-Dumps und Backups sind als Risiko dokumentiert.

## 7. Nachrichten- und Gruppenmodell (ADR-0001, ADR-0002)

### 7.1 Kryptografisches Modell
- Jede Unterhaltung (auch 1:1) wird über **Megolm** verschlüsselt. Jedes sendende Gerät besitzt eine ausgehende Megolm-Sitzung pro Unterhaltung.
- Megolm-Sitzungsschlüssel werden über paarweise **Olm**-Kanäle an alle aktiven Geräte aller Mitglieder verteilt (als To-Device-Ereignis über den Server).
- Empfänger speichern eingehende Megolm-Sitzungen im Schlüsselbund (verschlüsselt im Container). Dadurch kann jeder serverseitige Ciphertext später erneut entschlüsselt werden.
- Rotation einer ausgehenden Sitzung: bei jeder Mitgliedschaftsänderung, bei Freigabe/Widerruf eines Geräts eines Mitglieds, nach 100 Nachrichten oder 7 Tagen.
- Schlüssel abgelaufener Nachrichten (älter als die maximal mögliche Frist von 365 Tagen) werden aus dem Schlüsselbund entfernt.

### 7.2 Senden
1. Client prüft Mitgliedschaft und Geräteliste; bei Änderungen rotiert er die Sitzung und verteilt sie.
2. Klartext-Envelope (Typ, Text, Medienreferenzen) wird mit Megolm verschlüsselt.
3. Client sendet Ciphertext, Unterhaltungs-ID, Megolm-Sitzungs-ID und Idempotenz-ID.
4. Server speichert Ciphertext, setzt `expires_at = jetzt + retention`, erzeugt Ereignisse für alle Mitgliedsgeräte und weckt sie.

### 7.3 Abruf
- `GET /v1/conversations/{id}/messages?before=<seq>&limit=100` (neueste zuerst, `next_before` für ältere Seiten) bzw. `?after=<seq>` (älteste zuerst, zum Nachladen nach einem `message`-Ereignis). Die Sequenz wird pro Unterhaltung unter Zeilensperre vergeben, Reihenfolge = Commit-Reihenfolge; stabil bei parallel eintreffenden Nachrichten.
- Abgelaufene Nachrichten und Nachrichten vor dem Beitritt des Abrufenden (`joined_seq`) werden nie ausgeliefert.
- Senden ist idempotent pro Gerät und `client_id`.
- Client entschlüsselt im RAM. Fehlt ein Sitzungsschlüssel (z. B. Nachricht vor Gerätefreigabe), zeigt der Client „Nachricht für dieses Gerät nicht verfügbar".

### 7.4 Gruppen
Mitgliedschaftsänderungen erzeugen einen Systemhinweis und ein `conversation_updated`-Ereignis; alle Geräte rotieren ihre ausgehende Sitzung vor der nächsten Nachricht. Entfernte Mitglieder erhalten keine neuen Sitzungen und verlieren serverseitig den Abrufzugriff.

Berechtigungen: Jedes Mitglied darf austreten. Nur der Gruppen-Admin (anfangs der Ersteller, Rolle `admin` in `conversation_members`) darf Personen einladen und andere entfernen. Verlässt der Admin die Gruppe, wird das am längsten beteiligte verbleibende Mitglied Admin; alle sehen einen Systemhinweis. Einzelchats haben genau zwei Mitglieder; ein zweiter Einzelchat zwischen denselben Personen liefert den bestehenden zurück.

### 7.5 Aufbewahrungsfrist (ADR-0002)
- `conversations.retention_days` ∈ [1, 365], Standard 90.
- `PUT /v1/conversations/{id}/retention` durch jedes aktive Mitglied. Server aktualisiert `expires_at` aller Nachrichten der Unterhaltung, legt ein Systemereignis „Frist geändert von X auf Y Tage durch Z" an und verteilt es an alle Mitglieder.
- Ein Hintergrundjob entfernt minütlich abgelaufene Nachrichten physisch (inkl. Tombstones); Abrufpfade liefern sie schon ab `expires_at` nicht mehr aus. Clients blenden sie anhand von `expires_at` aus. Medien folgen in Phase 6 demselben Pfad.

## 8. Verbindliche globale Löscharchitektur (ADR-0004)

### 8.1 Semantik
Genau eine Löschoperation: **Löschen für alle**. Berechtigt: jedes aktive Mitglied der Unterhaltung sowie Administratoren über die Massenlöschung. Gilt für Einzelchats, Gruppen, Nachrichten und Medien.

### 8.2 Ablauf
1. Client sendet `POST /v1/messages/{id}/delete-for-all` mit Operations-ID.
2. Server prüft aktive Mitgliedschaft des Initiators.
3. In **einer Transaktion**: Löschjob anlegen (idempotent über Operations-ID), Nachricht als `deleted` markieren und Ciphertext leeren, Medienobjekte `purge_pending` setzen, Tombstone-Ereignisse für alle Mitgliedsgeräte in die Outbox schreiben.
4. Abrufpfade filtern `deleted` strikt; Medienendpunkte liefern 404/410.
5. Purge-Worker entfernt Objekte aus dem Speicher und setzt `active_removed`.
6. Outbox-Worker verteilt Tombstones über WebSocket/Push; Clients entfernen Inhalte aus RAM und Caches.
7. Status wechselt auf `backup_purge_pending` und nach Ablauf der Backup-Frist auf `backup_purge_done`.

### 8.3 Idempotenz und Race Conditions
- Gleiche Operations-ID ⇒ gleicher Job, keine Doppelwirkung. Löschen einer bereits gelöschten Nachricht ⇒ Verweis auf bestehenden Job.
- Löschung und Ereigniserzeugung laufen transaktional (Outbox-Pattern).
- Gelöschte Nachrichten werden auch bei Retries nie erneut ausgeliefert.
- Gelöschte Nachrichten bleiben als inhaltsleerer Tombstone (gelöscht von, Zeitpunkt) in der Zeitleiste, bis ihre Frist abläuft; Ciphertext und Sitzungs-ID werden sofort entfernt.
- Ereignisse (`message_deleted` usw.) liegen pro Gerät in `events` und werden mit `GET /v1/events?since=` bestätigt und gelöscht; nicht abgeholte Ereignisse verfallen nach 400 Tagen. Ein Client, dessen Ereignis-Cursor älter ist, verwirft seinen Zustand vollständig und lädt neu – da es keinen lokalen Verlauf gibt, ist das unkritisch.
- Systemhinweise sind nicht löschbar (409).

### 8.4 Medienlöschung
Umfasst verschlüsselte Originaldatei, verschlüsselte Vorschau, Chunks, Objektreferenzen, Datenbankmetadaten und eventuelle Derivate.

### 8.5 Backups und Replikate
- Backup-Aufbewahrung Standard 30 Tage (konfigurierbar, dokumentiert).
- Status `backup_purge_pending` bis `löschzeitpunkt + backup_retention` verstrichen ist.
- Das System behauptet nie, sämtliche Kopien seien vernichtet, solange Backups bestehen.
- Ein bösartiger Server kann Kopien behalten (Restrisiko).

### 8.6 Grenzen
Bereits exportierte, kopierte oder fotografierte Inhalte können nicht zurückgerufen werden.

## 9. Verschlüsselte Medien

1. Client erzeugt pro Original und pro Vorschau einen zufälligen 256-Bit-Schlüssel.
2. Verschlüsselung mit XChaCha20-Poly1305 in einem Stück (Associated Data `"ssm/media/v1"`), Format `nonce (24 B) || ciphertext`. Größenlimit 64 MiB pro Objekt (`SSM_MAX_MEDIA_MB`); STREAM/Chunks sind bei dieser Grenze nicht nötig und können später mit neuer Formatversion folgen.
3. Schlüssel, Größe, Dateiname, MIME-Typ und optionale Bildunterschrift stehen im Megolm-verschlüsselten Inhalt (`Content::Media`) – nie im Klartext beim Server.
4. Upload: `POST /v1/conversations/{id}/media` (nur aktive Mitglieder) liefert eine `media_id`. Die Nachricht referenziert per `media_ids` höchstens zwei Objekte (Original, Vorschau); der Server verknüpft nur eigene, noch unverknüpfte Uploads. Nicht versendete Uploads werden nach einer Stunde gelöscht. Dateien liegen unter `SSM_MEDIA_DIR` (systemd: `/var/lib/ssm/media`).
5. Download: `GET /v1/media/{id}` nur für Mitglieder, die die verknüpfte Nachricht sehen dürfen (nicht abgelaufen, nicht gelöscht, nach dem Beitritt gesendet).
6. Bilder bekommen eine Vorschau (JPEG, längste Seite ≤ 320 px), die im Chat automatisch geladen wird; das Original erst nach explizitem „Öffnen“/„Speichern“.
7. Entschlüsselte Medien nur im RAM; Vorschauen werden beim Verlassen des Chats und beim Sperren verworfen. Auf Android behalten die Medien-Schlüssel nur die Rust-Sitzung (nach Nachrichten-ID), die Kotlin-Seite sieht sie nie.
8. Export ist eine explizite Nutzeraktion mit Warnhinweis (FR-012); Nicht-Bilder können nur gespeichert, nicht in der App geöffnet werden.
9. Löschen für alle, Ablauf und Massenlöschung markieren verknüpfte Objekte; der Wartungsjob entfernt die Dateien und Zeilen (`media::purge`).

## 10. Admin-Oberfläche und Admin-API

### 10.1 UI-Bereiche
Übersicht, Geräteanfragen, Geräteverwaltung, Konten und Einladungen, Massenlöschung, Löschjobstatus, Audit-Protokoll.

### 10.1a Umsetzung im Linux-Client
- *Admin → Admin-Schlüssel einrichten…* erzeugt das Ed25519-Schlüsselpaar in `admin.ssmc` im Profilverzeichnis, versiegelt mit einem eigenen Muster, und zeigt den öffentlichen Schlüssel an.
- Der Betreiber registriert ihn in `ssm-server tui` (Konten → `k`) oder ein bestehender Admin im Client (Konten → „Admin Key…“).
- *Admin → Administration…* fragt das Admin-Muster ab, ermittelt die Schlüssel-ID über `GET /v1/admin/keys/lookup` und meldet sich per signierter Challenge an. Tabs: Übersicht, Geräte, Konten, Löschjobs, Audit-Log. Jede verändernde Kontoaktion und jeder Widerruf wird mit frischer Bestätigungssignatur ausgeführt; sich selbst sperren, die eigene Admin-Rolle entziehen oder das eigene Konto löschen ist über die API nicht möglich.
- Das Fenster schließt sich beim Sperren, Kontowechsel oder Auto-Lock; der Admin-Schlüssel verlässt damit den Speicher.

### 10.2 Authentisierung (ADR-0006)
- Das Admin-Schlüsselpaar (Ed25519) wird im Admin-Bereich des Clients erzeugt und liegt in einem eigenen, mustergeschützten Container (hardwaregebunden, wo möglich).
- Registrierung des öffentlichen Schlüssels: erster Admin per `ssm-admin`-CLI auf dem Server; weitere Admins durch einen bestehenden Admin.
- `POST /v1/admin/auth/challenge` → Nonce; `POST /v1/admin/auth/session` mit Signatur über `"ssm-admin-auth-v1"`, Felder `nonce`, `admin_key_id` → Admin-Token (10 min).
- Destruktive Aktionen (Widerruf, Massenlöschung, Admin-Verwaltung) verlangen zusätzlich eine frische Signatur über `"ssm-admin-confirm-v1"`, Felder `nonce`, `aktion`, `ziel`; die Nonce stammt von `POST /v1/admin/confirm/challenge` (nur mit Admin-Sitzung).
- Jede Anfrage wird serverseitig autorisiert; Rate-Limit pro Admin und IP.
- Kein SSH-Privatschlüssel in der Chat-App.

### 10.3 Massenlöschung nach Person
Alle serverseitigen Nachrichten und Medien, die vom Zielkonto stammen, über alle Unterhaltungen hinweg. Asynchroner Job mit Fortschritt, Teilergebnissen und Audit-Eintrag.

### 10.4 Audit-Log
Jeder Eintrag enthält `prev_hash` und `hash = SHA-256(prev_hash || kanonischer Eintrag)`. Ein Prüfbefehl in `ssm-admin` verifiziert die Kette. Die Tabelle ist für die Anwendungsrolle nur `INSERT`/`SELECT`.

## 11. Datenmodell

Die verbindliche Definition steht in `server/migrations/`. Übersicht:

- `accounts(id, username, role, status, created_at)`
- `invites(id, account_id, code_hash, expires_at, used_at)`
- `devices(id, account_id, display_name, signing_key, olm_identity_key, olm_fingerprint_key, status, created_at, approved_at, revoked_at)`
- `auth_challenges(nonce, device_id|admin_key_id, expires_at)`
- `sessions(token_hash, device_id, expires_at)`, `admin_sessions(token_hash, admin_key_id, expires_at)`
- `admin_keys(id, account_id, public_key, status, created_at)`
- `one_time_keys(device_id, key_id, public_key)`
- `conversations(id, kind, retention_days, created_at)`
- `conversation_members(conversation_id, account_id, status, role, joined_at, joined_seq, left_at)`
- `messages(id, conversation_id, seq, kind, sender_account_id, sender_device_id, client_id, session_id, ciphertext, notice, created_at, expires_at, deleted_at, deleted_by, delete_job_id)`
- `media_objects(id, message_id, uploader_device_id, kind, size, object_ref, purge_state)`
- `events(device_id, seq, kind, body, created_at)` – Outbox/Sync pro Gerät, Sequenz unter Zeilensperre des Geräts, ohne Klartext
- `delete_jobs(id, operation_id, requested_by, scope, status, created_at, completed_at, error_summary)`
- `push_endpoints(device_id, kind, endpoint, status)`
- `admin_audit_events(id, admin_account_id, action, target, result, correlation_id, created_at, prev_hash, hash)`

## 12. API

Siehe PRD Abschnitt 8; maschinenlesbar in `server/openapi.yaml`. Fehler als `application/problem+json` (RFC 9457). Es gibt keinen Endpoint für „nur für mich löschen".

## 13. Push, Echtzeitkanal und Metadaten (ADR-0008)

- Linux und Android im Vordergrund: WebSocket `GET /v1/ws`, Server sendet `{"type":"sync"}`; Client holt Ereignisse über `GET /v1/events?since=`.
- Android im Hintergrund: UnifiedPush-Endpunkt (bevorzugt, z. B. ntfy auf eigenem Server), sonst FCM. Payload ausschließlich ein zufälliges Weck-Signal ohne IDs.
- Nach dem Wecken ruft das Gerät mit seinem Geräte-Signaturschlüssel (funktioniert im gesperrten Zustand) `GET /v1/notifications/hint` ab: Antwort enthält nur Anzahl neuer Nachrichten und den Anfangsbuchstaben des Benutzernamens des letzten Absenders. Nicht im Push-Payload, nur über TLS.
- Push-Anbieter sehen Zustellzeitpunkte und Gerätetoken; im Datenschutzmodell offengelegt.
- Umsetzung: `push_endpoints` (je Gerät UnifiedPush-URL oder FCM-Token), `PUT/DELETE /v1/push-endpoint`. Der Server pusht nur, wenn das Gerät keine offene WebSocket-Verbindung hat, höchstens einmal pro 10 s je Gerät (danach genau ein Nachzügler). Nutzlast ist ein bedeutungsloses Byte. UnifiedPush-Endpunkte müssen HTTPS sein und auf öffentliche Adressen auflösen (Schutz des internen Netzes; abschaltbar für selbst gehostetes ntfy im LAN). Antwortet ein Endpunkt mit 404/410, wird er gelöscht. FCM wird mit einem Firebase-Dienstkonto aktiviert (`SSM_FCM_SERVICE_ACCOUNT`); ohne Firebase-Konfiguration im App-Build bleibt UnifiedPush der einzige Weg.
- Android: UI und Push-Dienst teilen sich eine Sitzung; der Dienst holt nach dem Wecken mit dem Geräteschlüssel nur den Hinweis (Anzahl, Anfangsbuchstabe) und zeigt „Neue Nachricht – Von X…“.

## 14. Sicherheits- und Teststrategie

### 14.1 Kryptografie
- Testvektoren und Roundtrip-Tests für Container, Muster-Kodierung und Medienverschlüsselung.
- Tests für Sitzungsrotation, Geräte-Widerruf, Gruppenänderungen, ungültige Ciphertexte, fehlende Sitzungsschlüssel.
- Keine eigene Implementierung von Algorithmen.

### 14.2 Löschung und Aufbewahrung
1. UI/API enthalten keine Aktion „nur für mich löschen".
2. Jedes Mitglied kann löschen, Nicht-Mitglieder erhalten 403/404.
3. Löschung blockiert weitere Auslieferung; Offline-Clients erhalten Tombstones.
4. Retries, doppelte Events, parallele Löschungen getestet.
5. Medienlöschung umfasst Original, Vorschau und Metadaten.
6. Backup-Status nicht sofort „abgeschlossen".
7. Ablauf-Job löscht fristgerecht; Friständerung erzeugt Systemhinweis für alle.

### 14.3 Administration
1. Nicht-Admins können Admin-API nicht verwenden.
2. Manipulierte oder wiederholte Signaturen/Nonces werden abgewiesen.
3. Freigabe, Deaktivierung und Widerruf wirken sofort auf bestehende Tokens und WebSockets.
4. Massenlöschung verlangt Bestätigungssignatur, zeigt Status und erzeugt Audit-Eintrag.
5. Audit-Hash-Kette erkennt Manipulation.

### 14.4 Client-Sicherheit
- Mustervalidierung, Container-Roundtrip, falsches Muster, Fehlversuchsverzögerung.
- Keine sensiblen Inhalte in Logs, Crash-Dumps oder Push-Payloads.
- Android `FLAG_SECURE`; Linux Dateirechte, Keyring/TPM, temporäre Dateien, Swap.

## 15. Betrieb und Incident Response

- TLS-Terminierung (Reverse Proxy oder integriert), Secrets aus Umgebungsvariablen/Dateien mit restriktiven Rechten.
- Datenbank- und Objektspeicher-Backups verschlüsselt, Aufbewahrung 30 Tage, regelmäßig getestet.
- `ssm-admin` erlaubt Notfall-Sperre von Geräten und Admin-Schlüsseln direkt auf dem Server.
- Audit-Kette regelmäßig verifizieren.
- Releases signiert.

## 16. Definition of Done für eine Sicherheitsfreigabe

- Threat Model und ADRs genehmigt.
- vodozemac-Version und Lizenzen geprüft.
- Kein Nachrichten-Klartext auf Server oder Client-Datenträger.
- Kein „nur für mich löschen" in UI oder API.
- Globale Löschung, Ablauf, Offline-Synchronisierung und Medien getestet.
- Adminoberfläche mit serverseitiger Autorisierung, Bestätigung und Audit vorhanden.
- Muster- und Gerätesicherheitsannahmen dokumentiert.
- Backup-/Replikat-Bereinigung mit klaren Statuswerten umgesetzt.
- Automatisierte Sicherheits-, Integrations- und Migrationstests bestehen.
- Unabhängiger Security Review vor produktivem Einsatz abgeschlossen.

## 17. Referenzen

- ADRs: `docs/adr/`
- vodozemac: https://github.com/matrix-org/vodozemac
- UnifiedPush: https://unifiedpush.org/
- RFC 9457 Problem Details: https://www.rfc-editor.org/rfc/rfc9457
- OWASP MASVS / ASVS
