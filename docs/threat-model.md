# Bedrohungsmodell

Stand: Version 1.2 (passend zu PRD/TDD v1.2). Gilt für Server (`ssm-server`, `ssm-admin`, TUI), Linux-Client (GTK4), Android-App und die Installationsskripte.

## 1. Schutzziele

| Ziel | Bedeutung |
|---|---|
| Vertraulichkeit der Inhalte | Nachrichten, Medien und Vorschauen sind nur für die Mitglieder einer Unterhaltung lesbar – nicht für Server, Betreiber-Backups, Netz oder Push-Dienste. |
| Integrität | Inhalte und Absender können nicht unbemerkt verändert werden; Geräte sind an Konten gebunden. |
| Kontrollierte Löschung | „Für alle löschen“, Ablauf (1–365 Tage) und Massenlöschung entfernen Inhalte serverseitig vollständig. |
| Nachvollziehbarkeit | Jede Admin-Aktion steht im hash-verketteten, nur anfügbaren Audit-Log. |
| Geräteschutz | Ein gestohlenes, gesperrtes Gerät gibt ohne Muster keine Schlüssel preis. |

## 2. Werte (Assets)

- Olm-Identitäts- und Sitzungsschlüssel, Megolm-Gruppensitzungen (im Schlüsselcontainer `keys.ssmc`).
- Geräteschlüssel (Ed25519, `device.key`) – meldet das Gerät beim Server an.
- Admin-Schlüssel (`admin.ssmc`, eigenes Muster).
- Klartext im Arbeitsspeicher während der Nutzung.
- Server: Ciphertexte, Medienobjekte, Metadaten (wer mit wem, wann, Größen), Audit-Log, Einladungscodes, Sitzungstoken.

## 3. Akteure und Annahmen

| Akteur | Annahme |
|---|---|
| Betreiber/Server-Admin (Shell, Datenbank) | **Vertrauenswürdig für Verfügbarkeit und Gerätefreigabe** (ADR-0002). Er kann Geräte freigeben und damit theoretisch ein eigenes Gerät in ein Konto einschleusen. Gegenmaßnahme: Fingerprint-Anzeige, Geräteliste im Client, Audit-Log. Er kann keine bestehenden Inhalte entschlüsseln. |
| App-Admin (Admin-Schlüssel) | Darf Konten/Geräte verwalten und Massenlöschungen auslösen, nie Inhalte lesen. Jede destruktive Aktion braucht eine frische Signatur. |
| Teilnehmer | Sieht, was in seinen Unterhaltungen ab Beitritt gesendet wurde. Kann Inhalte speichern oder abfotografieren (nicht verhinderbar, nur Warnhinweis FR-012). |
| Externer Angreifer im Netz | Kann mitlesen und manipulieren, wenn TLS fehlt oder kompromittiert ist. |
| Dieb/Finder eines Geräts | Hat das Gerät im gesperrten Zustand, ggf. mit Dateisystemzugriff. |
| Schadsoftware auf dem Endgerät | Außerhalb des Schutzbereichs: ein kompromittiertes, entsperrtes Gerät verliert die Vertraulichkeit. |
| Push-Dienst (UnifiedPush-Distributor, FCM) | Nicht vertrauenswürdig; erhält nur inhaltsfreie Weckrufe. |

## 4. Vertrauensgrenzen

1. Client ↔ Server: HTTPS über einen Reverse Proxy (Caddy, `scripts/setup-https.sh`); der Server selbst hört nur auf `127.0.0.1`.
2. Server ↔ PostgreSQL: lokaler Unix-Socket, Peer-Authentisierung; Audit-Tabelle gehört der Rolle `ssm_audit`.
3. Server ↔ Push-Dienste: ausgehend, nur Weckruf ohne Inhalt.
4. App ↔ Betriebssystem: Keystore/TPM, Dateisystem, Bildschirm, Benachrichtigungen.

## 5. Bedrohungen und Gegenmaßnahmen

### 5.1 Server und Datenbank

| Bedrohung | Gegenmaßnahme | Rest |
|---|---|---|
| Server liest Inhalte | Ende-zu-Ende mit Olm/Megolm (vodozemac); Medien pro Objekt mit eigenem Schlüssel (XChaCha20-Poly1305), Schlüssel nur im verschlüsselten Inhalt. | Metadaten sind sichtbar (Mitgliedschaften, Zeitpunkte, Größen, Medienanzahl). |
| Betreiber schleust Gerät ein | Freigabe nur durch Admin; Fingerprint beim Freigeben; neue Geräte sehen keine alten Nachrichten (kein Schlüssel-Backup); Audit-Eintrag. | Bewusst akzeptiert (ADR-0002); Nutzer sollten ihre Geräteliste prüfen. |
| Manipulation des Audit-Logs | Hash-Kette (`verify-audit`), Trigger gegen UPDATE/DELETE/TRUNCATE, Tabelle gehört `ssm_audit`, Dienstrolle darf nur SELECT/INSERT. | Ein PostgreSQL-Superuser kann alles ändern; die Hash-Kette macht das sichtbar, solange ein früherer Kettenwert extern notiert ist. |
| Gelöschte Inhalte bleiben liegen | Löschen ersetzt den Ciphertext durch einen Grabstein, Medienobjekte werden markiert und vom Wartungsjob entfernt; Backups halten Gelöschtes höchstens `SSM_BACKUP_RETENTION_DAYS` (30) Tage. | Bis zum Ablauf der Backup-Aufbewahrung existieren verschlüsselte Kopien. |
| SQL-Injection | Ausschließlich parametrisierte Abfragen; dynamische SQL-Teile nur aus festen Konstanten. | – |
| Ressourcenerschöpfung | Ratenbegrenzung: 30/min je IP für unauthentisierte Endpunkte, je Sitzung 600 Geräteanfragen, 60 Medien-Uploads, 120 Admin-Anfragen pro Minute; Medien max. 64 MiB; nicht versendete Uploads nach 1 h gelöscht. | Hinter dem lokalen Reverse Proxy gilt der letzte `X-Forwarded-For`-Eintrag als Client-Adresse (nur von Loopback-Peers akzeptiert). Ein Proxy auf einem anderen Host würde alle Clients unter seiner IP bündeln. |
| SSRF über Push-Endpunkte | Nur `https://`, öffentliche Adressen (abschaltbar für ein eigenes ntfy im LAN). | – |

### 5.2 Netz

| Bedrohung | Gegenmaßnahme | Rest |
|---|---|---|
| Mitlesen/Manipulation | TLS am Reverse Proxy; Inhalte zusätzlich E2E-verschlüsselt; Anmeldung per Signatur über eine Server-Nonce (kein Passwort, kein wiederverwendbares Geheimnis). | Ohne TLS (nur „dieser PC“-Installation) sind Metadaten und Token im lokalen Netz lesbar. |
| Replay | Nonces einmalig und kurzlebig; Sitzungstoken 15 min (Admin 10 min); Nachrichten idempotent per `client_id`. | – |

### 5.3 Endgeräte

| Bedrohung | Gegenmaßnahme | Rest |
|---|---|---|
| Gestohlenes, gesperrtes Gerät | Schlüsselcontainer: Muster (5×5, ≥ 6 Drücke) → Argon2id (kalibriert) → HKDF → KEK; Sperrverzögerung nach Fehlversuchen; Android-Keystore- bzw. TPM2-Geheimnis, wo vorhanden. | **Ohne TPM/Keystore** schützt nur das Muster. Ein Angreifer mit Dateikopie kann offline raten; Argon2id verteuert das, ein kurzes Muster bleibt angreifbar. Empfehlung: längere Muster. |
| TPM fehlt oder ist nicht zugänglich | Der Client funktioniert vollständig ohne TPM (Feature und Laufzeitprüfung optional, bestehende Profile unverändert). | Siehe oben. |
| TPM wird zurückgesetzt (BIOS-Update) | Profil ist dann nicht mehr zu öffnen; Gerät neu registrieren, Nachrichten liegen verschlüsselt auf dem Server. | Ältere Nachrichten sind für das neue Gerät nicht lesbar (keine Schlüssel-Weitergabe). |
| Klartext auf dem Datenträger | Nachrichten und Medien werden nie lokal gespeichert, nur im RAM entschlüsselt; Vorschauen beim Verlassen des Chats verworfen; Speichern nur nach Warnung. | Swap/Hibernation können RAM-Inhalte schreiben (verschlüsselten Swap empfehlen). Gespeicherte Exporte liegen unverschlüsselt. |
| Core-Dumps | Linux-Prozess ist nicht dumpbar (ab dem Start der Oberfläche, vor dem Entsperren). | – |
| Bildschirmaufnahme | Android: `FLAG_SECURE` (keine Screenshots, keine Vorschau in „Zuletzt verwendet“). | Linux bietet keinen entsprechenden Schutz. |
| Sperrbildschirm-Benachrichtigungen | Push enthält keinen Inhalt; Benachrichtigung zeigt höchstens das Initial des Absenders, auf dem Sperrbildschirm privat. | – |
| Auto-Lock | App sperrt beim Verlassen (Android) bzw. nach Inaktivität (Linux) und verwirft Schlüssel und Klartext. Ausnahme: der eigene Dateiauswahldialog (max. 5 min). | – |

### 5.4 Administration

| Bedrohung | Gegenmaßnahme | Rest |
|---|---|---|
| Diebstahl des Admin-Schlüssels | Eigener Container mit eigenem Muster; Admin-Sitzung 10 min; destruktive Aktionen mit frischer Signatur; Admin-Schlüssel per TUI widerrufbar. | Ein entsperrter Admin-Schlüssel auf einem kompromittierten Gerät erlaubt alle Admin-Aktionen bis zum Widerruf (sichtbar im Audit-Log). |
| Admin sperrt sich oder andere Admins versehentlich aus | API verbietet Selbstsperre, eigene Rechteentziehung und Selbstlöschung; TUI auf dem Server bleibt als Rückfallweg. | – |
| Zugriff auf `ssm-tui`/`ssm-ctl` | Nur per `sudo` auf dem Server, läuft als Dienstnutzer. | Wer Root auf dem Server hat, ist Betreiber. |

### 5.5 Lieferkette und Updates

| Bedrohung | Gegenmaßnahme | Rest |
|---|---|---|
| Manipulierte Abhängigkeiten | `Cargo.lock`/Gradle-Versionen fest; Build mit `--locked`. | Keine reproduzierbaren Builds. |
| Gefälschtes oder älteres APK | Release-Signatur (eigener Schlüssel); Android verweigert Updates mit anderer Signatur und niedrigerem `versionCode` (FR-023). | Erstinstallation muss über einen vertrauenswürdigen Weg erfolgen. |

## 6. Bewusst akzeptierte Restrisiken

1. Der Betreiber ist für die Gerätefreigabe vertrauenswürdig (ADR-0002).
2. Metadaten sind für den Server sichtbar.
3. Ohne Hardware-Schlüsselspeicher hängt der Geräteschutz allein von Muster und Argon2id ab.
4. Teilnehmer können Inhalte exportieren oder abfotografieren.
5. Kein Schutz gegen kompromittierte, entsperrte Endgeräte.
6. Backups enthalten gelöschte (verschlüsselte) Inhalte bis zum Ende der Aufbewahrungsfrist.

## 7. Prüfpunkte für einen Pentest

- Autorisierung jedes Endpunkts (fremde Unterhaltungen, Medien, Löschjobs, Admin-Endpunkte mit Gerätetoken).
- Mitgliedschaftsgrenzen: Nachrichten/Medien vor Beitritt, nach Austritt, nach Ablauf und Löschung.
- Ratenbegrenzung hinter dem Reverse Proxy.
- Audit-Kette nach Neustarts und Massenlöschungen (`ssm-ctl verify-audit`).
- Container-Format: Manipulation von `keys.ssmc`, `tpm.seal`, Sperrzähler in `profile.json`.
- Push-Endpunkt-Validierung (private Adressen, Weiterleitungen).
