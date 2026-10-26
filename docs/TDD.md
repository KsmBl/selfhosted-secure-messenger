# Technical Design Document (TDD)
## Self-hosted, Ende-zu-Ende-verschlüsselter Messenger für Android und Linux

**Status:** Technischer Entwurf – vor Implementierung durch ADRs und Security Review zu konkretisieren  
**Version:** 1.1  
**Sprache:** Deutsch

## 1. Zweck und verbindliche Produktregeln

Dieses Dokument beschreibt eine umsetzbare Zielarchitektur für Android- und Linux-Clients sowie den selbst gehosteten Server.

Verbindliche Regeln:
- Es gibt ausschließlich **Löschen für alle**. Keine lokale Löschfunktion und kein API-Endpunkt „nur für mich“.
- Die Chat-App enthält einen eigenen Administrationsbereich für autorisierte Admin-Clients.
- Adminrechte gestatten die Verwaltung und Löschung serverseitiger Ciphertexte, aber keine Entschlüsselung von E2EE-Inhalten.
- Kryptografie wird aus geprüften Protokollen und Bibliotheken zusammengesetzt; keine selbst entworfenen Kryptoprimitiven.

## 2. Architekturübersicht

### 2.1 Komponenten
- **Android-Client:** Kotlin, UI, Android Keystore, lokale sichere Datenhaltung, E2EE-Protokolladapter.
- **Linux-Client:** UI-Toolkit wird per ADR festgelegt; OS-Keyring/Secret Service und optional TPM2.
- **Gemeinsamer Core:** Rust ist ein Kandidat für Protokolladapter, Serialisierung und sicherheitskritische gemeinsame Logik. FFI und Plattformgrenzen müssen geprüft werden.
- **API-Server:** Rust oder Go; REST/HTTPS oder vergleichbare klar versionierte API.
- **Datenbank:** PostgreSQL für Konten, Geräte, Zustellung, Nachrichten-Ciphertexte, Löschjobs und Audit-Metadaten.
- **Medienobjektspeicher:** selbst gehosteter S3-kompatibler Speicher oder Dateisystem mit Zugriff über den Server; nur verschlüsselte Inhalte.
- **Push-Gateway:** plattformspezifischer Zustelldienst mit minimalem Payload.
- **Admin-API:** logisch getrennte, serverseitig autorisierte Schnittstelle; die Admin-UI ist Bestandteil des Clients.

### 2.2 Vertrauensgrenzen
1. Endgerät ↔ Server: TLS schützt Transport, ersetzt aber keine E2EE.
2. Client-Speicher ↔ Betriebssystem: PIN, Hardware-Key-Storage und Berechtigungen schützen den Schlüsselcontainer.
3. Server ↔ Datenbank/Objektspeicher: Server sieht Ciphertexte, Routing-Metadaten und Verwaltungsdaten.
4. Admin-Client ↔ Admin-API: gesonderte Authentisierung, kurzlebige Berechtigungen, strikte Autorisierung und Audit.
5. Push-Anbieter: darf keinen Nachrichtentext oder Medieninhalt erhalten.

## 3. Technologieauswahl und ADRs

Vorschlag, keine endgültige Festlegung:
- Rust für gemeinsamen Core oder Server; Go ist eine Alternative für den Server.
- Kotlin für Android.
- PostgreSQL für strukturierte Daten.
- Objekt-Storage für verschlüsselte Medien.
- Signal Protocol für 1:1 und MLS (RFC 9420) für Gruppen sind zu evaluierende Kandidaten. Bibliotheksreife, Lizenz, Plattformunterstützung, Interoperabilität und Sicherheitsreview sind zu prüfen.
- Android Keystore; Linux Secret Service und optional TPM2.

Vor dem produktiven Einsatz sind ADRs erforderlich für E2EE-Protokoll, Gruppenverwaltung, PIN/Hardwarebindung, Medienformat, Löschsemantik/Backups, Admin-Authentisierung und Linux-UI.

## 4. Schlüsselmodell und PIN

### 4.1 Geräteschlüssel
Jedes Gerät erzeugt ein eigenes Schlüsselpaar für die Geräteidentität. Private Schlüssel verlassen das Gerät nicht. Das konkrete Protokoll bestimmt weitere Identitäts-, Prekey- und Sitzungsschlüssel.

### 4.2 PIN-geschützter lokaler Container
- Erzeuge einen zufälligen Salt pro lokalem Container.
- Leite aus dem sechsstelligen PIN mit Argon2id einen Schlüsselableitungswert ab.
- Nutze diesen nur als Schlüsselverschlüsselungsschlüssel (KEK), um einen zufälligen Master Encryption Key (MEK) zu schützen.
- Der MEK verschlüsselt den lokalen E2EE-Schlüsselcontainer mit authentifizierter Verschlüsselung.
- PIN und abgeleitete Geheimnisse werden nie an den Server gesendet.
- Hardwarebindung und Betriebssystemschutz sind einzubeziehen, soweit verfügbar.
- Die Zielgröße von etwa drei Sekunden für die Ableitung ist auf repräsentativen Geräten zu benchmarken. Parameter müssen pro Plattform sinnvoll sein; eine fixe Wartezeit ist keine kryptografische Sicherheitsgarantie.
- Da sechsstellige PINs nur eine Million Kombinationen haben, bleibt ein kopierter Offline-Container ein relevantes Risiko. Dokumentiere dieses Risiko und erwäge eine längere Passphrase oder zwingende Hardwarebindung.

## 5. Geräte-Onboarding und Authentisierung

1. Client erzeugt Geräteidentität und einen Nachweis des Besitzes des privaten Schlüssels.
2. Client registriert Gerät als `pending`.
3. Server stellt einen begrenzten Enrollment-Status bereit, aber keinen regulären Nachrichtenzugriff.
4. Admin prüft Anfrage im Adminbereich und genehmigt oder lehnt sie ab.
5. Server setzt Status auf `active` oder verwirft die Anfrage.
6. Aktive Geräte verwenden Proof-of-Possession bzw. protokollgerechte Geräteauthentisierung; nicht allein ein langlebiges Bearer-Token.
7. Deaktivierte/widerrufene Geräte werden serverseitig abgewiesen. Sitzungen und Tokens werden widerrufen oder laufen kurzfristig aus.

## 6. Client-Zustandsmodell und lokaler Schutz

- `locked`: keine Chat-Klartexte sichtbar.
- `unlocking`: PIN wird geprüft und Schlüsselcontainer geöffnet.
- `unlocked`: nur notwendige Inhalte werden im Speicher gehalten.
- `chat_active`: Inhalt des gewählten Chats ist im UI sichtbar.
- `leaving_chat`: UI-Zustand, Vorschau-Puffer und temporäre Klartextdaten werden soweit möglich verworfen.
- `backgrounded`: sensible Ansichten werden auf Android abgedeckt; Verhalten auf Linux ist best effort.
- `locked_after_timeout`: Schlüssel werden geschlossen/aus dem aktiven Zustand entfernt, soweit Laufzeit und Plattform dies zulassen.

Es wird keine garantierte physische RAM-Löschung versprochen. Dauerhafte Klartext-Caches sind zu vermeiden. Betriebssystem-Swap, Crash-Dumps und Backups sind als Risiko zu bewerten.

## 7. Nachrichten- und Gruppenmodell

### 7.1 Senden
1. Client prüft Mitgliedschaft und Gerätestatus.
2. E2EE-Protokoll verschlüsselt die Nachricht für die vorgesehenen Empfänger.
3. Client sendet Ciphertext, Routingdaten und Idempotenz-ID.
4. Server speichert/queued Ciphertext und liefert ihn an aktive Geräte aus.
5. Server darf Nachrichtentext nicht entschlüsseln.

### 7.2 Abruf
- Cursorbasierte Pagination, Standardlimit 100.
- Server liefert ausschließlich Ciphertexte und minimale Metadaten.
- Client entschlüsselt nach Protokollprüfung lokal.
- Cursor und Sortierung müssen bei parallel eintreffenden Nachrichten stabil sein.

### 7.3 Gruppen
Mitgliedschaftsänderungen müssen die Gruppen-Schlüsselverwaltung berücksichtigen. Nach Entfernung eines Mitglieds müssen zukünftige Nachrichten für dieses Mitglied unlesbar sein. Das konkrete Re-Keying folgt dem gewählten Gruppenprotokoll.

## 8. Verbindliche globale Löscharchitektur

### 8.1 Semantik
Es gibt genau eine fachliche Löschoperation: **Löschen für alle**. Es gibt weder einen lokalen „nur für mich“-Modus noch einen entsprechenden API-Endpunkt. Das gilt für Einzelchats, Gruppen, Nachrichten und Medien.

### 8.2 Ablauf einer Nutzerlöschung
1. Client sendet eine authentisierte Löschanforderung mit Nachrichten-ID und eindeutiger Operations-ID.
2. Server prüft, ob der Initiator nach Produktregeln zum Löschen berechtigt ist.
3. Server legt einen idempotenten Löschjob an.
4. Betroffene Nachricht wird sofort für weitere Auslieferung gesperrt bzw. als nicht auslieferbar markiert.
5. Aktive Datenbankdatensätze und Medienobjekte werden entfernt oder in einen kontrollierten Purge-Prozess überführt, der ihre weitere Auslieferung zuverlässig verhindert.
6. Löschereignis wird an alle Mitglieder und Geräte der Unterhaltung zugestellt.
7. Online-Clients entfernen den Inhalt aus UI und App-Caches. Offline-Clients verarbeiten das Ereignis beim nächsten Sync, bevor sie die betroffene Nachricht erneut anzeigen.
8. Status und Fehler werden nachvollziehbar aktualisiert.

### 8.3 Idempotenz und Race Conditions
- Wiederholte Anfragen mit gleicher Operations-ID erzeugen keine mehrfachen widersprüchlichen Aktionen.
- Löschung und Zustellung müssen transaktional oder über ein Outbox-/Event-Pattern koordiniert werden.
- Eine Nachricht, deren Löschung bereits akzeptiert wurde, darf bei Retries nicht erneut ausgeliefert werden.
- Offline-Sync muss Lösch-Tombstones oder gleichwertige Ereignisse lange genug erhalten, um veraltete lokale Kopien zu bereinigen. Tombstones enthalten keine Klartexte.

### 8.4 Medienlöschung
Die Löschoperation umfasst:
- verschlüsselte Originaldatei,
- verschlüsselte Vorschau,
- Chunk-/Multipart-Objekte,
- Objekt-Storage-Referenzen,
- Datenbankmetadaten,
- abgeleitete Thumbnails oder sonstige serverseitige Derivate.

Der Server darf bei bereits angenommenem Löschjob keine dieser aktiven Objektreferenzen erneut ausliefern.

### 8.5 Backup- und Replikatstrategie
- Backups und Replikate besitzen dokumentierte Aufbewahrungsfristen.
- Der Löschstatus unterscheidet aktive Daten entfernt, Replikatbereinigung ausstehend und Backup-Purge abgeschlossen.
- Backups können gegebenenfalls durch Ablauf der Retention und kontrollierte Neu-Erstellung bereinigt werden; das konkrete Verfahren wird per ADR festgelegt.
- Das System behauptet nicht, sämtliche Kopien seien sofort vernichtet, wenn Backups noch bestehen.
- Ein kompromittierter oder bösartiger Server kann Kopien behalten. Dies bleibt ein dokumentiertes Restrisiko.

### 8.6 Grenzen
Die App kann Inhalte, die Empfänger bereits exportiert, kopiert, fotografiert oder außerhalb der App gespeichert haben, nicht zuverlässig zurückrufen. „Für alle löschen“ gilt für kontrollierte App-/Serverdaten und die Synchronisierung der Clients, nicht für beliebige externe Kopien.

## 9. Verschlüsselte Medien

1. Client generiert geeignete zufällige Medienschlüssel.
2. Vorschau und Original werden mit getrennten Schlüsseln oder einer klar dokumentierten Schlüsselableitung authentifiziert verschlüsselt.
3. Server speichert ausschließlich Ciphertexte.
4. Chatliste lädt zunächst nur Vorschauobjekte bzw. die für Vorschauen nötigen Daten.
5. Original wird erst nach explizitem Tap heruntergeladen.
6. Chunking/Streaming nutzt authentifizierte Verschlüsselung und eindeutige Nonces nach den Regeln der gewählten Bibliothek.
7. Export in Gerätespeicher ist eine explizite Nutzeraktion und verlässt den Schutzbereich der App.

## 10. Admin-Oberfläche und Admin-API

### 10.1 UI-Bereiche
- Übersicht mit offenen Geräteanfragen und Sicherheitsereignissen.
- Geräteanfragen: freigeben/ablehnen.
- Geräteverwaltung: deaktivieren, widerrufen, Status ansehen.
- Kontenverwaltung.
- Massenlöschung aller serverseitigen Nachrichten und Medien einer ausgewählten Person.
- Löschjobstatus einschließlich Fehlern und Backup-Purge-Status.
- Audit-Protokoll.

### 10.2 Authentisierung und Autorisierung
- Admin-Authentisierung ist von normaler Chat-Authentisierung logisch getrennt.
- Admin-API prüft Berechtigungen serverseitig bei jeder Anfrage; UI-Rollen oder versteckte Menüs reichen nicht.
- Kurzlebige Tokens, minimale Scopes, Rate-Limits und erneute Authentisierung für besonders destruktive Aktionen.
- Ein SSH-Privatschlüssel wird nicht in der Chat-App abgelegt. SSH bleibt eine separate Server-Administrationsoption oder ein kontrollierter Zugangsweg.
- Administrative Befehle protokollieren Admin-ID, Zeit, Aktion, Ziel, Ergebnis und Korrelations-ID.
- Adminrechte gewähren keinen Zugriff auf E2EE-Schlüssel oder Nachricht-Klartexte.

### 10.3 Massenlöschung nach Person
Empfohlener Umfang: alle serverseitigen Nachrichten und Medien, die vom Zielkonto stammen, über alle Unterhaltungen hinweg. Nachrichten anderer Absender in denselben Gruppen bleiben bestehen. Vor Ausführung zeigt die UI das Zielkonto und den Umfang; Bestätigung ist obligatorisch. Die Aktion erzeugt einen asynchronen Löschjob mit Fortschritt, Teilergebnissen und Audit-Eintrag.

## 11. Datenmodell (konzeptionell)

- `accounts(id, status, created_at, ...)`
- `devices(id, account_id, public_identity_key, status, created_at, approved_at, revoked_at, ...)`
- `conversations(id, type, created_at, ...)`
- `conversation_members(conversation_id, account_id, status, ...)`
- `messages(id, conversation_id, sender_account_id, ciphertext, sequence, created_at, delivery_state, ...)`
- `media_objects(id, message_id, encrypted_object_ref, kind, size, purge_state, ...)`
- `delete_jobs(id, operation_id, requested_by, scope, status, created_at, completed_at, error_summary, ...)`
- `push_endpoints(id, device_id, token, status, ...)`
- `admin_audit_events(id, admin_account_id, action, target, result, correlation_id, created_at, ...)`

Keine Servertabelle enthält E2EE-Privatschlüssel oder Nachricht-Klartexte. Die endgültigen Constraints und Indizes werden in Migrationen spezifiziert.

## 12. API-Skizze

- `POST /v1/devices/enroll`
- `GET /v1/devices/status`
- `POST /v1/messages`
- `GET /v1/conversations/{id}/messages?cursor=...&limit=100`
- `POST /v1/messages/{id}/delete-for-all`
- `GET /v1/delete-jobs/{id}`
- `POST /v1/media`
- `GET /v1/media/{id}/preview`
- `GET /v1/media/{id}/content`
- `POST /v1/admin/devices/{id}/approve`
- `POST /v1/admin/devices/{id}/disable`
- `POST /v1/admin/devices/{id}/revoke`
- `POST /v1/admin/accounts/{id}/delete-all-content`
- `GET /v1/admin/delete-jobs/{id}`
- `GET /v1/admin/audit-events`

Es gibt ausdrücklich keinen Endpoint für „nur für mich löschen“. API-Spezifikation und Fehlercodes sind vor Implementierung per OpenAPI zu definieren.

## 13. Push und Metadaten

- Push-Payload enthält keine Nachrichtentexte, Medien oder Vorschauen.
- Sichtbare Benachrichtigung zeigt höchstens den Anfangsbuchstaben des Absenders.
- Wo möglich, enthält Push nur einen zufälligen Wake-up-/Sync-Hinweis.
- Push-Anbieter können Zustellzeitpunkte und Geräte-Token sehen; dies ist im Datenschutzmodell offenzulegen.

## 14. Sicherheits- und Teststrategie

### 14.1 Kryptografie
- Nutze Testvektoren der gewählten Protokollbibliotheken.
- Teste Schlüsselrotation, Gerätereaktivierung, Widerruf, Gruppenänderungen und ungültige Ciphertexte.
- Führe keine eigene Implementierung von Algorithmen oder Protokollbausteinen ein.

### 14.2 Löschung
1. UI/API enthalten keine Aktion „nur für mich löschen“.
2. Löschung in Einzel- und Gruppenchats blockiert weitere Serverauslieferung.
3. Alle Mitglieder erhalten Löschereignisse; Offline-Clients wenden sie beim nächsten Sync an.
4. Retries, doppelte Events, parallele Löschungen und Race Conditions sind getestet.
5. Medienlöschung deckt Original, Vorschau, Chunks und Metadaten ab.
6. Backup-Bereinigung hat eigenen Status und wird nicht als sofort abgeschlossen ausgegeben.
7. Nach bestätigter Löschung kann der Server den aktiven Inhalt nicht über normale API-Pfade erneut ausliefern.

### 14.3 Administration
1. Nicht-Admins können Admin-UI und Admin-API nicht verwenden.
2. Manipulierte Requests werden serverseitig abgewiesen.
3. Freigabe, Deaktivierung und Widerruf wirken auf bestehende und neue Sitzungen.
4. Massenlöschung verlangt Bestätigung, zeigt Status/Fehler und erzeugt Audit-Eintrag.
5. Admin-Aktionen geben keine E2EE-Schlüssel frei und erzeugen keinen Klartextzugriff.

### 14.4 Client-Sicherheit
- PIN-Brute-Force-Schutz und Schlüsselcontainer testen.
- Keine sensiblen Inhalte in Logs, Crash-Dumps oder Push-Payloads.
- Screenshot-Schutz auf Android prüfen; Grenzen dokumentieren.
- Linux-Dateirechte, Keyring-Integration, temporäre Dateien und Swap-Risiken prüfen.

## 15. Betrieb und Incident Response

- TLS-Zertifikatsverwaltung, sichere Secrets und regelmäßige Updates.
- Datenbank- und Objektspeicher-Backups verschlüsseln und Zugriff beschränken.
- Retention und Backup-Purge regelmäßig testen.
- Gerätewiderruf und Admin-Zugang bei Kompromittierung schnell deaktivieren können.
- Audit-Logs gegen unbemerkte Manipulation schützen.
- Sicherheitsupdates signieren und nachvollziehbar veröffentlichen.

## 16. Definition of Done für eine Sicherheitsfreigabe

- Threat Model und ADRs genehmigt.
- E2EE-Bibliotheken und Lizenzen geprüft.
- Kein Nachrichten-Klartext auf dem Server.
- Kein „nur für mich löschen“ in UI oder API.
- Globale Löschung einschließlich Offline-Synchronisierung und Medien getestet.
- Adminoberfläche mit serverseitiger Autorisierung, Bestätigung und Audit vorhanden.
- PIN- und Gerätesicherheitsannahmen dokumentiert.
- Backup-/Replikat-Bereinigung mit klaren Statuswerten umgesetzt.
- Automatisierte Sicherheits-, Integrations- und Migrationstests bestehen.
- Unabhängiger Security Review vor produktivem Einsatz abgeschlossen.

## 17. Referenzen

- Signal Protocol: https://signal.org/docs/
- MLS RFC 9420: https://www.rfc-editor.org/rfc/rfc9420
- OWASP MASVS: https://mas.owasp.org/MASVS/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
