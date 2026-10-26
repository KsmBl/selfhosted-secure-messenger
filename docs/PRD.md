# Product Requirements Document (PRD)
## Self-hosted, Ende-zu-Ende-verschlüsselter Messenger für Android und Linux

**Status:** Freigegeben zur Umsetzung (Phase 0 abgeschlossen)  
**Version:** 1.2  
**Sprache:** Deutsch  
**Änderungen gegenüber 1.1:** siehe Abschnitt 13

## 1. Ziel und Produktumfang

Entwickelt wird ein selbst gehosteter Messenger mit Android- und Linux-Clients. Die Anwendung unterstützt Einzel- und Gruppenchats, Ende-zu-Ende-Verschlüsselung (E2EE), Konten per Einladung, manuelle Gerätefreigabe, verschlüsselte Medien, datensparsame Push-Benachrichtigungen und eine in die Chat-App integrierte Administrationsoberfläche.

Verbindliche Produktregeln:
1. **Jede Löschung ist eine Löschung für alle.** Eine Funktion „nur für mich löschen" existiert nicht – weder in der Benutzeroberfläche noch in der API. **Jeder Teilnehmer einer Unterhaltung darf jede Nachricht dieser Unterhaltung für alle löschen.**
2. **Administration findet in einer eigenen Oberfläche innerhalb der Chat-App statt.** Sie ist nur für autorisierte Admin-Clients zugänglich und serverseitig abgesichert.
3. **Administratoren erhalten durch ihre Adminrechte keinen Zugriff auf E2EE-Klartexte oder private E2EE-Schlüssel.** Der Betreiber des Servers ist für die Gerätefreigabe vertrauenswürdig; das daraus folgende Restrisiko ist in Abschnitt 3 dokumentiert (ADR-0003).
4. **Der Client speichert keinen Nachrichtenverlauf.** Verschlüsselte Nachrichten liegen ausschließlich auf dem Server und werden zur Anzeige heruntergeladen und im Arbeitsspeicher entschlüsselt (ADR-0002).

## 2. Ziele

- Nachrichten und Medien ausschließlich Ende-zu-Ende-verschlüsselt übertragen und speichern.
- Konten nur per Admin-Einladung anlegen; neue Geräte erst nach manueller Freigabe zulassen.
- Bei Verlust eines Geräts dessen Zugang serverseitig sperren oder widerrufen können.
- Nachrichten in Seiten zu je 100 Einträgen vom Server laden und lokal im Arbeitsspeicher entschlüsseln.
- Nachrichten nach einer pro Chat einstellbaren Frist (Standard 90 Tage, 1–365 Tage) automatisch serverseitig löschen.
- Nachrichten und Medien global löschen und die Löschung an alle Clients verteilen.
- Chat-Inhalte beim Verlassen eines Chats aus dem Arbeitsspeicher und lokalen App-Caches entfernen, soweit technisch möglich.
- Push-Nachrichten ohne Inhalt versenden; als sichtbaren Hinweis höchstens den Anfangsbuchstaben des Absenders verwenden.
- Ein 5×5-Entsperrmuster zum lokalen Entsperren unterstützen und Offline-Brute-Force-Angriffe durch Argon2id, Hardwarebindung und Fehlversuchsverzögerung erschweren.
- Medienvorschauen zunächst separat verschlüsselt laden und Originaldateien erst auf ausdrückliche Aktion herunterladen.
- Administration direkt in der Chat-App anbieten.

## 3. Nicht-Ziele, Sicherheitsgrenzen und akzeptierte Restrisiken

- Kein Schutz gegen jede Form eines kompromittierten oder bereits entsperrten Endgeräts.
- Kein zuverlässiges Zurückholen von Inhalten, die Empfänger zuvor exportiert, kopiert, fotografiert oder außerhalb der App gespeichert haben.
- Keine Garantie, dass ein bösartiger Server tatsächlich jede Kopie vernichtet. Backups, Replikate und Speicher-Snapshots benötigen eigene Bereinigungsregeln.
- Screenshot-Sperren sind plattformabhängig und verhindern keine externe Kameraaufnahme.
- **Vertrauenswürdiger Betreiber (ADR-0003):** Ein Administrator oder Angreifer mit Serverkontrolle kann ein eigenes Gerät unter einem fremden Konto freigeben. Dieses Gerät empfängt danach künftige Nachrichten des Kontos. Dieses Risiko wird bewusst akzeptiert; der Betreiber gilt als vertrauenswürdig für die Gerätefreigabe.
- **Eingeschränkte Forward Secrecy (ADR-0001/0002):** Weil der Verlauf serverseitig liegt und wiederholt entschlüsselt wird, hält der Client einen Schlüsselbund. Wer den Schlüsselbund eines entsperrten Geräts erbeutet, kann den serverseitigen Verlauf der betroffenen Zeiträume lesen.
- **Kurzes Entsperrmuster (ADR-0005):** Die Mindestlänge von 6 Eingaben ergibt theoretisch ca. 28 Bit; menschlich gewählte Muster liegen deutlich darunter. Ohne Hardwarebindung ist ein kopierter Container offline angreifbar.
- **Löschung durch beliebige Teilnehmer (ADR-0004):** Jedes Mitglied einer Gruppe kann Beiträge anderer für alle entfernen.

## 4. Rollen

### 4.1 Nutzer
- Erhält ein Konto über einen Einladungscode und registriert damit sein erstes Gerät.
- Kann nach Freigabe Einzel- und Gruppenchats verwenden.
- Kann Nachrichten und Medien senden und jede Nachricht seiner Unterhaltungen **für alle** löschen.
- Kann die Aufbewahrungsfrist eines Chats ändern.
- Kann Medien explizit auf das Gerät exportieren.
- Kann eigene Geräte und ausstehende Gerätefreigaben einsehen.

### 4.2 Administrator
- Verwendet einen Client mit gesondertem Admin-Schlüsselpaar (ADR-0006).
- Erhält innerhalb der Chat-App einen separaten Administrationsbereich.
- Erstellt Konten und Einladungscodes.
- Kann Geräteanfragen freigeben oder ablehnen, Geräte deaktivieren/widerrufen, Konten und Geräte verwalten sowie serverseitige Nachrichten und Medien einer ausgewählten Person global löschen.
- Sieht bei Geräteanfragen nur Gerätebezeichnung, Benutzername und Schlüssel-Fingerprint – keine Inhalte.
- Kann Status von Löschaufträgen und administrative Audit-Einträge einsehen.
- Erhält **keine** E2EE-Schlüssel und keine Klartext-Leseberechtigung aufgrund der Adminrolle.

### 4.3 Erster Administrator
Der erste Administrator und sein Admin-Schlüssel werden über eine Server-CLI (lokal bzw. per SSH) angelegt.

## 5. Funktionale Anforderungen

### FR-001 – Geräteidentität und manuelle Freigabe
Jedes Gerät erzeugt eine eigene kryptografische Identität (Geräte-Signaturschlüssel und E2EE-Identitätsschlüssel). Neue Geräte befinden sich zunächst im Status `pending` und dürfen keine regulären Nachrichten senden oder empfangen, bis ein Administrator sie einmalig freigibt.

### FR-002 – Geräteverwaltung
Gerätestatus: `pending`, `active`, `disabled`, `revoked`, `rejected`.
- `disabled` ist reversibel (z. B. Gerät vorübergehend verlegt).
- `revoked` und `rejected` sind endgültig: das Gerät wird vollständig gelöscht (Sitzungen, Schlüssel, Ereignisse) und muss sich neu registrieren. Von ihm gesendete Nachrichten bleiben für die anderen lesbar.
Statusänderungen werden serverseitig autorisiert und protokolliert. `disabled`/`revoked` verhindern sofort weitere authentisierte API-Zugriffe; bestehende Sitzungen werden beendet.

### FR-003 – Entsperrmuster und lokaler Schlüsselcontainer
Der Client wird mit einem Muster auf einem 5×5-Punkteraster entsperrt. Das Muster ist eine Folge von Punktberührungen; jeder Punkt darf beliebig oft und in beliebiger Reihenfolge berührt werden. Anforderungen:
- Mindestlänge 6 Eingaben, Höchstlänge 64.
- Triviale Muster werden abgelehnt (z. B. nur ein Punkt wiederholt, eine einzelne gerade Reihe/Spalte/Diagonale, die vier Ecken).
- Keine sichtbare Spur der Eingabe; kein Hervorheben gedrückter Punkte über eine kurze Berührungsrückmeldung hinaus.
- Das Muster wird niemals an den Server übertragen.
- Argon2id mit zufälligem Salt und anschließende HKDF-Ableitung erzeugen einen Schlüsselverschlüsselungsschlüssel, der einen zufälligen Datenschlüssel schützt. Der Datenschlüssel verschlüsselt den lokalen Schlüsselcontainer.
- Hardware-Key-Storage (Android Keystore/StrongBox, Linux TPM2) wird eingebunden, wo verfügbar und zugänglich. Geräte ohne TPM bzw. TPM2 bleiben voll nutzbar; dort schützt allein das Muster mit Argon2id (dokumentiertes Restrisiko).
- Zielgröße ca. drei Sekunden Ableitungszeit auf unterstützten Geräten; Fehlversuche führen zu steigenden Wartezeiten.
- Das Entsperrmuster gilt auf Android und Linux. Das Admin-Schlüsselpaar hat ein eigenes, separates Muster.

### FR-004 – Einzel- und Gruppenchats
Einzel- und Gruppennachrichten werden clientseitig verschlüsselt. Änderungen der Gruppenmitgliedschaft erzwingen eine neue Gruppensitzung; entfernte Mitglieder können künftig gesendete Nachrichten nicht entschlüsseln.

### FR-005 – Ende-zu-Ende-Verschlüsselung
Der Server verarbeitet nur die für Routing, Zustellung und Speicherung nötigen Metadaten und Ciphertexte. Verwendet wird Olm/Megolm über die geprüfte Bibliothek `vodozemac` (ADR-0001). Eigenentwickelte Kryptografie ist nicht zulässig.

### FR-006 – Nachrichtenverlauf und Paginierung
Der Client speichert keinen Nachrichtenverlauf. Zur Anzeige lädt er Ciphertexte cursorbasiert in Seiten zu 100 Einträgen und entschlüsselt sie im Arbeitsspeicher. Dauerhaft gespeichert werden auf dem Client nur Schlüssel (verschlüsselt im Container), niemals Nachrichteninhalte.

### FR-007 – Globale Löschung ist die einzige Löschfunktion
Es gibt **keine** Funktion „nur für mich löschen", kein lokales alternatives Löschziel und keinen entsprechenden API-Endpunkt. Jede Löschaktion bedeutet „für alle Teilnehmer löschen". Berechtigt ist jedes aktive Mitglied der Unterhaltung, unabhängig vom Absender.

### FR-008 – Globale Löschung von Nachrichten
Eine berechtigte Löschanfrage erzeugt einen idempotenten Löschauftrag mit eindeutiger Operations-ID. Der Server verhindert die weitere Auslieferung der betroffenen Nachricht, entfernt aktive serverseitige Datensätze und verteilt ein Löschereignis an alle Mitglieder der Unterhaltung. Offline-Clients übernehmen das Ereignis beim nächsten Synchronisieren und entfernen betroffene Inhalte aus Arbeitsspeicher und App-Caches. In der Unterhaltung wird angezeigt, dass eine Nachricht gelöscht wurde (ohne Inhalt).

### FR-009 – Globale Löschung von Medien
Die Löschung umfasst die Nachricht sowie alle dazugehörigen Originaldateien, verschlüsselten Vorschaudateien, Chunks, Objekt-Referenzen und serverseitigen Metadaten. Aktive Speicher dürfen gelöschte Objekte nicht erneut ausliefern.

### FR-010 – Löschstatus und Backup-Bereinigung
Der Status unterscheidet mindestens: `requested`, `in_progress`, `active_removed`, `backup_purge_pending`, `backup_purge_done`, `failed`. Backups, Replikate und Snapshots folgen einer dokumentierten Aufbewahrungsfrist (Standard: 30 Tage). Eine vollständige Bereinigung darf nicht vorgetäuscht werden, solange Kopien in Backups verbleiben.

### FR-011 – Verschlüsselte Medien und Vorschauen
Bilder, Videos und Audiodateien werden vor dem Upload auf dem Client verschlüsselt. Vorschaudateien werden separat verschlüsselt. Beim Öffnen eines Chats werden zunächst nur verschlüsselte Vorschauen geladen. Die vollständige Mediendatei wird erst nach expliziter Nutzeraktion heruntergeladen und nur im Arbeitsspeicher bzw. einem beim Verlassen des Chats gelöschten App-Cache gehalten.

### FR-012 – Expliziter Medienexport
Das Speichern eines Mediums in den allgemeinen Gerätespeicher erfordert eine bewusste Nutzeraktion. Der Client weist darauf hin, dass exportierte Dateien außerhalb der Kontrolle der App liegen und durch spätere globale Löschung oder Ablauf nicht entfernt werden.

### FR-013 – Arbeitsspeicher und lokale Daten
Nach Verlassen eines Chats entfernt der Client Chat-Inhalte aus UI-Zustand, Puffern und lokalen App-Caches. Klartextnachrichten werden nie dauerhaft gespeichert. RAM-Bereinigung ist best effort und wird nicht als garantierte sichere Speicherlöschung beworben.

### FR-014 – Screenshot-Schutz
Android setzt `FLAG_SECURE` für alle Fenster mit Chat- oder Admin-Inhalten. Linux-Clients weisen auf die eingeschränkte Durchsetzbarkeit hin. Externe Fotoaufnahmen können nicht verhindert werden.

### FR-015 – Push-Privatsphäre
Push-Payloads sind reine Weck-Signale ohne Inhalt, ohne Absender und ohne Unterhaltungsbezug. Android nutzt UnifiedPush, mit Firebase Cloud Messaging (FCM) als Fallback (ADR-0008). Linux nutzt eine dauerhafte WebSocket-Verbindung. Nach dem Wecken fragt der Client über TLS den Benachrichtigungshinweis ab; angezeigt wird höchstens der Anfangsbuchstabe des Absenders. Push-Anbieter können Zustellzeitpunkte und Gerätetoken sehen.

### FR-016 – In-App-Adminoberfläche
Der Chat-Client enthält einen separaten Administrationsbereich. Dieser wird nur nach erfolgreicher Admin-Authentifizierung mit dem Admin-Schlüsselpaar freigeschaltet. UI-Sichtbarkeit gilt nicht als Sicherheitsgrenze; jeder Admin-Endpunkt prüft die Berechtigung serverseitig.

### FR-017 – Admin-Geräte- und Kontoverwaltung
Der Admin kann Konten und Einladungscodes erstellen, ausstehende Geräteanfragen freigeben/ablehnen, Geräte deaktivieren, reaktivieren oder widerrufen und Konten bzw. deren Geräte verwalten.

### FR-018 – Admin-Massenlöschung
Der Admin kann eine Person auswählen und alle von ihr stammenden serverseitigen Nachrichten und Medien über alle Unterhaltungen hinweg global löschen. Beiträge anderer Personen bleiben bestehen. Vor der Ausführung werden Zielkonto und Umfang angezeigt; eine explizite Bestätigung und erneute Admin-Authentisierung sind erforderlich. Ergebnis, Fehler und Teilerfolge werden dargestellt und protokolliert.

### FR-019 – Admin-Authentifizierung und API
Administrative Aktionen laufen über eine getrennte, minimal berechtigte Admin-API. Die Authentisierung erfolgt per Challenge-Response mit einem separaten Admin-Schlüsselpaar im Hardware-Key-Storage, entsperrt durch ein eigenes Muster (ADR-0006). Admin-Tokens sind kurzlebig (max. 10 Minuten); destruktive Aktionen erfordern eine frische Signatur. Ein SSH-Privatschlüssel wird nicht in der Chat-App gespeichert; SSH bleibt separater Administrationsweg.

### FR-020 – Audit-Log
Admin-Aktionen protokollieren mindestens Admin-Identität, Zeit, Aktion, Ziel, Ergebnis und Korrelations-ID. Das Log ist zugriffsbeschränkt und über eine Hash-Kette gegen unbemerkte nachträgliche Änderung geschützt.

### FR-021 – Least Privilege
Normale Konten dürfen keine Admin-Aktionen ausführen. Adminrechte erlauben keine Entschlüsselung von E2EE-Inhalten.

### FR-022 – Transport- und API-Sicherheit
TLS, Proof-of-Possession-Geräteauthentisierung, Autorisierung pro Objekt, Rate-Limits, Replay-Schutz, Eingabevalidierung und sichere Session-Verwaltung sind erforderlich.

### FR-023 – Update-Sicherheit
Release-Artefakte werden signiert. Der Update-Prozess prüft Signaturen und verhindert Downgrades, soweit die Plattform dies unterstützt.

### FR-024 – Minimierung von Metadaten
Nur notwendige Zustell- und Verwaltungsmetadaten werden gespeichert. Aufbewahrungsfristen und Zugriffsrechte sind dokumentiert.

### FR-025 – Aufbewahrungsfrist pro Chat
Jede Unterhaltung hat eine Aufbewahrungsfrist von 1 bis 365 Tagen (Standard 90 Tage). Jedes aktive Mitglied kann die Frist ändern. Jede Änderung erzeugt einen Systemhinweis in der Unterhaltung, den alle Mitglieder sehen. Der Server löscht abgelaufene Nachrichten und Medien automatisch nach denselben Regeln wie eine globale Löschung. Eine Verkürzung wirkt sofort auch auf bereits vorhandene Nachrichten.

### FR-026 – Konten per Einladung
Konten werden ausschließlich von Administratoren angelegt. Dabei entsteht ein einmalig verwendbarer, zeitlich begrenzter Einladungscode (Standard 7 Tage). Mit dem Code registriert der Nutzer sein erstes Gerät; dieses Gerät muss zusätzlich vom Admin freigegeben werden. Weitere Geräte registrieren sich mit Benutzername und durchlaufen ebenfalls die Admin-Freigabe.

### FR-027 – Gruppenrechte
In einer Gruppe darf jedes Mitglied austreten. Nur der Gruppen-Admin darf Personen einladen und andere Mitglieder entfernen. Admin ist zunächst der Ersteller; verlässt der Admin die Gruppe, übernimmt das am längsten beteiligte verbleibende Mitglied. Die Änderung erscheint als Systemhinweis.

### FR-028 – Konten löschen
Administratoren können ein Konto vollständig löschen. Dabei werden alle Nachrichten des Kontos für alle gelöscht, das Konto verlässt alle Unterhaltungen (Systemhinweis mit dem Namen; Gruppen erhalten bei Bedarf einen neuen Admin), Geräte, Schlüssel, Sitzungen und Einladungen werden entfernt, und der Benutzername wird wieder frei. Die Löschung wird im Audit-Log protokolliert.

## 6. Admin-Oberfläche: Mindestansichten

1. **Übersicht:** ausstehende Anfragen, aktive/deaktivierte Geräte, aktuelle administrative Ereignisse.
2. **Geräte:** Suche nach Konto/Gerät, Freigabe, Ablehnung, Deaktivierung, Reaktivierung, Widerruf.
3. **Konten:** Konto anlegen, Einladungscode erzeugen, Kontostatus und zugehörige Geräte.
4. **Globale Massenlöschung:** Person auswählen, Umfang prüfen, Löschung bestätigen, Fortschritt/Fehler einsehen.
5. **Audit und Löschstatus:** administrative Vorgänge und Status aktiver Speicher-/Backup-Bereinigung.

## 7. Konzeptionelles Datenmodell

- `accounts`: Konto-ID, Benutzername, Rolle, Status, Erstellungszeit.
- `invites`: Code-Hash, Konto-ID, Ablaufzeit, Verwendungszeitpunkt.
- `devices`: Geräte-ID, Konto-ID, Bezeichnung, öffentliche Schlüssel, Status, Zeitstempel.
- `admin_keys`: Konto-ID, öffentlicher Admin-Schlüssel, Status.
- `one_time_keys`: Gerät, öffentlicher Einmalschlüssel.
- `conversations`: ID, Typ, Aufbewahrungsfrist, Erstellungszeit.
- `conversation_members`: Unterhaltung, Konto, Mitgliedschaftsstatus.
- `messages`: ID, Unterhaltung, Absender, Ciphertext, Sequenz, Zeit, Ablaufzeit, Status.
- `media_objects`: ID, Nachrichten-ID, verschlüsselte Objekt-Referenz, Typ, Größe, Löschstatus.
- `events`: Sequenz pro Konto/Gerät, Typ (Nachricht, Löschung, Friständerung, Mitgliedschaft), Bezug – ohne Klartext.
- `delete_jobs`: Operations-ID, Initiator, Zielumfang, Status, Zeitstempel, Fehlerdetails.
- `push_endpoints`: Gerätebezug, Typ (UnifiedPush/FCM), Endpunkt/Token, Status.
- `admin_audit_events`: Admin-ID, Aktion, Ziel, Ergebnis, Zeit, Korrelations-ID, Hash-Kette.

Keine Tabelle enthält E2EE-Privatschlüssel oder Nachricht-Klartexte.

## 8. API-Bereiche (konzeptionell)

Nutzer-API:
- `POST /v1/auth/challenge`, `POST /v1/auth/session`
- `POST /v1/devices/enroll/challenge`, `POST /v1/devices/enroll` (mit Einladungscode oder Benutzername)
- `GET /v1/devices/status`, `GET /v1/devices` (eigene Geräte)
- `POST /v1/keys/one-time`, `POST /v1/keys/claim`, `GET /v1/accounts/{id}/devices`
- `GET|POST /v1/conversations`, `GET /v1/conversations/{id}`, `POST /v1/conversations/{id}/members`, `DELETE /v1/conversations/{id}/members/{account}`
- `PUT /v1/conversations/{id}/retention`
- `GET /v1/conversations/{id}/messages?before=...|after=...&limit=100`, `POST /v1/conversations/{id}/messages`
- `POST /v1/messages/{id}/delete-for-all`
- `GET /v1/delete-jobs/{id}`
- `GET /v1/events?since=...`, `GET /v1/ws` (Echtzeitkanal)
- `GET /v1/notifications/hint`
- `PUT /v1/push-endpoint`
- `POST /v1/media`, `GET /v1/media/{id}/preview`, `GET /v1/media/{id}/content`

Admin-API:
- `POST /v1/admin/auth/challenge`, `POST /v1/admin/auth/session`, `POST /v1/admin/confirm/challenge`
- `POST /v1/admin/accounts`, `POST /v1/admin/accounts/{id}/invites`, `GET /v1/admin/accounts`
- `GET /v1/admin/devices?status=pending`
- `POST /v1/admin/devices/{id}/approve|reject|disable|enable|revoke`
- `POST /v1/admin/accounts/{id}/delete-all-content`
- `GET /v1/admin/delete-jobs/{id}`
- `GET /v1/admin/audit-events`

**Verbindlich:** Es gibt keinen Endpunkt zum Löschen nur auf dem eigenen Client. Die genaue API ist in der OpenAPI-Spezifikation beschrieben.

## 9. Akzeptanzkriterien

- Konten entstehen nur per Admin; Einladungscodes sind einmalig und laufen ab.
- Ein neues Gerät kann vor Freigabe keine regulären Nachrichten lesen oder senden.
- Das Entsperrmuster verlangt mindestens 6 Eingaben, lehnt triviale Muster ab und wird nicht an den Server gesendet.
- Nachrichten und Medien werden Ende-zu-Ende-verschlüsselt gespeichert und übertragen.
- Der Client legt keine Nachrichteninhalte dauerhaft ab.
- Pagination liefert standardmäßig höchstens 100 Nachrichten pro Seite.
- **Weder UI noch API bieten „nur für mich löschen".**
- Jedes Mitglied kann jede Nachricht der Unterhaltung für alle löschen; Nicht-Mitglieder nicht.
- Eine globale Löschung verhindert die erneute Auslieferung aus aktiven Server-Speichern und erzeugt Löschereignisse für alle Gesprächsmitglieder.
- Offline-Clients übernehmen Löschereignisse nach Wiederverbindung.
- Abgelaufene Nachrichten werden automatisch gelöscht; Friständerungen erscheinen bei allen Mitgliedern.
- Medienlöschung umfasst Vorschauen, Chunks und Metadaten.
- Backup-Bereinigung wird separat verfolgt und nicht fälschlich als sofort abgeschlossen angezeigt.
- Nur Admins mit gültigem Admin-Schlüssel können Adminoberfläche und Admin-API verwenden.
- Massenlöschung verlangt Bestätigung, liefert einen Status und erzeugt einen Audit-Eintrag.
- Adminrechte erlauben keinen Zugriff auf Klartexte oder E2EE-Schlüssel.
- Push-Payloads enthalten weder Inhalt noch Absender.

## 10. Risiken und offene Entscheidungen

- Gerätewechsel: Neue Geräte können in Version 1 nur Nachrichten lesen, die nach ihrer Freigabe gesendet wurden. Schlüsselweitergabe zwischen eigenen Geräten ist ein Kandidat für eine spätere Version.
- Kontowiederherstellung bei Verlust aller Geräte: neues Gerät, neue Identität, kein Zugriff auf alten Verlauf.
- Konkrete Backup-Werkzeuge und Replikat-Bereinigung.
- Verfügbarkeit von StrongBox/TPM2 auf Zielgeräten.

## 11. Umsetzungsphasen

0. ADRs und Bedrohungsmodell (abgeschlossen mit v1.2).
1. Server: Konten, Einladungen, Admin-Bootstrap-CLI, Geräteregistrierung, Admin-API, Audit-Log, Echtzeitkanal, OpenAPI.
2. Rust-Core: Entsperrmuster/Schlüsselcontainer, Hardwarebindung, vodozemac, Schlüsselbund, UniFFI.
3. Einzelchats auf Android und Linux, Pagination, reine RAM-Anzeige.
4. Globale Löschung, Aufbewahrungsfristen, Synchronisation, Löschstatus.
5. Gruppenchats und Sitzungsrotation.
6. Medien, verschlüsselte Vorschauen und On-Demand-Download.
7. Adminoberfläche im Client und Massenlöschung.
8. Push-Integration, Plattformhärtung, Penetrationstest und Sicherheitsreview.

## 12. Referenzen

- ADRs: `docs/adr/`
- vodozemac: https://github.com/matrix-org/vodozemac
- Olm/Megolm-Spezifikation: https://gitlab.matrix.org/matrix-org/olm/-/tree/master/docs
- UnifiedPush: https://unifiedpush.org/
- OWASP MASVS: https://mas.owasp.org/MASVS/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/

## 13. Änderungen gegenüber Version 1.1

- E2EE-Protokoll festgelegt: Olm/Megolm via vodozemac (statt Signal/MLS-Kandidaten).
- Kein clientseitiger Verlauf; Server ist einziger (verschlüsselter) Verlaufsspeicher.
- Neue Aufbewahrungsfrist pro Chat (FR-025).
- Löschberechtigung: jeder Teilnehmer.
- Betreiber als vertrauenswürdig für Gerätefreigabe dokumentiert.
- Konten per Admin-Einladung (FR-026), Bootstrap per CLI.
- 6-stelliger PIN ersetzt durch 5×5-Entsperrmuster.
- Admin-Authentisierung per separatem Admin-Schlüsselpaar.
- Push über UnifiedPush mit FCM-Fallback; Linux per WebSocket.
- Gerätestatus `rejected` und Reaktivierung ergänzt.
- API-Liste um fehlende Endpunkte ergänzt.
