# Product Requirements Document (PRD)
## Self-hosted, Ende-zu-Ende-verschlüsselter Messenger für Android und Linux

**Status:** Entwurf zur Umsetzung  
**Version:** 1.1  
**Sprache:** Deutsch

## 1. Ziel und Produktumfang

Entwickelt wird ein selbst gehosteter Messenger mit Android- und Linux-Clients. Die Anwendung unterstützt Einzel- und Gruppenchats, Ende-zu-Ende-Verschlüsselung (E2EE), manuelle Gerätefreigabe, verschlüsselte Medien, datensparsame Push-Benachrichtigungen und eine in die Chat-App integrierte Administrationsoberfläche.

Verbindliche Produktregeln:
1. **Jede Löschung ist eine Löschung für alle.** Eine Funktion „nur für mich löschen“ existiert nicht – weder in der Benutzeroberfläche noch in der API.
2. **Administration findet in einer eigenen Oberfläche innerhalb der Chat-App statt.** Sie ist nur für autorisierte Admin-Clients zugänglich und serverseitig abgesichert.
3. **Administratoren erhalten durch ihre Adminrechte keinen Zugriff auf E2EE-Klartexte oder private E2EE-Schlüssel.**

## 2. Ziele

- Nachrichten und Medien ausschließlich Ende-zu-Ende-verschlüsselt übertragen und speichern.
- Neue Geräte erst nach manueller Freigabe zulassen.
- Bei Verlust eines Geräts dessen Zugang serverseitig sperren oder widerrufen können.
- Nachrichten in Seiten zu je 100 Einträgen laden.
- Nachrichten und Medien global löschen und die Löschung an alle Clients verteilen.
- Chat-Inhalte beim Verlassen eines Chats aus dem Arbeitsspeicher und lokalen App-Caches entfernen, soweit technisch möglich.
- Push-Nachrichten ohne Nachrichteninhalt versenden; als sichtbaren Hinweis höchstens den Anfangsbuchstaben des Absenders verwenden.
- Einen sechsstelligen PIN zum lokalen Entsperren unterstützen und Offline-Brute-Force-Angriffe durch Schlüsselableitung, Hardwarebindung und Rate-Limits erschweren.
- Medienvorschauen zunächst separat verschlüsselt laden und Originaldateien erst auf ausdrückliche Aktion herunterladen.
- Administration direkt in der Chat-App anbieten.

## 3. Nicht-Ziele und Sicherheitsgrenzen

- Kein Schutz gegen jede Form eines kompromittierten oder bereits entsperrten Endgeräts.
- Kein zuverlässiges Zurückholen von Inhalten, die Empfänger zuvor exportiert, kopiert, fotografiert oder außerhalb der App gespeichert haben.
- Keine Garantie, dass ein bösartiger Server tatsächlich jede Kopie vernichtet. Backups, Replikate und Speicher-Snapshots benötigen eigene Bereinigungsregeln.
- Screenshot-Sperren sind plattformabhängig und verhindern keine externe Kameraaufnahme.
- Ein sechsstelliger PIN besitzt nur eine Million mögliche Kombinationen. Eine langsame Schlüsselableitung allein reicht nicht als vollständiger Schutz, wenn ein Angreifer einen Offline-Schlüsselcontainer kopiert hat.

## 4. Rollen

### 4.1 Nutzer
- Kann nach erfolgreicher Anmeldung Einzel- und Gruppenchats verwenden.
- Kann Nachrichten und Medien senden und **für alle** löschen.
- Kann Medien explizit auf das Gerät exportieren.
- Kann eigene Geräte und ausstehende Gerätefreigaben einsehen, soweit vorgesehen.

### 4.2 Administrator
- Verwendet einen gesondert autorisierten Admin-Client.
- Erhält innerhalb der Chat-App einen separaten Administrationsbereich.
- Kann Geräteanfragen freigeben oder ablehnen, Geräte deaktivieren/widerrufen, Konten und Geräte verwalten sowie serverseitige Nachrichten und Medien einer ausgewählten Person global löschen.
- Kann Status von Löschaufträgen und administrative Audit-Einträge einsehen.
- Erhält **keine** E2EE-Schlüssel und keine Klartext-Leseberechtigung allein aufgrund der Adminrolle.

## 5. Funktionale Anforderungen

### FR-001 – Geräteidentität und manuelle Freigabe
Jedes Gerät erzeugt eine eigene kryptografische Identität. Neue Geräte befinden sich zunächst im Status `pending` und dürfen keine regulären Nachrichten senden oder empfangen, bis ein Administrator sie freigibt.

### FR-002 – Geräteverwaltung
Gerätestatus: `pending`, `active`, `disabled`, `revoked`. Statusänderungen werden serverseitig autorisiert und protokolliert. Widerruf muss weitere authentisierte API-Zugriffe des Geräts verhindern.

### FR-003 – PIN und lokaler Schlüsselcontainer
Der Client fordert beim Entsperren einen sechsstelligen PIN. Der PIN wird niemals an den Server übertragen. Eine Schlüsselableitung wie Argon2id mit zufälligem Salt schützt einen zufälligen Datenschlüssel, der den lokalen E2EE-Schlüsselcontainer verschlüsselt. Wo verfügbar, wird Hardware-Key-Storage eingebunden. Die Zielgröße von etwa drei Sekunden für die Schlüsselableitung wird auf unterstützten Geräten gemessen und abgestimmt; sie ist kein alleiniger Sicherheitsmechanismus.

### FR-004 – Einzel- und Gruppenchats
Einzel- und Gruppennachrichten werden clientseitig verschlüsselt. Änderungen der Gruppenmitgliedschaft müssen die Gruppen-Schlüsselverwaltung berücksichtigen; entfernte Mitglieder dürfen keine künftig gesendeten Nachrichten entschlüsseln können.

### FR-005 – Ende-zu-Ende-Verschlüsselung
Der Server verarbeitet nur die für Routing, Zustellung und Speicherung nötigen Metadaten und Ciphertexte. Es wird eine geprüfte, etablierte Protokollimplementierung verwendet. Eigenentwickelte Kryptografie ist nicht zulässig. Die konkrete Protokollwahl wird durch einen Architecture Decision Record (ADR) festgelegt.

### FR-006 – Nachrichten-Paginierung
Nachrichten werden standardmäßig in Seiten zu 100 Einträgen geladen. Cursorbasierte Pagination wird bevorzugt, um stabile Ergebnisse bei parallelen Änderungen zu ermöglichen.

### FR-007 – Globale Löschung ist die einzige Löschfunktion
Es gibt **keine** Funktion „nur für mich löschen“, kein lokales alternatives Löschziel und keinen entsprechenden API-Endpunkt. Jede Löschaktion eines Nutzers bedeutet „für alle Teilnehmer löschen“.

### FR-008 – Globale Löschung von Nachrichten
Eine berechtigte Löschanfrage erzeugt einen idempotenten Löschauftrag mit eindeutiger Operations-ID. Der Server verhindert die weitere Auslieferung der betroffenen Nachricht, entfernt aktive serverseitige Datensätze und verteilt ein Löschereignis an alle Mitglieder der Unterhaltung. Offline-Clients übernehmen das Ereignis beim nächsten Synchronisieren und entfernen betroffene Inhalte aus lokalen App-Caches.

### FR-009 – Globale Löschung von Medien
Die Löschung umfasst die Nachricht sowie alle dazugehörigen Originaldateien, verschlüsselten Vorschaudateien, Chunks, Objekt-Referenzen und serverseitigen Metadaten. Aktive Speicher dürfen gelöschte Objekte nicht erneut ausliefern.

### FR-010 – Löschstatus und Backup-Bereinigung
Der Status unterscheidet mindestens zwischen angefordert, in Bearbeitung, aus aktiven Speichern entfernt und Backup-Bereinigung ausstehend/abgeschlossen. Backups, Replikate und Snapshots folgen einer dokumentierten Aufbewahrungs- und Bereinigungsfrist. Eine vollständige Bereinigung darf nicht vorgetäuscht werden, wenn noch Kopien in Backups verbleiben.

### FR-011 – Verschlüsselte Medien und Vorschauen
Bilder, Videos und Audiodateien werden vor dem Upload auf dem Client verschlüsselt. Vorschaudateien werden separat verschlüsselt. Beim Öffnen eines Chats werden zunächst nur verschlüsselte Vorschauen bzw. die für die Anzeige nötigen Daten geladen. Die vollständige Mediendatei wird erst nach expliziter Nutzeraktion heruntergeladen.

### FR-012 – Expliziter Medienexport
Das Speichern eines Mediums in den allgemeinen Gerätespeicher erfordert eine bewusste Nutzeraktion. Der Client weist darauf hin, dass exportierte Dateien außerhalb der Kontrolle der App liegen und durch spätere globale Löschung nicht zuverlässig entfernt werden können.

### FR-013 – Arbeitsspeicher und lokale Daten
Nach Verlassen eines Chats entfernt der Client Chat-Inhalte aus sichtbarem UI-Zustand und lokalen App-Caches, soweit möglich. Dauerhafte Speicherung von Klartextnachrichten ist zu vermeiden. RAM-Bereinigung ist best effort und darf nicht als garantierte sichere Speicherlöschung beworben werden.

### FR-014 – Screenshot-Schutz
Android verwendet, wo angemessen, plattformeigene Screenshot-/Screen-Capture-Schutzmechanismen. Linux-Desktop-Clients weisen auf die eingeschränkte Durchsetzbarkeit hin. Externe Fotoaufnahmen können nicht verhindert werden.

### FR-015 – Push-Privatsphäre
Push-Payloads enthalten keinen Nachrichteninhalt, keine Medienvorschau und möglichst keine sensiblen Gesprächsmetadaten. Als sichtbarer Hinweis wird höchstens der Anfangsbuchstabe des Absenders angezeigt. Die Betriebssystemplattform und der Push-Anbieter können weiterhin gewisse Zustellmetadaten sehen.

### FR-016 – In-App-Adminoberfläche
Der Chat-Client enthält einen separaten Administrationsbereich. Dieser wird nur nach erfolgreicher Admin-Authentifizierung freigeschaltet. UI-Sichtbarkeit gilt nicht als Sicherheitsgrenze; jeder Admin-Endpunkt prüft die Berechtigung serverseitig.

### FR-017 – Admin-Geräte- und Kontoverwaltung
Der Admin kann ausstehende Geräteanfragen freigeben/ablehnen, Geräte deaktivieren oder widerrufen und Konten bzw. deren Geräte verwalten.

### FR-018 – Admin-Massenlöschung
Der Admin kann eine Person auswählen und alle zugehörigen serverseitigen Nachrichten und Medien zur globalen Löschung anweisen. Vor der Ausführung werden Zielkonto und Umfang angezeigt; eine explizite Bestätigung ist erforderlich. Ergebnis, Fehler und Teilerfolge werden dargestellt und protokolliert.

### FR-019 – Admin-Authentifizierung und API
Administrative Aktionen laufen über eine getrennte, minimal berechtigte Admin-API mit kurzlebigen Berechtigungen. Kritische Vorgänge können erneute Authentifizierung erfordern. Ein SSH-Privatschlüssel darf nicht in der normalen Chat-App gespeichert werden. SSH kann als separater Administrationsweg bestehen bleiben.

### FR-020 – Audit-Log
Admin-Aktionen protokollieren mindestens Admin-Identität, Zeit, Aktion, Ziel, Ergebnis und Korrelations-ID. Das Log ist zugriffsbeschränkt und gegen unbemerkte nachträgliche Änderung zu schützen.

### FR-021 – Least Privilege
Normale Konten dürfen keine Admin-Aktionen ausführen. Adminrechte erlauben keine Entschlüsselung von E2EE-Inhalten.

### FR-022 – Transport- und API-Sicherheit
TLS, strikte Authentisierung, Autorisierung pro Objekt, Rate-Limits, Replay-Schutz, Eingabevalidierung und sichere Session-Verwaltung sind erforderlich.

### FR-023 – Update-Sicherheit
Release-Artefakte werden signiert. Der Update-Prozess prüft Signaturen und verhindert Downgrades, soweit die Plattform dies unterstützt.

### FR-024 – Minimierung von Metadaten
Nur notwendige Zustell- und Verwaltungsmetadaten werden gespeichert. Aufbewahrungsfristen und Zugriffsrechte sind dokumentiert.

## 6. Admin-Oberfläche: Mindestansichten

1. **Übersicht:** ausstehende Anfragen, aktive/deaktivierte Geräte, aktuelle administrative Ereignisse.
2. **Geräte:** Suche nach Konto/Gerät, Freigabe, Ablehnung, Deaktivierung, Widerruf.
3. **Konten:** Kontostatus und zugehörige Geräte.
4. **Globale Massenlöschung:** Person auswählen, Umfang prüfen, Löschung bestätigen, Fortschritt/Fehler einsehen.
5. **Audit und Löschstatus:** administrative Vorgänge und Status aktiver Speicher-/Backup-Bereinigung.

## 7. Konzeptionelles Datenmodell

- `accounts`: Konto-ID, Status, Erstellungszeit.
- `devices`: Geräte-ID, Konto-ID, öffentlicher Identitätsschlüssel, Status, Zeitstempel.
- `conversations`: ID, Typ, Erstellungszeit.
- `conversation_members`: Unterhaltung, Konto, Mitgliedschaftsstatus.
- `messages`: ID, Unterhaltung, Absender, Ciphertext, Sequenz-/Zeitinformationen, Status.
- `media_objects`: ID, Nachrichten-ID, verschlüsselte Objekt-Referenz, Typ, Größe, Löschstatus.
- `delete_jobs`: Operations-ID, Initiator, Zielumfang, Status, Zeitstempel, Fehlerdetails.
- `push_endpoints`: Gerätebezug, Push-Token, Status.
- `admin_audit_events`: Admin-ID, Aktion, Ziel, Ergebnis, Zeit, Korrelations-ID.

Keine Tabelle enthält E2EE-Privatschlüssel oder Nachricht-Klartexte.

## 8. API-Bereiche (konzeptionell)

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

**Verbindlich:** Es gibt keinen Endpunkt zum Löschen nur auf dem eigenen Client. Die genaue API wird vor Implementierung versioniert und in einer OpenAPI-Spezifikation beschrieben.

## 9. Akzeptanzkriterien

- Ein neues Gerät kann vor Freigabe keine regulären Nachrichten lesen oder senden.
- Der PIN wird nicht an den Server gesendet.
- Nachrichten und Medien werden Ende-zu-Ende-verschlüsselt gespeichert und übertragen.
- Pagination liefert standardmäßig höchstens 100 Nachrichten pro Seite.
- **Weder UI noch API bieten „nur für mich löschen“.**
- Eine globale Löschung verhindert die erneute Auslieferung aus aktiven Server-Speichern und erzeugt Löschereignisse für alle Gesprächsmitglieder.
- Offline-Clients übernehmen Löschereignisse nach Wiederverbindung und bereinigen App-Caches.
- Medienlöschung umfasst Vorschauen, Chunks und Metadaten.
- Backup-Bereinigung wird separat verfolgt und nicht fälschlich als sofort abgeschlossen angezeigt.
- Nur Admins können die Adminoberfläche und Admin-API verwenden.
- Massenlöschung verlangt Bestätigung, liefert einen Status und erzeugt einen Audit-Eintrag.
- Adminrechte erlauben keinen Zugriff auf Klartexte oder E2EE-Schlüssel.
- Push-Payloads enthalten keinen Nachrichteninhalt.

## 10. Risiken und offene Entscheidungen

- Konkretes E2EE-Protokoll und reife Bibliotheken für Android/Linux.
- Schlüsselwiederherstellung und Gerätewechsel.
- Backup- und Replikat-Bereinigungsfristen.
- Verfügbarkeit und Datenschutz von Push-Diensten.
- Hardware-Key-Storage auf Linux und unterschiedlichen Android-Geräten.
- Umgang mit Gruppenschlüsselrotation und Offline-Mitgliedern.
- Wie „alle Nachrichten einer Person“ bei Nachrichten in Gruppen definiert wird: empfohlen ist die Löschung aller serverseitigen Nachrichten, die vom Zielkonto stammen, über alle Unterhaltungen hinweg; Gruppenbeiträge anderer Personen bleiben bestehen.

## 11. Empfohlene Umsetzungsphasen

1. ADRs und Bedrohungsmodell abschließen.
2. Servergrundlage, Konten, Gerätefreigabe und Admin-API.
3. E2EE für Einzelchats und verschlüsselte Speicherung.
4. Globale Löschung, zuverlässige Synchronisation und Löschstatus.
5. Gruppenchats und Schlüsselrotation.
6. Medien, verschlüsselte Vorschauen und On-Demand-Download.
7. Adminoberfläche im Client und Massenlöschung.
8. Push-Integration, Plattformhärtung, Penetrationstest und Sicherheitsreview.

## 12. Referenzen

- Signal Protocol Dokumentation: https://signal.org/docs/
- Messaging Layer Security, RFC 9420: https://www.rfc-editor.org/rfc/rfc9420
- OWASP MASVS: https://mas.owasp.org/MASVS/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
