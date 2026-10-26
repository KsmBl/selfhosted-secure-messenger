# ADR-0004: Löschsemantik: nur Löschen für alle, jeder Teilnehmer berechtigt

**Status:** Angenommen (2026-10-26)

## Kontext
Die Produktregel erlaubt ausschließlich „Löschen für alle". Offen war, wer löschen darf und wie Offline-Clients, Medien und Backups behandelt werden.

## Entscheidung
- Einzige Löschoperation: Löschen für alle. Kein Endpunkt und keine UI für „nur für mich".
- **Jedes aktive Mitglied** einer Unterhaltung darf **jede** Nachricht dieser Unterhaltung löschen. Admins löschen über die Massenlöschung (alle Nachrichten einer Person).
- Ablauf transaktional mit Outbox: Löschjob (idempotent über Operations-ID), Nachricht als gelöscht markieren und Ciphertext leeren, Medien auf `purge_pending`, Tombstone-Ereignisse für alle Mitgliedsgeräte.
- Abrufpfade liefern statt des Inhalts nur den Tombstone; Medien liefern 410.
- Gelöschte Nachrichten bleiben bis zum Fristablauf als inhaltsleerer Tombstone in der Zeitleiste. Löschereignisse liegen pro Gerät vor, bis das Gerät sie bestätigt; nicht abgeholte Ereignisse verfallen nach 400 Tagen (> maximale Aufbewahrung). Clients mit älterem Ereignis-Cursor setzen ihren Zustand zurück.
- Statuswerte: `requested`, `in_progress`, `active_removed`, `backup_purge_pending`, `backup_purge_done`, `failed`. Backup-Aufbewahrung Standard 30 Tage.
- Abgelaufene Nachrichten werden minütlich physisch entfernt und vorher schon nicht mehr ausgeliefert; Clients blenden sie anhand von `expires_at` aus, ein Ereignis ist dafür nicht nötig.

## Konsequenzen
- Jedes Gruppenmitglied kann Beiträge anderer entfernen (akzeptiertes Missbrauchsrisiko; im UI wird angezeigt, dass und von wem gelöscht wurde).
- Da Clients keinen Verlauf speichern, ist das Bereinigen auf dem Client auf RAM und Medien-Cache beschränkt.

## Verworfene Alternativen
- Nur Absender darf löschen.
- Absender + Gruppenbesitzer.
