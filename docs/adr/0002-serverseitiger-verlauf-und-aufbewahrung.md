# ADR-0002: Serverseitiger Verlauf, kein Client-Verlauf, Aufbewahrungsfrist pro Chat

**Status:** Angenommen (2026-10-26)

## Kontext
Clients sollen keinen Nachrichtenverlauf speichern. Gleichzeitig sollen Nachrichten seitenweise (100) angezeigt werden können.

## Entscheidung
- Der Server speichert Ciphertexte bis zum Ablauf der Aufbewahrungsfrist oder bis zur Löschung.
- Der Client lädt Seiten zu 100 Nachrichten, entschlüsselt sie ausschließlich im RAM und verwirft sie beim Verlassen des Chats.
- Der Client speichert dauerhaft nur Schlüsselmaterial im verschlüsselten Container.
- Aufbewahrungsfrist pro Unterhaltung: 1–365 Tage, Standard 90.
- Jedes aktive Mitglied darf die Frist ändern. Jede Änderung erzeugt ein Systemereignis, das allen Mitgliedern im Chat angezeigt wird.
- Eine Verkürzung wirkt sofort auf vorhandene Nachrichten. Abgelaufene Nachrichten werden über den Pfad der globalen Löschung (ADR-0004) entfernt.

## Konsequenzen
- Datenverlust des Clients ist unkritisch; Neuinstallation + Freigabe genügt (aber ohne Zugriff auf alten Verlauf, ADR-0001).
- Ohne Netzverbindung ist kein Verlauf sichtbar.
- Der Server hält mehr Daten (Ciphertexte) länger vor; geschützt durch E2EE.
- Benutzer sehen den Systemhinweis zur Friständerung; der Hinweis ist Server-Metadatum, nicht E2EE (der Server kennt die Frist ohnehin).

## Verworfene Alternativen
- Lokale verschlüsselte Verlaufsdatenbank (widerspricht Produktvorgabe).
- Rein flüchtige Nachrichten ohne Verlauf.
