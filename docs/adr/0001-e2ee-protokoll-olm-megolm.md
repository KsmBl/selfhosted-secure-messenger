# ADR-0001: E2EE-Protokoll: Olm/Megolm über vodozemac

**Status:** Angenommen (2026-10-26)

## Kontext
Der Client hält keinen Nachrichtenverlauf (ADR-0002). Nachrichten werden bei jeder Anzeige vom Server geladen und erneut entschlüsselt. Der Signal Double Ratchet und MLS löschen Nachrichtenschlüssel unmittelbar nach dem Entschlüsseln (Forward Secrecy); ein späteres erneutes Entschlüsseln desselben Ciphertexts ist damit unmöglich. Eigenentwickelte Kryptografie ist ausgeschlossen.

## Entscheidung
- **Megolm** verschlüsselt alle Nachrichten einer Unterhaltung (auch 1:1). Jedes sendende Gerät hat eine ausgehende Sitzung pro Unterhaltung.
- **Olm** (paarweise, Double-Ratchet-basiert) verteilt Megolm-Sitzungsschlüssel an alle aktiven Geräte aller Mitglieder.
- Implementierung: Rust-Bibliothek **`vodozemac`** (Apache-2.0, extern auditiert), keine eigene Protokollimplementierung.
- Empfänger speichern eingehende Megolm-Sitzungen ab dem ersten bekannten Index im Schlüsselbund (verschlüsselt mit dem MEK, ADR-0005).
- Rotation: bei Mitgliedschaftsänderung, Geräte-Freigabe/-Widerruf eines Mitglieds, nach 100 Nachrichten oder 7 Tagen.

## Konsequenzen
- Serverseitiger Verlauf ist mit etabliertem Protokoll umsetzbar.
- Forward Secrecy ist auf Rotationsgranularität eingeschränkt: Wer den Schlüsselbund eines entsperrten Geräts erbeutet, kann gespeicherte Ciphertexte der enthaltenen Sitzungen entschlüsseln (dokumentiertes Restrisiko).
- Entfernte Mitglieder erhalten keine neuen Sitzungen ⇒ künftige Nachrichten bleiben für sie unlesbar (FR-004).
- Neue Geräte lesen nur Nachrichten ab ihrer Freigabe (keine Schlüsselweitergabe in v1).
- Bekannte historische Megolm-Schwächen (Absenderauthentisierung) sind in vodozemac adressiert; der Client prüft Absendergerät und Sitzungsherkunft und akzeptiert Sitzungsschlüssel nur über Olm.

## Verworfene Alternativen
- **Signal Protocol + MLS:** zwei Protokolle, kein erneutes Entschlüsseln, libsignal unter AGPL-3.0.
- **MLS mit eigenem epochenbasiertem Schlüsselbund:** eigene Konstruktion, bräuchte separates Review.
