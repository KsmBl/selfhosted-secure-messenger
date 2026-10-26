# ADR-0007: Konten per Admin-Einladung, Bootstrap per CLI

**Status:** Angenommen (2026-10-26)

## Kontext
Die Version 1.1 definierte nicht, wie Konten entstehen und wie der erste Admin angelegt wird.

## Entscheidung
- Nur Admins legen Konten an (Benutzername: 3–32 Zeichen, `[a-z0-9_.-]`, eindeutig).
- Dabei entsteht ein Einladungscode: 128 Bit Zufall, Base32, einmalig, Ablauf 7 Tage. Der Server speichert nur SHA-256 des Codes.
- Das erste Gerät registriert sich mit dem Code; es bleibt `pending` bis zur Admin-Freigabe.
- Weitere Geräte registrieren sich mit dem Benutzernamen und benötigen ebenfalls Freigabe.
- Der erste Admin (Konto + Admin-Schlüssel) wird mit `ssm-admin bootstrap` auf dem Server angelegt.

## Konsequenzen
- Keine offene Registrierung, keine Spam-Konten.
- Der Einladungscode muss über einen sicheren Kanal außerhalb der App übermittelt werden.

## Verworfene Alternativen
- Selbstregistrierung.
- Kontoerstellung ausschließlich per CLI.
