# ADR-0006: Admin-Authentisierung über separates Schlüsselpaar

**Status:** Angenommen (2026-10-26)

## Kontext
Die Admin-API muss logisch von der Chat-Authentisierung getrennt sein, kurzlebige Berechtigungen nutzen und für destruktive Aktionen eine erneute Authentisierung verlangen. SSH-Schlüssel dürfen nicht in der Chat-App liegen.

## Entscheidung
- Jeder Administrator besitzt ein eigenes Ed25519-**Admin-Schlüsselpaar**, unabhängig vom Gerät. Es liegt in einem separaten Container mit eigenem Entsperrmuster (ADR-0005), hardwaregebunden, wo möglich.
- Der erste Admin-Schlüssel wird mit `ssm-admin` direkt auf dem Server registriert. Weitere Admins werden von einem bestehenden Admin hinzugefügt (destruktive Aktion).
- Login: `POST /v1/admin/auth/challenge` → Nonce (60 s, einmalig); `POST /v1/admin/auth/session` mit Signatur über `"ssm-admin-auth-v1"`, Felder `nonce`, `admin_key_id` (längenpräfixiert) → Token (10 min).
- Destruktive Aktionen verlangen eine frische Signatur über `"ssm-admin-confirm-v1"`, Felder `nonce`, `aktion`, `ziel`, mit Nonce von `POST /v1/admin/confirm/challenge`.
- Admin-Endpunkte autorisieren jede Anfrage serverseitig und haben ein eigenes Rate-Limit.
- Alle Admin-Aktionen landen im hash-verketteten Audit-Log.

## Konsequenzen
- Kein gemeinsames Geheimnis auf dem Server; Server hält nur öffentliche Schlüssel.
- Verlust des Admin-Containers: neuer Schlüssel per `ssm-admin` oder durch einen anderen Admin.

## Verworfene Alternativen
- FIDO2/WebAuthn-Hardwareschlüssel.
- Admin-Passwort + TOTP.
