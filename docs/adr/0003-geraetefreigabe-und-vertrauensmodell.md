# ADR-0003: Gerätefreigabe durch Admin, vertrauenswürdiger Betreiber

**Status:** Angenommen (2026-10-26)

## Kontext
Neue Geräte sollen erst nach manueller Freigabe Nachrichten senden und empfangen. Wenn allein der Admin freigibt, kann ein Admin (oder ein Angreifer mit Serverkontrolle) ein eigenes Gerät unter einem fremden Konto registrieren. Absender verschlüsseln künftige Nachrichten dann auch für dieses Gerät.

## Entscheidung
- Freigabe erfolgt einmalig durch einen Administrator. Der Admin sieht Benutzername, Gerätebezeichnung und Schlüssel-Fingerprint, keine Inhalte.
- Der Serverbetreiber wird für die Gerätefreigabe als **vertrauenswürdig** angenommen. Das Restrisiko wird dokumentiert, nicht technisch verhindert.
- Gerätestatus: `pending` → `active` | `rejected`; `active` ⇄ `disabled`; `active`/`disabled` → `revoked`. `rejected` und `revoked` sind endgültig: das Gerät wird vollständig gelöscht. Nachrichten behalten die ID des sendenden Geräts (ohne Fremdschlüssel), damit sie für die anderen lesbar bleiben.
- Geräteauthentisierung per Proof of Possession: Ed25519-Signatur über eine einmalige Server-Nonce, danach kurzlebiges Token (15 min). Jede Anfrage prüft den aktuellen Gerätestatus.

## Konsequenzen
- Einfache Bedienung; kein Abgleich zwischen Geräten oder Kontakten nötig.
- Bei Kompromittierung des Servers sind künftige Nachrichten betroffener Konten lesbar. Das ist im PRD (Abschnitt 3) offengelegt.
- Clients zeigen die Geräteliste eines Kontakts an, damit unerwartete Geräte auffallen können (keine Pflichtwarnung).

## Verworfene Alternativen
- Mitbestätigung durch ein bestehendes eigenes Gerät.
- Pflichtwarnung an Kontakte bei neuer Gerätefreigabe.
