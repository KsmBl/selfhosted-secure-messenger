# ADR-0008: Push über UnifiedPush mit FCM-Fallback, WebSocket als Echtzeitkanal

**Status:** Angenommen (2026-10-26)

## Kontext
Push-Payloads dürfen keinen Inhalt enthalten; angezeigt wird höchstens der Anfangsbuchstabe des Absenders. Linux hat keinen Push-Dienst. Im gesperrten Zustand kann der Client nichts entschlüsseln.

## Entscheidung
- Echtzeit: WebSocket `GET /v1/ws` auf allen Clients im Vordergrund und dauerhaft unter Linux. Der Server sendet nur `{"type":"sync"}`; Daten werden über `GET /v1/events` geholt.
- Android im Hintergrund: **UnifiedPush** (bevorzugt, z. B. selbst gehostetes ntfy), **FCM** als Fallback, wenn kein Distributor installiert ist.
- Payload: ausschließlich ein zufälliges Weck-Signal ohne Konto-, Unterhaltungs- oder Nachrichten-ID.
- Nach dem Wecken authentisiert sich das Gerät mit dem Geräte-Signaturschlüssel (nicht musterpflichtig) und ruft `GET /v1/notifications/hint` ab: Anzahl neuer Nachrichten + Anfangsbuchstabe des Benutzernamens des letzten Absenders. Die Benachrichtigung zeigt nur diesen Buchstaben.

## Konsequenzen
- Push-Anbieter (insb. Google bei FCM) sehen Zustellzeitpunkte und Gerätetoken; offengelegt im Datenschutzmodell.
- Der Geräte-Signaturschlüssel muss ohne Muster nutzbar sein; er erlaubt Metadatenabruf, aber keine Entschlüsselung.

## Verworfene Alternativen
- Nur FCM; nur UnifiedPush.
- Absenderinitial im Push-Payload.
