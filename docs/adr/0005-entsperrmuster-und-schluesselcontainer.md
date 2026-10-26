# ADR-0005: 5×5-Entsperrmuster und lokaler Schlüsselcontainer

**Status:** Angenommen (2026-10-26)

## Kontext
Ein sechsstelliger PIN hat nur 10⁶ Kombinationen. Gewünscht ist stattdessen ein Muster auf einem 5×5-Raster, bei dem jeder Punkt beliebig oft gedrückt werden darf.

## Entscheidung
- Raster 5×5, Punkte 0–24. Muster = Folge von Punktindizes, Wiederholungen erlaubt.
- Länge 6–64 (theoretisch 4,64 Bit pro Eingabe; 6 Eingaben ≈ 28 Bit).
- Ablehnung trivialer Muster: weniger als 3 verschiedene Punkte; eine Zeile, Spalte oder Hauptdiagonale in Reihenfolge (vorwärts/rückwärts); nur die vier Ecken.
- Keine sichtbare Eingabespur.
- Kanonische Kodierung: `"ssm-pattern-v1" || len(u8) || indizes(u8…)`.
- Schlüsselableitung:
  1. `k_pattern = Argon2id(kodierung, salt16, m, t, p=1)`, Kalibrierung auf ≈3 s, Mindestwerte m = 64 MiB, t = 3.
  2. `KEK = HKDF-SHA256(ikm = k_pattern || hw, salt = salt16, info = "ssm/kek/v1")`, `hw` = 32-Byte-Hardware-Geheimnis (Android Keystore/StrongBox, Linux TPM2) oder leer, falls keine Hardware verfügbar.
  3. `MEK` zufällig (256 Bit), verpackt mit XChaCha20-Poly1305 unter KEK; Header (Version, Parameter, Salt, Hardware-Flag) als Associated Data.
  4. MEK verschlüsselt den Container-Inhalt (XChaCha20-Poly1305).
- Hardwarebindung ist verpflichtend, wo verfügbar.
- Fehlversuche: ab dem 5. exponentielle Wartezeit, max. 1 h.
- Gilt auf Android und Linux. Das Admin-Schlüsselpaar hat einen eigenen Container mit eigenem Muster.

## Konsequenzen
- Mit 6 Eingaben und menschlicher Musterwahl ist ein kopierter Container ohne Hardwarebindung offline angreifbar (akzeptiertes, dokumentiertes Restrisiko). Nutzer werden bei fehlender Hardware im Setup darauf hingewiesen und es wird ein längeres Muster empfohlen.
- Die Wartezeit nach Fehlversuchen schützt nur gegen Online-Raten am Gerät, nicht gegen Offline-Angriffe.

## Verworfene Alternativen
- 6-stelliger PIN.
- Mindestlänge 8 oder 10.
- TPM2 als zwingende Voraussetzung unter Linux.
