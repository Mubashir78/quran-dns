# SMS Gateway Design (option B, 2026-10-02)

Phone = Android with SMS-relay app. App forwards incoming SMS to server,
server replies through phone send API. DNS core untouched.

## Flow

their phone --SMS--> android --WiFi POST /sms/incoming--> qdns
qdns parses, looks up store, POSTs reply text to phone send API --SMS--> them

## Message format

`chapter:verse [lang]` e.g. `2:255`, `112:4 en`, `112:4 ur`, `1:1 ar`.
lang default en. Reply always Arabic + translation (ar request = Arabic only).
Bad input -> one-SMS help text. Unknown verse -> "not found" text.

## Truncation

Cap reply ~400 chars (3 segments) + tail "full text: reader page".
Long verses never sent whole.

## Security (first non-localhost piece)

- Bind LAN only, `--lan` flag. Token `--sms-token`, required on receiver.
- No logging of sender numbers or bodies.
- Endpoint answers verse patterns only; rest gets help text.
- Per-sender cooldown 30s + existing IP rate limit.

## Testing

Parser/truncation unit tests with fake sender. Endpoint e2e over localhost.
Live phone pairing checklist in docs.
