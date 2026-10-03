# Pair your Android as the SMS gateway (SMSGate)

Recommended app: **SMS Gateway for Android** (`capcom6/android-sms-gateway`,
5K stars, Apache 2.0, Android 5.0+, no account needed). Fits because it runs
a local API on the phone plus `sms:received` webhooks — no cloud, no signup.

Why this one over the rest: textbee needs an account + cloud/self-hosted
backend (heavy); LibreSMS/SMOff are send-only or young; SUSA/nomad forwarders
can't send replies. SMSGate does both directions on your LAN.

## Phone setup

1. Install the app, grant SMS permissions, start its **local server**.
   Note its IP/port + username/password (e.g. `http://192.168.1.Y:8080`).
2. Register the webhook so incoming texts reach our server (laptop LAN IP
   `192.168.1.X`, `--sms-token` value must match):
```
curl -X POST -u USER:PASS -H 'Content-Type: application/json' \
  -d '{"id":"qdns","url":"http://192.168.1.X:8053/sms/incoming","event":"sms:received"}' \
  http://192.168.1.Y:8080/webhooks
```

## Laptop

Same WiFi, then:
```
.venv/bin/python -m qdns.server --host 192.168.1.X --port 5453 \
  --doh-port 8053 --sms-send-url 'http://192.168.1.Y:8080/message' \
  --sms-username USER --sms-password PASS --sms-smsgate --sms-token 'pick-one'
```

## Try it

From another phone text `112:4 en` to your number. Expect Arabic + English.
Text `hello` → help text means plumbing works.

Notes: phone stays awake on WiFi; long verses truncate ~400 chars; logs never
store numbers; token on.
