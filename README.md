# qdns — Qur'an over DNS

Fetch any of the 6,236 Qur'an verses (Arabic + English + Urdu) with an
ordinary DNS TXT query. A Python + `asyncio` authoritative server answers
from an in-memory corpus; clients can be `dig`, the bundled CLI, a terminal
script with proper Arabic shaping, a web reader page, or even SMS/WhatsApp
style text messages via a phone gateway.

Built with Python 3.10+, `dnspython`, `asyncio`, and stdlib-only HTTP for DoH.

## Features

- **DNS core** — authoritative UDP + TCP server for zone `quran.test.`;
  verses as TXT records (`<surah>-<ayah>.<lang>`), `help` text at the apex.
- **Modern DNS behavior** — EDNS0 payload negotiation (server max 1232),
  apex SOA/NS, SOA in NXDOMAIN/NODATA (negative caching), TC-empty + TCP
  fallback for answers over the UDP budget.
- **DNSSEC island** — Ed25519-signed apex (SOA/NS/DNSKEY) with DO-bit
  RRSIGs; verses served unsigned (documented limitation).
- **DNS-over-HTTPS** — RFC 8484 GET/POST endpoint reusing the same
  resolver, plus a self-hosted **reader page** (search, range view,
  memorize mode, khatmah tracker, verify button).
- **SMS gateway** — text `112:4 en` from any phone, get Arabic + translation
  back (Android phone as gateway, inbox polling).
- **Terminal CLI** — `scripts/verse` with Arabic shaping, REPL, ranges,
  JSON output.
- **Ops** — per-IP token-bucket rate limiting, `scripts/bench.py`
  (UDP/TCP QPS + p50/p99).

## Quick start

    pip install -r requirements.txt
    python -m unittest                        # 94 tests
    python -m qdns.server --port 5453         # DNS (UDP+TCP); --doh-port 8053 adds DoH

Port 53 needs root; 5353 is the code default. On machines running
Avahi/mDNS (which owns UDP 5353 system-wide), use `--port 5453`.

## Usage examples

**dig (any verse, English):**

    dig @127.0.0.1 -p 5453 2-255.en.quran.test TXT +short
    dig @127.0.0.1 -p 5453 help.quran.test TXT +short
    dig @127.0.0.1 -p 5453 quran.test SOA +short

**Bundled DNS client (auto UDP→TCP fallback on truncation):**

    python -m qdns.client 2:255 -l en -v
    python -m qdns.client 2:282 -l ur        # long verse, transparently uses TCP

**Terminal reader (shaped Arabic, REPL, ranges):**

    scripts/verse 112:4 -l en                 # Arabic + English
    scripts/verse 2:255-257 -l ur             # passage (max 20 verses)
    scripts/verse                             # interactive REPL (try: help)
    scripts/verse 112:4 --json                # machine-readable

**DNS-over-HTTPS + reader page:**

    python -m qdns.server --port 5453 --doh-port 8053
    # reader page:
    xdg-open http://127.0.0.1:8053/
    # raw DoH query (RFC 8484):
    curl -s 'http://127.0.0.1:8053/dns-query?dns=<base64url-wire>' \
      -H 'accept: application/dns-message' | xxd | head

**SMS (needs an Android phone running SMS Gateway for Android on the same LAN):**

    python -m qdns.server --port 5453 --sms-base-url http://<phone>:8080 \
        --sms-username qdns --sms-password <pass> --sms-smsgate --sms-poll
    # from any phone, text:  112:4 en   -> Arabic + English verse replies

**DNSSEC keys + benchmark:**

    python scripts/keygen.py                  # Ed25519 KSK+ZSK into keys/ (gitignored)
    python scripts/bench.py --port 5453       # UDP/TCP QPS, p50/p99, TC rate

## Name scheme

    <surah>-<ayah>.<lang>.quran.test.     lang: ar (default) | en | ur
    help.quran.test.  (or the zone apex)  usage text

Responses: NOERROR + TXT (found) · NXDOMAIN + SOA (no such verse/lang) ·
NOERROR/empty + SOA (non-TXT type) · REFUSED (outside our zone) ·
TC + empty (UDP answer too big — retry over TCP).

## Layout

    qdns/config.py    zone, languages, TTLs, EDNS/SOA constants
    qdns/names.py     DNS name -> ParsedQuery
    qdns/store.py     data/quran.json loader (6,236 verses x 3 langs)
    qdns/txt.py       UTF-8-safe 255-byte chunking, TXT rrsets
    qdns/resolver.py  Message -> Message (no sockets): verses, apex, DNSSEC
    qdns/server.py    asyncio UDP + TCP transports, rate limiting
    qdns/dnssec.py    Ed25519 signer, apex pre-signing
    qdns/doh.py       DoH endpoint + reader page + search + SMS webhook
    qdns/sms.py       SMS parsing, replies, gateway client, inbox poller
    qdns/client.py    CLI DNS client (UDP with TCP fallback)
    qdns/web.html     reader page (served by doh.py)
    scripts/verse     terminal reader CLI
    scripts/fetch_data.py   rebuild data/quran.json from quran-api
    scripts/keygen.py       generate DNSSEC keys
    scripts/bench.py        latency/throughput benchmark
    scripts/publish_desec.py  publish zone to deSEC (needs DESEC_TOKEN)
    tests/            unit + live-server tests (94)

## Data + translation licences

`data/quran.json` bundles: Uthmani (Hafs) Arabic, Mustafa Khattab
(The Clear Quran) English, and Maududi Urdu, via fawazahmed0/quran-api;
rebuild with `python scripts/fetch_data.py`. Check each translation's
licence before redistributing, and have texts reviewed by a qualified
person before any public release.

## Known limits

Prototype: single zone, in-memory data, unsigned verses, local-only
defaults. Do not expose UDP to the open internet as-is (DNS can be abused
for amplification); the reader page is safe to share via a tunnel.

## License

MIT — see [LICENSE](LICENSE).
