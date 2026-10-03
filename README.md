# qdns — Qur'an over DNS (prototype)

Fetch any verse (Arabic, English, Urdu) with an ordinary DNS TXT query.
Built with Python 3.10+, `dnspython` and `asyncio`.

## Quick start

    pip install -r requirements.txt
    python -m unittest                          # 18 tests
    python -m qdns --port 5353                  # terminal 1: server (UDP+TCP)
    python -m qdns.client 2:255 -l en -v        # terminal 2: client

With `dig` (if installed):

    dig @127.0.0.1 -p 5353 2-255.en.quran.test TXT +short
    dig @127.0.0.1 -p 5353 help.quran.test TXT +short

Port 53 needs root; the default 5353 does not. `data/quran.json` is bundled;
rebuild it with `python scripts/fetch_data.py`.

## Name scheme

    <surah>-<ayah>.<lang>.quran.test.     lang: ar (default) | en | ur
    help.quran.test.  (or the zone apex)  usage text

Responses: NOERROR+TXT (found) · NXDOMAIN (no such verse/lang) ·
NOERROR/empty (non-TXT type) · REFUSED (outside our zone).

## Code flow

    client: qdns.client / dig
       |  TXT? 2-255.en.quran.test
       v
    +-----------------------------+
    | server.py  (asyncio)        |
    |  UDP 5353      TCP 5353     |
    |  datagram_     2-byte len   |
    |  received      prefix       |
    +--------------+--------------+
                   v
            process(bytes)
             from_wire()
                   v
    +-----------------------------+
    | resolver.py  handle(query)  |
    |  1. in our zone? else       |
    |     REFUSED                 |
    |  2. names.parse_qname()     |
    |  3. store.get() else        |
    |     NXDOMAIN                |
    |  4. txt.make_txt_rrset()    |
    |     (split <=255 B, UTF-8)  |
    +--------------+--------------+
                   v
          to_wire(max_size=512)
           |                |
      fits (UDP/TCP)    too big (UDP only)
           |                |
         reply         TC=1, no answer
                            |
                  client retries on TCP
                  -> full answer

## Layout

    qdns/config.py    constants (zone, langs, limits)
    qdns/names.py     DNS name -> ParsedQuery
    qdns/store.py     data/quran.json loader
    qdns/txt.py       UTF-8-safe 255-byte chunking, TXT rrset
    qdns/resolver.py  Message -> Message (no sockets)
    qdns/server.py    asyncio UDP + TCP transports
    qdns/client.py    CLI (UDP with TCP fallback)
    scripts/fetch_data.py   build the dataset
    tests/            unit + live-server tests

## Suggested 3-week path

1. Week 1 — Read names/txt/resolver; run tests; inspect packets with Wireshark
   (`udp.port == 5353 || tcp.port == 5353`). Add a language or a `S.count` name.
2. Week 2 — Server: study UDP truncation + TCP framing; break it on purpose
   (shrink UDP_LIMIT, send garbage) and watch the log.
3. Week 3 — Phase 2 items below; write up measurements.

## Phase 2 ideas (not implemented yet)

- EDNS0: honour client payload size (see TODO in resolver.py), compare with 512
- SOA/NS records at the apex + SOA in NXDOMAIN answers (negative caching)
- DNSSEC signing so verses are verifiably unaltered
- DNS-over-HTTPS front end reusing `Resolver.handle`
- Benchmark script (latency/throughput vs an HTTP API), rate limiting
- Real delegation: register a domain, point NS at a public server

## Known limits of this prototype

- Single zone, in-memory data, no rate limiting, no DNSSEC, no EDNS0.
- Do not expose to the open internet as-is (DNS can be abused for amplification).
- Data: fawazahmed0/quran-api editions (Uthmani Hafs; Mustafa Khattab,
  The Clear Quran; Maududi). Check each translation's licence before redistributing, and
  have texts reviewed by a qualified person before any public release.
