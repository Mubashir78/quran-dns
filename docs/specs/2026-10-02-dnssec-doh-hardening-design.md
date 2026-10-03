# Phase 2b Design: DNSSEC island, DoH, rate-limit + bench (2026-10-02)

Scope: finish remaining deferred scopes. Local demo only: bind 127.0.0.1,
default DNS port 5353. Prototype grade, no public exposure.

## B. DNSSEC island of security (unsigned verses documented)

- Algorithm Ed25519 (alg 15, small sigs fit UDP+EDNS budget).
- `scripts/keygen.py`: generate KSK (flag 257) + ZSK (flag 256), store PEM
  under `keys/` (gitignored), print DNSKEY text + DS for manual trust.
- New `qdns/dnssec.py`: load keys, pre-sign static apex sets at startup
  (SOA, NS, DNSKEY) with 14-day validity; attach RRSIGs only when query has
  DO bit (RFC 4035 s3). Verse TXT stays unsigned: documented limitation.
- `Resolver`: optional `dnssec` object (None by default, zero behavior change
  when absent). Serve DNSKEY query at apex. RRSIG inception/expiration fixed
  clock injectable for tests.
- Tests `tests/test_dnssec.py`: DNSKEY answer present, RRSIG present iff DO,
  `dns.dnssec.validate` passes on apex SOA, verse answers unsigned.
- Depends on `cryptography`; add to requirements.

## C. Minimal DoH front end (RFC 8484, stdlib only)

- New `qdns/doh.py`: `ThreadingHTTPServer` on 127.0.0.1, default port 8053.
  `POST /dns-query` (`Content-Type: application/dns-message`) raw body;
  `GET /dns-query?dns=<b64url-no-pad>` with padding fixup. Reply 200
  `Content-Type: application/dns-message`, `Cache-Control: max-age=TTL`.
  400/415/404 on misuse. Shared translator: `from_wire -> handle -> to_wire`
  (full wire, no UDP cap; TCP-equivalent semantics).
- Standalone `python -m qdns.doh` plus `--doh-port` wiring in server `main`
  (main wiring done by integrator, not DoH worker, to avoid edit conflict).
- Tests `tests/test_doh.py` via urllib against ephemeral port: POST/GET
  roundtrip verse, 404/415 paths, TC-free long answer over DoH.

## D. Rate limiting + benchmark

- `qdns/server.py`: `RateLimiter` token-bucket per IP (defaults 100 qps,
  burst 200; generous so local demo unaffected). UDP: drop over-limit
  datagrams silently (no reflection). TCP: close connection when over limit.
  Constructor-injectable for tests; defaults preserve current behavior.
- `scripts/bench.py`: asyncio QPS/latency p50/p99 for UDP, TCP, and
  UDP-with-fallback; reports TC rate. DNS-only (no HTTP comparator: the
  question for this prototype is UDP vs TCP/fallback cost).
- Tests `tests/test_ratelimit.py`: bucket refill math, UDP drop hook,
  TCP close hook.

## Contracts for parallel workers

- DNSSEC worker owns: `qdns/dnssec.py`, `scripts/keygen.py`, `qdns/resolver.py`,
  `qdns/config.py`, `tests/test_dnssec.py`, `requirements.txt`.
- DoH worker owns: `qdns/doh.py`, `tests/test_doh.py`. MUST NOT edit
  `qdns/server.py` (integrator wires `--doh-port`).
- Rate-limit worker owns: `qdns/server.py` (additive hooks only),
  `scripts/bench.py`, `tests/test_ratelimit.py`. MUST NOT edit resolver/config.
- Every worker: run `.venv/bin/python -m unittest` before finishing; all
  green. Report files changed + test evidence.
