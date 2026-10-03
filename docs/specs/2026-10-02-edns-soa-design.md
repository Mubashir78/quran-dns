# Design: EDNS0 Negotiated + SOA/NS Apex (Phase 2 First Step)

Date: 2026-10-02
Status: draft for review
Scope: local demo only, `127.0.0.1:5353`, keep RFC1035 512 + negotiate `min(client,1232)`

## 1. Intent

Enable modern resolvers to get larger UDP answers without forced TCP fallback, while keeping backward compat with plain 512 clients. Add authoritative SOA/NS + negative caching. Unlock DNSSEC and DoH later.

Success:
- Plain query (no OPT) still 512 + TC+empty on large verse, TCP full.
- EDNS query `payload=4096` gets UDP answer up to 1232 when fits.
- `payload<512` clamps to 512.
- `edns version>0` returns BADVERS.
- Apex SOA/NS queries answer directly. NXDOMAIN and NODATA carry SOA in authority.
- All 18 existing tests updated, no regressions. New tests cover EDNS + SOA.

Non-goals:
- No public internet exposure. No rate limiting, ACL, or delegation now.
- No DNSSEC signing now. No DoH now. No bench now.

## 2. Constraints

- Files: `qdns/config.py`, `qdns/resolver.py`, `qdns/server.py`, `tests/test_resolver_e2e.py`
- Data: `data/quran.json` 6236 verses, worst `2:282 bn` 3325 B, 14 chunks. Never fits UDP. Must TC.
- Compat: negotiated only. No require-EDNS. Client `qdns/client.py:30` sends no OPT, stays old path.
- Local demo: `host 127.0.0.1`, no hardening beyond crash guards.

## 3. Approaches Considered

### A. Negotiated EDNS + SOA first (recommended, approved)

Change resolver to echo OPT with server max 1232. Change server to derive UDP limit from query. Add SOA/NS apex + authority.

Pros: backward compat, fewer TCP fallbacks, unlocks DNSSEC/DoH, low risk, testable locally.
Cons: touches wire path, needs test updates.

### B. DNSSEC first

Sign verses with Ed25519, serve DNSKEY/RRSIG.

Rejected first: needs EDNS (RRSIG blows 512), needs SOA, key management overhead. Do after A.

### C. DoH first

Add `qdns/doh.py` POST/GET reusing `Resolver.handle`.

Rejected first: reuses same handle, but without EDNS+SOA semantics DoH inherits gaps. Do after A.

## 4. Design

### 4.1 Config `qdns/config.py:9`

Add:
```python
SERVER_EDNS_MAX = 1232
NEG_TTL = 300
NS_NAMES = ("ns1.quran.test.",)
SOA_MNAME = "ns1.quran.test."
SOA_RNAME = "hostmaster.quran.test."
```

Keep `UDP_LIMIT=512`, `TTL=3600`, `ZONE=quran.test.`

### 4.2 Resolver `qdns/resolver.py:27`

Current: `resp = make_response(query)` then `resp.use_edns(-1)` strips OPT.

New:
```python
resp = dns.message.make_response(query, our_payload=SERVER_EDNS_MAX)
if query.edns is not None and query.edns > 0:
    resp.set_rcode(dns.rcode.BADVERS)
    return resp
if resp.edns >= 0 and resp.request_payload < 512:
    resp.request_payload = 512
```

Keep opcode, question count, zone checks. Set AA. Parse via `qdns/names.py:32` `parse_qname`. Lookup via `VerseStore.get`.

Apex: if `q.name == zone`:
- `SOA` -> answer SOA only
- `NS` -> answer NS only
- `TXT` or `ANY` -> answer TXT help text only (no SOA/NS in answer)

NXDOMAIN paths (`QueryParseError`, lookup None): set NXDOMAIN, append SOA RRset to `authority`.

NODATA path (non-TXT type): keep NOERROR empty answer, append SOA to `authority` per RFC2308.

DO bit: ignore for now (unsigned zone). Do not set AD.

### 4.3 Server `qdns/server.py:35`

Current: fixed `to_wire(max_size=512)`, second `to_wire()` unbounded.

New helper:
```python
def _udp_limit(query) -> int:
    if query.edns is not None and query.edns >= 0:
        return max(512, min(query.payload, SERVER_EDNS_MAX, 65535))
    return UDP_LIMIT
```

In `process(udp=True)`:
```python
limit = _udp_limit(query)
try:
    wire = resp.to_wire(max_size=limit)
except dns.exception.TooBig:
    resp.answer.clear()
    resp.flags |= dns.flags.TC
    wire = resp.to_wire(max_size=limit)
```

TCP path unchanged `to_wire()` full.

Hardening (local still):
- `handle_tcp`: reject `length==0 or length>65535`, close. Add total deadline 30s, `Semaphore(100)` cap.
- Wrap `datagram_received` + `process` in try/except, log warning.
- `log.info` per query -> `debug` to avoid flood.
- `_formerr` keep ID echo, QDCOUNT 0.

### 4.4 TXT `qdns/txt.py:21`

Add `assert 1 <= limit <= 255` in `chunk_utf8`. No change to split logic (proven UTF-8 safe). `join_txt` caller catches decode error.

### 4.5 Store `qdns/store.py:14`

Add load validation: check `verses` exists, each value has all LANGS, count 6236 warn if not. Raise `ValueError` with path.

### 4.6 Tests `tests/test_resolver_e2e.py`

Update `test_edns_query_gets_no_opt` -> assert `edns==0`, `payload<=1232`, `request_payload==4096`.
Add:
- no-EDNS long verse TC+empty, TCP full (exists, keep)
- EDNS 4096 short verse fits UDP, no TC
- EDNS 4096 long verse `2:282 en` 2.5KB with server cap 1232 -> TC (proves min)
- EDNS 512 long verse -> TC
- EDNS 100 -> clamped 512 -> TC
- BADVERS on `edns=1`
- Apex SOA/NS answer, NXDOMAIN has SOA authority, NODATA has SOA authority
- All 6236x4 TCP roundtrip + UDP either fits or TC+empty

## 5. Risks

- Long QNAME + OPT could make second `to_wire()` TooBig. Mitigate: cap second wire same limit, fallback SERVFAIL.
- Serial bump needed on data reload else negative cache poisons. Use date-based serial, bump on startup.
- `dnspython` `to_wire(max_size=0)` uses request_payload, but plain queries need 512. Do not use 0, use explicit limit.
- TCP zero-length spin. Mitigate length check.

## 6. Verification

- `python -m unittest` green
- Manual: `dig @127.0.0.1 -p 5353 2-255.en.quran.test TXT +short` fits UDP
- `dig +bufsize=4096` long verse no TC when <1232, TC when >1232
- `dig help.quran.test TXT +short`, `dig quran.test SOA +short`, `dig 9-9.en.quran.test TXT` NXDOMAIN + SOA authority
- Wireshark filter `udp.port==5353 || tcp.port==5353`

## 7. Todo Plan (via todo-list skill)

1. [x] Baseline tests green - 18 pass (pre-change)
2. [x] Harden TCP/UDP guards + logging - zero-length/garbage covered by tests
3. [x] Implement EDNS negotiated - payload/BADVERS tests green, dig shows udp:1232
4. [x] Implement SOA/NS + authority - dig SOA/NS/NXDOMAIN+SOA verified
5. [x] Update + add tests - full suite 28 pass
6. [x] Manual dig verify - short UDP, long TC->TCP, SOA, NS, NXDOMAIN+SOA all confirmed

Next after approval: write implementation plan, then execute 1-6.

## 8. Status (2026-10-02, implemented)
Done: EDNS negotiated (min 512, max 1232, BADVERS), SOA/NS apex + SOA
on NXDOMAIN/NODATA, TCP/UDP guards (length, lifetime, query cap, 100-conn
semaphore, SERVFAIL fallback, quiet log default), store/txt/client
validation. Tests: 28 pass (`python -m unittest`). Live smoke: short verse
UDP, 2:282 TCP fallback OK.
