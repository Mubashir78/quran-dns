"""Reader web UI routes: page, substring search, DNSSEC verify, fonts.

One job: browser-facing pages and JSON helpers. DNS answers stay in
resolver/doh; SMS stays in sms.
"""
from __future__ import annotations

import json
from pathlib import Path

from .http import Router, send_bytes, send_text

# family -> fontconfig pattern, resolved once per process.
_FONTS = {
    "naskh": "Noto Naskh Arabic",
    "nastaliq": "Noto Nastaliq Urdu",
}
_FONT_CACHE: dict = {}


def serve_page(h, server, parsed, qs) -> None:
    try:
        body = (Path(__file__).resolve().parent / "web.html").read_bytes()
    except OSError:
        send_text(h, 404, "not found")
        return
    send_bytes(h, 200, body, "text/html; charset=utf-8",
               {"Cache-Control": "no-store"})


def serve_font(h, server, parsed, qs) -> None:
    # Self-hosted fonts: phones often lack Quranic-mark
    # glyphs (U+06E1/06E2/06E5). Resolved once per process.
    which = parsed.path.rsplit("/", 1)[-1]
    pattern = _FONTS.get(which)
    if pattern is None:
        send_text(h, 404, "font not found")
        return
    data = _FONT_CACHE.get(which)
    if data is None:
        import subprocess
        try:
            out = subprocess.run(
                ["fc-match", pattern, "--format=%{file}"],
                capture_output=True, text=True, timeout=5)
            data = Path(out.stdout.strip()).read_bytes()
            _FONT_CACHE[which] = data
        except Exception:
            send_text(h, 404, "font not found")
            return
    send_bytes(h, 200, data, "font/ttf", {"Cache-Control": "max-age=86400"})


def serve_search(h, server, parsed, qs) -> None:
    """Substring search over one language. JSON list of up to 20 refs."""
    q = (qs.get("q") or [""])[0].strip()
    lang = (qs.get("lang") or ["en"])[0].strip()
    if len(q) < 3 or lang not in ("ar", "en", "ur"):
        send_text(h, 400, "need q=<3+ chars> and lang=en|ur|ar")
        return
    store = getattr(server, "store", None)
    if store is None:
        store = server.resolver.store
    hits = [{"ref": ref, "snippet": snip}
            for ref, snip in store.search(q, lang)]
    body = json.dumps({"q": q, "lang": lang, "hits": hits}).encode("utf-8")
    send_bytes(h, 200, body, "application/json")


def serve_verify(h, server, parsed, qs) -> None:
    """Server-side DNSSEC check of one verse answer. JSON out."""
    import re

    import dns.dnssec
    import dns.flags
    import dns.message
    import dns.rdatatype
    ref = (qs.get("ref") or [""])[0].strip()
    lang = (qs.get("lang") or ["en"])[0].strip()
    m = re.fullmatch(r"(\d{1,3})[:\-](\d{1,3})", ref)
    if not m or lang not in ("ar", "en", "ur"):
        send_text(h, 400, "need ref=S:A and lang=en|ur|ar")
        return
    resolver = server.resolver
    if resolver.dnssec is None or resolver.verse_signer is None:
        send_text(h, 503, "signing off")
        return
    name = f"{int(m.group(1))}-{int(m.group(2))}.{lang}.{resolver.zone.to_text()}"
    q = dns.message.make_query(name, "TXT", use_edns=0, payload=1232)
    q.ednsflags |= dns.flags.DO
    resp = resolver.handle(q)
    txt = rrsig = None
    for rr in resp.answer:
        if rr.rdtype == dns.rdatatype.TXT:
            txt = rr
        elif rr.rdtype == dns.rdatatype.RRSIG:
            rrsig = rr
    valid = False
    if txt is not None and rrsig is not None:
        try:
            dns.dnssec.validate(txt, rrsig, resolver.dnssec.keyring())
            valid = True
        except Exception:
            valid = False
    body = json.dumps({"ref": ref, "lang": lang, "valid": valid}).encode()
    send_bytes(h, 200, body, "application/json")


def register_web(router: Router) -> None:
    router.add("GET", "/", serve_page)
    router.add("GET", "/search", serve_search)
    router.add("GET", "/verify", serve_verify)
    router.add_prefix("GET", "/font/", serve_font)
