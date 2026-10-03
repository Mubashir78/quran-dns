"""Minimal DoH front end (RFC 8484, stdlib only).

ThreadingHTTPServer on 127.0.0.1:8053 by default.
  POST /dns-query with Content-Type: application/dns-message (raw body)
  GET  /dns-query?dns=<base64url-no-pad> (padding fixup)
Shared translator: from_wire -> Resolver.handle -> to_wire (full wire,
no UDP cap; TCP-equivalent semantics). Replies 200 with
Content-Type: application/dns-message and Cache-Control: max-age=TTL.
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import dns.exception
import dns.message
import dns.rcode

from .config import DEFAULT_DATA, TTL, ZONE
from .resolver import Resolver
from .store import VerseStore

log = logging.getLogger("qdns.doh")

DOH_PATH = "/dns-query"
DOH_MIME = "application/dns-message"


def translate(resolver: Resolver, body: bytes) -> bytes:
    """Shared translator: wire in -> wire out (full size, no UDP cap)."""
    query = dns.message.from_wire(body)
    resp = resolver.handle(query)
    try:
        return resp.to_wire()
    except dns.exception.TooBig:
        resp.set_rcode(dns.rcode.SERVFAIL)
        return resp.to_wire()


SMS_PATH = "/sms/incoming"
SMS_MIME = "application/json"


def make_server(resolver: Resolver, host: str = "127.0.0.1", port: int = 8053,
                store=None, gateway=None, sms_token: str = "") -> ThreadingHTTPServer:
    from .sms import Cooldown
    server = ThreadingHTTPServer((host, port), DohHandler)
    server.resolver = resolver  # type: ignore[attr-defined]
    server.store = store  # type: ignore[attr-defined]
    server.sms_gateway = gateway  # type: ignore[attr-defined]
    server.sms_token = sms_token  # type: ignore[attr-defined]
    server.sms_cooldown = Cooldown()  # type: ignore[attr-defined]
    server.daemon_threads = True
    return server


class DohHandler(BaseHTTPRequestHandler):
    server_version = "qdns-doh"

    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    # -- helpers ---------------------------------------------------------
    def _send_text(self, code: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(code, text)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_dns(self, wire: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", DOH_MIME)
        self.send_header("Content-Length", str(len(wire)))
        self.send_header("Cache-Control", f"max-age={TTL}")
        self.end_headers()
        try:
            self.wfile.write(wire)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_page(self) -> None:
        try:
            from pathlib import Path
            body = (Path(__file__).resolve().parent / "web.html").read_bytes()
        except OSError:
            self._send_text(404, "not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # family -> fontconfig pattern, resolved once per process.
    _FONTS = {
        "naskh": "Noto Naskh Arabic",
        "nastaliq": "Noto Nastaliq Urdu",
    }
    _FONT_CACHE: dict = {}

    def _send_font(self, which: str) -> None:
        # Self-hosted fonts: phones often lack Quranic-mark
        # glyphs (U+06E1/06E2/06E5). Resolved once per process.
        pattern = self._FONTS.get(which)
        if pattern is None:
            self._send_text(404, "font not found")
            return
        data = self._FONT_CACHE.get(which)
        if data is None:
            import subprocess
            try:
                out = subprocess.run(
                    ["fc-match", pattern, "--format=%{file}"],
                    capture_output=True, text=True, timeout=5)
                from pathlib import Path as _P
                data = _P(out.stdout.strip()).read_bytes()
                self._FONT_CACHE[which] = data
            except Exception:
                self._send_text(404, "font not found")
                return
        self.send_response(200)
        self.send_header("Content-Type", "font/ttf")
        self.send_header("Cache-Control", "max-age=86400")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _method_not_allowed(self) -> None:
        if urlparse(self.path).path != DOH_PATH:
            self._send_text(404, "not found")
        else:
            self._send_text(405, "method not allowed")

    def __getattr__(self, name):
        # Any unimplemented do_* verb -> 405 (or 404 on wrong path),
        # instead of the default 501.
        if name.startswith("do_"):
            def _fallback():
                self._method_not_allowed()
            return _fallback
        raise AttributeError(name)

    # -- verbs -----------------------------------------------------------
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            return self._send_page()
        if parsed.path == "/verify":
            return self._do_verify(parse_qs(parsed.query, keep_blank_values=True))
        if parsed.path == "/search":
            return self._do_search(parse_qs(parsed.query, keep_blank_values=True))
        if parsed.path == "/font/naskh":
            return self._send_font("naskh")
        if parsed.path == "/font/nastaliq":
            return self._send_font("nastaliq")
        if parsed.path != DOH_PATH:
            self._send_text(404, "not found")
            return
        qs = parse_qs(parsed.query, keep_blank_values=True)
        vals = qs.get("dns")
        if not vals or not vals[0]:
            self._send_text(400, "missing dns parameter")
            return
        s = vals[0].strip()
        try:
            raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        except Exception:
            self._send_text(400, "bad dns parameter")
            return
        if not raw:
            self._send_text(400, "empty dns message")
            return
        try:
            wire = translate(self.server.resolver, raw)  # type: ignore[attr-defined]
        except Exception:
            self._send_text(400, "bad dns message")
            return
        self._send_dns(wire)

    def _do_verify(self, qs) -> None:
        """Server-side DNSSEC check of one verse answer. JSON out."""
        import dns.dnssec
        import dns.flags
        import dns.rdatatype
        ref = (qs.get("ref") or [""])[0].strip()
        lang = (qs.get("lang") or ["en"])[0].strip()
        m = __import__("re").fullmatch(r"(\d{1,3})[:\-](\d{1,3})", ref)
        if not m or lang not in ("ar", "en", "ur"):
            self._send_text(400, "need ref=S:A and lang=en|ur|ar")
            return
        resolver = self.server.resolver  # type: ignore[attr-defined]
        if resolver.dnssec is None or resolver.verse_signer is None:
            self._send_text(503, "signing off")
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
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _do_search(self, qs) -> None:
        """Substring search over one language. JSON list of up to 20 refs."""
        q = (qs.get("q") or [""])[0].strip()
        lang = (qs.get("lang") or ["en"])[0].strip()
        if len(q) < 3 or lang not in ("ar", "en", "ur"):
            self._send_text(400, "need q=<3+ chars> and lang=en|ur|ar")
            return
        store = getattr(self.server, "store", None)  # type: ignore[attr-defined]
        if store is None:
            store = self.server.resolver.store  # type: ignore[attr-defined]
        qfold = q.casefold()
        hits = []
        for ref in sorted(store._verses, key=lambda r: tuple(map(int, r.split(":")))):
            text = store._verses[ref].get(lang, "")
            if qfold in text.casefold():
                s, a = ref.split(":")
                hits.append({"ref": f"{s}:{a}", "snippet": text[:120]})
                if len(hits) >= 20:
                    break
        body = json.dumps({"q": q, "lang": lang, "hits": hits}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == SMS_PATH:
            return self._do_sms()
        if parsed.path != DOH_PATH:
            self._send_text(404, "not found")
            return
        ctype = self.headers.get("Content-Type", "")
        media = ctype.split(";")[0].strip().lower()
        if media != DOH_MIME:
            self._send_text(415, "unsupported media type")
            return
        length = self.headers.get("Content-Length")
        try:
            n = int(length) if length is not None else 0
        except ValueError:
            self._send_text(400, "bad content-length")
            return
        if n < 0:
            self._send_text(400, "bad content-length")
            return
        try:
            body = self.rfile.read(n) if n > 0 else b""
        except Exception:
            self._send_text(400, "bad request body")
            return
        if not body:
            self._send_text(400, "empty dns message")
            return
        try:
            wire = translate(self.server.resolver, body)  # type: ignore[attr-defined]
        except Exception:
            self._send_text(400, "bad dns message")
            return
        self._send_dns(wire)

    def _do_sms(self) -> None:
        from .sms import handle_incoming
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ctype != SMS_MIME:
            self._send_text(415, "unsupported media type")
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(n) if n > 0 else b"")
        except Exception:
            self._send_text(400, "bad json body")
            return
        if self.server.store is None or self.server.sms_gateway is None:  # type: ignore[attr-defined]
            self._send_text(503, "sms gateway not configured")
            return
        try:
            result = handle_incoming(payload, self.server.store,  # type: ignore[attr-defined]
                                     self.server.sms_token,  # type: ignore[attr-defined]
                                     self.server.sms_cooldown)  # type: ignore[attr-defined]
        except PermissionError:
            self._send_text(403, "bad sms token")
            return
        except KeyError:
            self._send_text(400, "payload needs from/body fields")
            return
        if result is None:
            self._send_text(200, "cooldown, reply skipped")
            return
        sender, reply = result
        try:
            self.server.sms_gateway.send(sender, reply)  # type: ignore[attr-defined]
        except Exception as exc:
            log.warning("sms send failed: %s", exc)
            self._send_text(502, "relay send failed")
            return
        self._send_text(200, "replied")

    # Explicit common verbs -> 405 (fallback __getattr__ covers the rest).
    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_HEAD(self) -> None:
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()


def serve(host: str, port: int, data_path, zone: str,
          sms_send_url: str = "", sms_token: str = "",
          sms_username: str = "", sms_password: str = "",
          sms_smsgate: bool = False) -> None:
    store = VerseStore.from_file(data_path)
    try:
        from .dnssec import load_signer
        signer = load_signer()
    except Exception:
        signer = None
    resolver = Resolver(store, zone=zone, dnssec=signer)
    if signer is not None:
        from .dnssec import VerseSigner, verse_chain
        vsigner = VerseSigner(signer.zsk_private, signer.zsk_dnskey, zone=zone)
        vsigner.set_chain(verse_chain(store, zone))
        resolver.verse_signer = vsigner
    gateway = None
    if sms_send_url:
        from .sms import PhoneGateway
        gateway = PhoneGateway(sms_send_url, sms_token,
                               sms_username, sms_password, sms_smsgate)
    httpd = make_server(resolver, host, port, store=store,
                        gateway=gateway, sms_token=sms_token)
    log.info("serving %d verses for zone %s on %s:%d (doh)",
             len(store), zone, host, httpd.server_address[1])
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main(argv=None):
    ap = argparse.ArgumentParser(description="Qur'an-over-DNS DoH front end (prototype)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8053)
    ap.add_argument("--data", default=str(DEFAULT_DATA))
    ap.add_argument("--zone", default=ZONE)
    ap.add_argument("--sms-send-url", default="",
                    help="relay app send API (enables POST /sms/incoming)")
    ap.add_argument("--sms-token", default="",
                    help="shared secret the relay app must send back")
    ap.add_argument("--sms-username", default="",
                    help="relay app local API username (SMSGate mode)")
    ap.add_argument("--sms-password", default="",
                    help="relay app local API password (SMSGate mode)")
    ap.add_argument("--sms-smsgate", action="store_true",
                    help="use SMSGate local API payload shape")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.WARNING if args.quiet else logging.INFO,
                        format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    serve(args.host, args.port, args.data, args.zone,
          args.sms_send_url, args.sms_token,
          args.sms_username, args.sms_password, args.sms_smsgate)


if __name__ == "__main__":
    main()
