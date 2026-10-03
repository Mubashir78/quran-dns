"""DNS-over-HTTPS (RFC 8484, stdlib only).

One job: DNS wire format over HTTPS.
  POST /dns-query with Content-Type: application/dns-message (raw body)
  GET  /dns-query?dns=<base64url-no-pad> (padding fixup)
Shared translator: from_wire -> Resolver.handle -> to_wire (full wire,
no UDP cap; TCP-equivalent semantics). Replies 200 with
Content-Type: application/dns-message and Cache-Control: max-age=TTL.

Reader pages live in web.py, SMS in sms.py; both register their routes
on the same server via make_server.
"""
from __future__ import annotations

import argparse
import base64
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import dns.exception
import dns.message
import dns.rcode

from .config import DEFAULT_DATA, TTL, ZONE
from .http import Router, send_bytes, send_text
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


def _doh_get(h, server, parsed, qs) -> None:
    vals = qs.get("dns")
    if not vals or not vals[0]:
        send_text(h, 400, "missing dns parameter")
        return
    s = vals[0].strip()
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        send_text(h, 400, "bad dns parameter")
        return
    if not raw:
        send_text(h, 400, "empty dns message")
        return
    try:
        wire = translate(server.resolver, raw)
    except Exception:
        send_text(h, 400, "bad dns message")
        return
    _send_dns(h, wire)


def _doh_post(h, server, parsed, qs) -> None:
    ctype = h.headers.get("Content-Type", "")
    media = ctype.split(";")[0].strip().lower()
    if media != DOH_MIME:
        send_text(h, 415, "unsupported media type")
        return
    length = h.headers.get("Content-Length")
    try:
        n = int(length) if length is not None else 0
    except ValueError:
        send_text(h, 400, "bad content-length")
        return
    if n < 0:
        send_text(h, 400, "bad content-length")
        return
    try:
        body = h.rfile.read(n) if n > 0 else b""
    except Exception:
        send_text(h, 400, "bad request body")
        return
    if not body:
        send_text(h, 400, "empty dns message")
        return
    try:
        wire = translate(server.resolver, body)
    except Exception:
        send_text(h, 400, "bad dns message")
        return
    _send_dns(h, wire)


def _send_dns(h, wire: bytes) -> None:
    send_bytes(h, 200, wire, DOH_MIME, {"Cache-Control": f"max-age={TTL}"})


def build_router() -> Router:
    from .sms import register_sms
    from .web import register_web
    router = Router()
    router.add("GET", DOH_PATH, _doh_get)
    router.add("POST", DOH_PATH, _doh_post)
    register_web(router)
    register_sms(router)
    return router


def make_server(resolver: Resolver, host: str = "127.0.0.1", port: int = 8053,
                store=None, gateway=None, sms_token: str = "") -> ThreadingHTTPServer:
    from .sms import Cooldown
    server = ThreadingHTTPServer((host, port), DohHandler)
    server.router = build_router()  # type: ignore[attr-defined]
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

    def _dispatch(self, method: str) -> None:
        self.server.router.dispatch(self, method, self.path)  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def __getattr__(self, name):
        # Any other verb -> same 404/405 mapping, not the default 501.
        if name.startswith("do_"):
            def _fallback():
                self._dispatch(name[3:])
            return _fallback
        raise AttributeError(name)


def serve(host: str, port: int, data_path, zone: str,
          sms_send_url: str = "", sms_token: str = "",
          sms_username: str = "", sms_password: str = "",
          sms_smsgate: bool = False) -> None:
    from .resolver import build_resolver
    from .sms import make_gateway
    store = VerseStore.from_file(data_path)
    resolver = build_resolver(store, zone)
    gateway = make_gateway(sms_send_url, sms_token,
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
