"""Step 5: transports. asyncio UDP + TCP listeners around the Resolver.

UDP : one datagram in -> one datagram out. If the answer is bigger than
      UDP_LIMIT we set the TC (truncated) flag and send NO answer data; the
      client then retries over TCP (RFC 1035 s4.2.1).
TCP : each message is prefixed by a 2-byte big-endian length (RFC 1035 s4.2.2).
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import struct
import time

import dns.exception
import dns.flags
import dns.message
import dns.rcode

from .config import DEFAULT_DATA, SERVER_EDNS_MAX, UDP_LIMIT, ZONE
from .resolver import Resolver
from .store import VerseStore

log = logging.getLogger("qdns")

_TCP_SEM = asyncio.Semaphore(100)


class RateLimiter:
    """Token-bucket rate limiter, one bucket per client IP.

    Defaults (100 qps, burst 200) are generous so the local demo is
    unaffected; the limiter only sheds abusive load. ``clock`` is
    injectable (defaults to :func:`time.monotonic`) so tests can drive
    refill deterministically.
    """

    def __init__(self, rate: float = 100.0, burst: float = 200.0,
                 clock=time.monotonic):
        self.rate = rate
        self.burst = burst
        self._clock = clock
        self._buckets: dict[str, list[float]] = {}  # ip -> [tokens, last_stamp]

    def allow(self, ip: str) -> bool:
        now = self._clock()
        bucket = self._buckets.get(ip)
        if bucket is None:
            tokens, last = self.burst, now
        else:
            tokens, last = bucket
            tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens >= 1.0:
            self._buckets[ip] = [tokens - 1.0, now]
            return True
        self._buckets[ip] = [tokens, now]
        return False


DEFAULT_LIMITER = RateLimiter()


def _udp_limit(query: dns.message.Message) -> int:
    if query.edns is not None and query.edns >= 0:
        payload = query.payload or 512
        return max(512, min(payload, SERVER_EDNS_MAX, 65535))
    return UDP_LIMIT


def _formerr(data: bytes) -> bytes | None:
    """Unparseable packet: echo its ID back with FORMERR if we can."""
    if len(data) < 12:
        return None
    flags = int(dns.flags.QR) | int(dns.rcode.FORMERR)   # response bit + rcode 1
    return data[:2] + struct.pack("!HHHHH", flags, 0, 0, 0, 0)


def process(resolver: Resolver, data: bytes, *, udp: bool) -> bytes | None:
    """bytes in -> bytes out. Shared by both transports."""
    try:
        query = dns.message.from_wire(data)
    except Exception:                                  # malformed packet
        return _formerr(data)

    resp = resolver.handle(query)
    if not udp:
        try:
            wire = resp.to_wire()
        except dns.exception.TooBig:
            resp.set_rcode(dns.rcode.SERVFAIL)
            wire = resp.to_wire()
    else:
        limit = _udp_limit(query)
        try:
            wire = resp.to_wire(max_size=limit)
        except dns.exception.TooBig:
            resp.answer.clear()
            resp.flags |= dns.flags.TC
            try:
                wire = resp.to_wire(max_size=limit)
            except dns.exception.TooBig:
                resp.set_rcode(dns.rcode.SERVFAIL)
                wire = resp.to_wire(max_size=limit)

    q = query.question[0].name if query.question else "<none>"
    log.debug("%s %-28s -> %s %dB%s", "udp" if udp else "tcp", q,
              dns.rcode.to_text(resp.rcode()), len(wire),
              " TC" if resp.flags & dns.flags.TC else "")
    return wire


class UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolver: Resolver, limiter: RateLimiter | None = None):
        self.resolver = resolver
        self.limiter = DEFAULT_LIMITER if limiter is None else limiter
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        ip = addr[0] if isinstance(addr, tuple) else str(addr)
        if self.limiter is not None and not self.limiter.allow(ip):
            return                               # over limit: drop silently, no reply
        try:
            reply = process(self.resolver, data, udp=True)
        except Exception:
            log.warning("udp process failed from %s", addr, exc_info=True)
            return
        if reply:
            try:
                self.transport.sendto(reply, addr)
            except Exception:
                log.warning("udp sendto failed to %s", addr, exc_info=True)


async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                     resolver: Resolver, idle: float = 10.0,
                     max_lifetime: float = 30.0, max_queries: int = 100,
                     limiter: RateLimiter | None = None):
    if limiter is not None:                      # per-connection check: shed load
        peer = writer.get_extra_info("peername")
        ip = peer[0] if isinstance(peer, tuple) else str(peer)
        if not limiter.allow(ip):
            writer.close()
            return
    start = time.monotonic()
    queries = 0
    try:
        while True:                                     # clients may reuse the connection
            if time.monotonic() - start > max_lifetime or queries >= max_queries:
                break
            hdr = await asyncio.wait_for(reader.readexactly(2), idle)
            (length,) = struct.unpack("!H", hdr)
            if length == 0:
                break
            if length > 65535:
                break
            data = await asyncio.wait_for(reader.readexactly(length), idle)
            queries += 1
            try:
                reply = process(resolver, data, udp=False)
            except Exception:
                log.warning("tcp process failed", exc_info=True)
                break
            if reply:
                writer.write(struct.pack("!H", len(reply)) + reply)
                await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()


async def start_servers(resolver: Resolver, host: str, port: int,
                        limiter: RateLimiter | None = None):
    lim = DEFAULT_LIMITER if limiter is None else limiter
    loop = asyncio.get_running_loop()
    udp, _ = await loop.create_datagram_endpoint(
        lambda: UdpProtocol(resolver, limiter=lim), local_addr=(host, port))

    async def _guarded(reader, writer):
        async with _TCP_SEM:
            await handle_tcp(reader, writer, resolver, limiter=lim)

    tcp = await asyncio.start_server(_guarded, host, port)
    return udp, tcp


async def serve(host: str, port: int, data_path, zone: str, doh_port: int | None = None,
              sms_send_url: str = "", sms_token: str = "",
              sms_username: str = "", sms_password: str = "",
              sms_smsgate: bool = False, sms_base_url: str = "",
              sms_poll: float = 10.0):
    store = VerseStore.from_file(data_path)
    from .resolver import build_resolver
    resolver = build_resolver(store, zone)
    if resolver.dnssec is not None:
        log.info("DNSSEC island active (apex SOA/NS/DNSKEY signed, Ed25519)")
    else:
        log.warning("DNSSEC off (no keys); run scripts/keygen.py")
    if resolver.verse_signer is not None:
        log.info("verse signing + NSEC khatmah chain active (%d names)",
                 len(resolver.verse_signer._next))
    udp, tcp = await start_servers(resolver, host, port)
    log.info("serving %d verses for zone %s on %s:%d (udp+tcp)",
             len(store), zone, host, port)
    httpd = None
    if doh_port is not None:
        from .doh import make_server
        from .sms import make_gateway
        import threading
        gateway = make_gateway(sms_send_url, sms_token,
                               sms_username, sms_password, sms_smsgate)
        httpd = make_server(resolver, host, doh_port, store=store,
                            gateway=gateway, sms_token=sms_token)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        log.info("serving DoH for zone %s on %s:%d (/dns-query)",
                 zone, host, httpd.server_address[1])
    if sms_base_url:
        from .sms import Cooldown, InboxPoller, make_gateway, poll_forever
        import threading
        gateway = make_gateway(sms_base_url.rstrip("/") + "/message",
                               sms_token, sms_username, sms_password, sms_smsgate)
        poller = InboxPoller(sms_base_url, sms_username, sms_password,
                             store, gateway, Cooldown())
        threading.Thread(target=poll_forever,
                         args=(poller, sms_poll), daemon=True).start()
        log.info("polling SMS inbox at %s every %ss", sms_base_url, sms_poll)
    try:
        await asyncio.Event().wait()                    # run forever
    finally:
        udp.close()
        tcp.close()
        if httpd is not None:
            httpd.shutdown()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Qur'an-over-DNS server (prototype)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5353, help="53 needs root; default 5353")
    ap.add_argument("--data", default=str(DEFAULT_DATA))
    ap.add_argument("--zone", default=ZONE)
    ap.add_argument("--doh-port", type=int, default=None,
                    help="also serve DoH on this port (default: off)")
    ap.add_argument("--sms-send-url", default="",
                    help="relay app send API (enables POST /sms/incoming on DoH port)")
    ap.add_argument("--sms-token", default="",
                    help="shared secret the relay app must send back")
    ap.add_argument("--sms-username", default="",
                    help="relay app local API username (SMSGate mode)")
    ap.add_argument("--sms-password", default="",
                    help="relay app local API password (SMSGate mode)")
    ap.add_argument("--sms-smsgate", action="store_true",
                    help="use SMSGate local API payload shape")
    ap.add_argument("--sms-base-url", default="",
                    help="phone local server base (enables inbox polling)")
    ap.add_argument("--sms-poll", type=float, default=10.0,
                    help="inbox poll interval seconds")
    ap.add_argument("-q", "--quiet", action="store_true", help="hide per-query log lines")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.WARNING if args.quiet else logging.INFO,
                        format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    try:
        asyncio.run(serve(args.host, args.port, args.data, args.zone, args.doh_port,
                          args.sms_send_url, args.sms_token,
                          args.sms_username, args.sms_password, args.sms_smsgate,
                          args.sms_base_url, args.sms_poll))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
