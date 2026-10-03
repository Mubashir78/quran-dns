"""Section D tests: token-bucket math, UDP drop hook, TCP close hook."""
import asyncio
import socket
import struct
import unittest

import dns.message

from qdns.resolver import Resolver
from qdns.server import RateLimiter, UdpProtocol, start_servers
from qdns.store import VerseStore

STORE = VerseStore({"1:1": {"ar": "بسم الله", "en": "In the name of Allah"}})
RES = Resolver(STORE)
WIRE = dns.message.make_query("1-1.en.quran.test.", "TXT").to_wire()


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class BucketMathTest(unittest.TestCase):
    def test_allow_up_to_burst_then_deny(self):
        lim = RateLimiter(rate=10.0, burst=3.0, clock=Clock())
        self.assertTrue([lim.allow("a") for _ in range(3)])
        self.assertFalse(lim.allow("a"))

    def test_partial_refill(self):
        clock = Clock()
        lim = RateLimiter(rate=10.0, burst=3.0, clock=clock)
        for _ in range(3):
            self.assertTrue(lim.allow("a"))
        self.assertFalse(lim.allow("a"))
        clock.t += 0.05                      # +0.5 token: still short
        self.assertFalse(lim.allow("a"))
        clock.t += 0.05                      # +1.0 token total
        self.assertTrue(lim.allow("a"))
        self.assertFalse(lim.allow("a"))

    def test_refill_capped_at_burst(self):
        clock = Clock()
        lim = RateLimiter(rate=10.0, burst=2.0, clock=clock)
        self.assertTrue(lim.allow("a"))
        self.assertTrue(lim.allow("a"))
        clock.t += 100.0                     # idle long: capped, not 1000 tokens
        self.assertTrue(lim.allow("a"))
        self.assertTrue(lim.allow("a"))
        self.assertFalse(lim.allow("a"))

    def test_buckets_are_per_ip(self):
        lim = RateLimiter(rate=1.0, burst=1.0, clock=Clock())
        self.assertTrue(lim.allow("1.2.3.4"))
        self.assertFalse(lim.allow("1.2.3.4"))
        self.assertTrue(lim.allow("5.6.7.8"))   # other IP unaffected

    def test_defaults(self):
        lim = RateLimiter()
        self.assertEqual((lim.rate, lim.burst), (100.0, 200.0))


class FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))


class UdpDropTest(unittest.TestCase):
    def test_over_limit_datagram_yields_no_reply(self):
        lim = RateLimiter(rate=1.0, burst=1.0, clock=Clock())
        proto = UdpProtocol(RES, limiter=lim)
        fake = FakeTransport()
        proto.connection_made(fake)
        addr = ("127.0.0.1", 9999)
        proto.datagram_received(WIRE, addr)
        self.assertEqual(len(fake.sent), 1)          # first query answered
        self.assertEqual(dns.message.from_wire(fake.sent[0][0]).question[0].name,
                         dns.message.from_wire(WIRE).question[0].name)
        proto.datagram_received(WIRE, addr)
        self.assertEqual(len(fake.sent), 1)          # over limit: dropped, no reply

    def test_other_ip_still_served(self):
        lim = RateLimiter(rate=1.0, burst=1.0, clock=Clock())
        proto = UdpProtocol(RES, limiter=lim)
        fake = FakeTransport()
        proto.connection_made(fake)
        proto.datagram_received(WIRE, ("10.0.0.1", 1111))
        proto.datagram_received(WIRE, ("10.0.0.1", 1111))  # dropped
        proto.datagram_received(WIRE, ("10.0.0.2", 2222))  # fresh bucket: served
        self.assertEqual(len(fake.sent), 2)


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def tcp_query_once(host, port):
    """One TCP query; returns reply bytes, or b"" if the server closed us."""
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(struct.pack("!H", len(WIRE)) + WIRE)
        await writer.drain()
        try:
            hdr = await asyncio.wait_for(reader.readexactly(2), 5.0)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError,
                ConnectionResetError):
            return b""
        (length,) = struct.unpack("!H", hdr)
        try:
            return await asyncio.wait_for(reader.readexactly(length), 5.0)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError,
                ConnectionResetError):
            return b""
    except (ConnectionResetError, BrokenPipeError):
        return b""
    finally:
        writer.close()


class TcpCloseTest(unittest.IsolatedAsyncioTestCase):
    async def test_over_limit_connection_closed_without_reply(self):
        # Frozen clock: no refill, so the outcome is timing-independent.
        lim = RateLimiter(rate=100.0, burst=1.0, clock=lambda: 0.0)
        port = free_port()
        udp, tcp = await start_servers(RES, "127.0.0.1", port, limiter=lim)
        try:
            first = await tcp_query_once("127.0.0.1", port)
            self.assertTrue(first)               # one token: served
            dns.message.from_wire(first)         # parses as a DNS reply
            second = await tcp_query_once("127.0.0.1", port)
            self.assertEqual(second, b"")        # over limit: closed, no reply
        finally:
            udp.close()
            tcp.close()
            await tcp.wait_closed()

    async def test_direct_handle_tcp_guards_peer_ip(self):
        lim = RateLimiter(rate=100.0, burst=1.0, clock=lambda: 0.0)
        port = free_port()
        udp, tcp = await start_servers(RES, "127.0.0.1", port, limiter=lim)
        try:
            # Burst of 1 already spent by the previous connection in this
            # test's server is per-test; open max+1 connections instead.
            results = [await tcp_query_once("127.0.0.1", port) for _ in range(3)]
            self.assertTrue(results[0])
            self.assertEqual(results[1], b"")
            self.assertEqual(results[2], b"")
        finally:
            udp.close()
            tcp.close()
            await tcp.wait_closed()


if __name__ == "__main__":
    unittest.main()
