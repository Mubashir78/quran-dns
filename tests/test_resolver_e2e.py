import asyncio
import socket
import unittest
from pathlib import Path

import dns.flags
import dns.message
import dns.query
import dns.rcode

from qdns.client import fetch
from qdns.config import DEFAULT_DATA
from qdns.resolver import Resolver
from qdns.server import process, start_servers
from qdns.store import VerseStore
from qdns.txt import join_txt

LONG = "الحمد لله رب العالمين " * 120          # ~2.5 KB, far above 512 B
STORE = VerseStore({"1:1": {"ar": "بسم الله", "en": "In the name of Allah"},
                    "2:282": {"en": LONG}})
RES = Resolver(STORE)


def ask(name, rdtype="TXT", udp=True):
    wire = dns.message.make_query(name, rdtype).to_wire()
    return dns.message.from_wire(process(RES, wire, udp=udp))


def ask_edns(name, rdtype="TXT", udp=True, payload=4096, version=0):
    q = dns.message.make_query(name, rdtype, use_edns=version, payload=payload)
    return dns.message.from_wire(process(RES, q.to_wire(), udp=udp))


class ResolverTest(unittest.TestCase):
    def test_hit(self):
        r = ask("1-1.en.quran.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertTrue(r.flags & dns.flags.AA)
        self.assertEqual(join_txt(r.answer[0][0]), "In the name of Allah")

    def test_unicode_roundtrip(self):
        self.assertEqual(join_txt(ask("1-1.quran.test.").answer[0][0]), "بسم الله")

    def test_missing_verse_or_lang_is_nxdomain(self):
        self.assertEqual(ask("1-1.ur.quran.test.").rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual(ask("9-9.en.quran.test.").rcode(), dns.rcode.NXDOMAIN)

    def test_outside_zone_refused(self):
        self.assertEqual(ask("example.com.").rcode(), dns.rcode.REFUSED)

    def test_wrong_type_is_nodata(self):
        r = ask("1-1.en.quran.test.", "A")
        self.assertEqual((r.rcode(), len(r.answer)), (dns.rcode.NOERROR, 0))

    def test_edns_query_keeps_opt_capped(self):
        q = dns.message.make_query("1-1.en.quran.test.", "TXT", use_edns=0, payload=4096)
        direct = RES.handle(q)
        self.assertEqual(direct.request_payload, 4096)
        r = dns.message.from_wire(process(RES, q.to_wire(), udp=True))
        self.assertEqual(r.edns, 0)
        self.assertLessEqual(r.payload, 1232)

    def test_edns_mid_answer_fits_udp_with_cap(self):
        mid = VerseStore({"1:1": {"en": "m" * 800}})
        res = Resolver(mid)
        for payload, want_tc in ((512, True), (4096, False)):
            q = dns.message.make_query("1-1.en.quran.test.", "TXT",
                                       use_edns=0, payload=payload)
            r = dns.message.from_wire(process(res, q.to_wire(), udp=True))
            self.assertEqual(bool(r.flags & dns.flags.TC), want_tc)

    def test_edns_small_cap_clamped(self):
        q = dns.message.make_query("2-282.en.quran.test.", "TXT",
                                   use_edns=0, payload=100)
        direct = RES.handle(q)
        self.assertEqual(direct.request_payload, 512)
        r = dns.message.from_wire(process(RES, q.to_wire(), udp=True))
        self.assertTrue(r.flags & dns.flags.TC)

    def test_bad_version_gets_badvers(self):
        q = dns.message.make_query("1-1.en.quran.test.", "TXT",
                                   use_edns=1, payload=4096)
        r = RES.handle(q)
        self.assertEqual(r.rcode(), dns.rcode.BADVERS)
        self.assertEqual(r.edns, 0)

    def test_apex_soa_ns_txt(self):
        self.assertEqual(len(RES.handle(
            dns.message.make_query("quran.test.", "SOA")).answer), 1)
        self.assertEqual(len(RES.handle(
            dns.message.make_query("quran.test.", "NS")).answer), 1)
        self.assertEqual(len(RES.handle(
            dns.message.make_query("quran.test.", "TXT")).answer), 1)

    def test_nxdomain_and_nodata_carry_soa(self):
        for name, rdtype, rcode in (("9-9.en.quran.test.", "TXT", dns.rcode.NXDOMAIN),
                                    ("1-1.en.quran.test.", "A", dns.rcode.NOERROR),
                                    ("quran.test.", "A", dns.rcode.NOERROR)):
            r = RES.handle(dns.message.make_query(name, rdtype))
            self.assertEqual(r.rcode(), rcode)
            self.assertEqual(len(r.answer), 0)
            self.assertEqual(len(r.authority), 1)

    def test_long_answer_truncated_on_udp_full_on_tcp(self):
        udp = ask("2-282.en.quran.test.")
        self.assertTrue(udp.flags & dns.flags.TC)
        self.assertEqual(len(udp.answer), 0)
        tcp = ask("2-282.en.quran.test.", udp=False)
        self.assertFalse(tcp.flags & dns.flags.TC)
        self.assertEqual(join_txt(tcp.answer[0][0]), LONG)

    def test_garbage_packet_gets_formerr(self):
        out = process(RES, b"\x12\x34" + b"\xff" * 20, udp=True)
        self.assertEqual(out[:2], b"\x12\x34")
        self.assertEqual(dns.message.from_wire(out).rcode(), dns.rcode.FORMERR)

    def test_bad_opcode_is_notimp(self):
        q = dns.message.make_query("1-1.en.quran.test.", "TXT")
        q.set_opcode(15)
        self.assertEqual(RES.handle(q).rcode(), dns.rcode.NOTIMP)

    def test_non_in_class_refused(self):
        import dns.rdataclass
        q = dns.message.make_query("1-1.en.quran.test.", "TXT",
                                   rdclass=dns.rdataclass.CH)
        self.assertEqual(RES.handle(q).rcode(), dns.rcode.REFUSED)

    def test_chunk_limit_guarded(self):
        from qdns.txt import chunk_utf8
        with self.assertRaises(AssertionError):
            chunk_utf8("x", 300)

    def test_corrupt_store_rejected(self):
        import json, tempfile, os
        from qdns.store import VerseStore
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"nope": {}}, fh)
            path = fh.name
        try:
            with self.assertRaises(ValueError):
                VerseStore.from_file(path)
        finally:
            os.unlink(path)


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class LiveServerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.port = free_port()
        self.udp, self.tcp = await start_servers(RES, "127.0.0.1", self.port)

    async def asyncTearDown(self):
        self.udp.close()
        self.tcp.close()
        await self.tcp.wait_closed()

    async def test_client_fallback_to_tcp(self):
        resp, used_tcp = await asyncio.to_thread(
            fetch, "2-282.en.quran.test.", "127.0.0.1", self.port, 3.0)
        self.assertTrue(used_tcp)
        self.assertEqual(join_txt(resp.answer[0][0]), LONG)

    async def test_short_answer_stays_on_udp(self):
        resp, used_tcp = await asyncio.to_thread(
            fetch, "1-1.en.quran.test.", "127.0.0.1", self.port, 3.0)
        self.assertFalse(used_tcp)

    async def test_tcp_zero_length_closes(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(b"\x00\x00")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 5.0)
        self.assertEqual(data, b"")
        writer.close()


@unittest.skipUnless(Path(DEFAULT_DATA).exists(), "run scripts/fetch_data.py first")
class RealDataTest(unittest.TestCase):
    def test_every_verse_fits_in_tcp_and_roundtrips(self):
        store = VerseStore.from_file(DEFAULT_DATA)
        res = Resolver(store)
        self.assertEqual(len(store), 6236)
        for ref in ("1:1", "2:255", "2:282", "112:1", "114:6"):
            s, a = ref.split(":")
            for lang in ("ar", "en", "ur"):
                q = dns.message.make_query(f"{s}-{a}.{lang}.quran.test.", "TXT")
                r = dns.message.from_wire(process(res, q.to_wire(), udp=False))
                self.assertEqual(join_txt(r.answer[0][0]), store.get(int(s), int(a), lang))


if __name__ == "__main__":
    unittest.main()
