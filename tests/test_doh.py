import base64
import threading
import unittest
import urllib.error
import urllib.request

import dns.flags
import dns.message
import dns.rcode

from qdns.config import TTL
from qdns.doh import make_server
from qdns.resolver import Resolver
from qdns.store import VerseStore
from qdns.txt import join_txt

LONG = "الحمد لله رب العالمين " * 120  # ~2.5KB, far above UDP limits
STORE = VerseStore({"1:1": {"ar": "بسم الله", "en": "In the name of Allah"},
                    "2:282": {"en": LONG}})
RES = Resolver(STORE)


def _query_wire(name, rdtype="TXT"):
    return dns.message.make_query(name, rdtype).to_wire()


def _b64_nopad(wire: bytes) -> str:
    return base64.urlsafe_b64encode(wire).decode().rstrip("=")


class DohTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(RES, "127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      kwargs={"poll_interval": 0.05},
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5.0)

    def _post(self, wire, content_type="application/dns-message", path="/dns-query"):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url, data=wire, method="POST",
                                     headers={"Content-Type": content_type,
                                              "Accept": "application/dns-message"})
        return urllib.request.urlopen(req, timeout=5)

    def _get(self, wire, path="/dns-query"):
        url = f"http://127.0.0.1:{self.port}{path}?dns={_b64_nopad(wire)}"
        req = urllib.request.Request(url, method="GET",
                                     headers={"Accept": "application/dns-message"})
        return urllib.request.urlopen(req, timeout=5)

    def test_post_roundtrip_verse(self):
        wire = _query_wire("1-1.en.quran.test.")
        with self._post(wire) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.getheader("Content-Type"), "application/dns-message")
            self.assertEqual(resp.getheader("Cache-Control"), f"max-age={TTL}")
            body = resp.read()
        msg = dns.message.from_wire(body)
        self.assertEqual(msg.rcode(), dns.rcode.NOERROR)
        self.assertEqual(join_txt(msg.answer[0][0]), "In the name of Allah")

    def test_get_roundtrip_verse(self):
        wire = _query_wire("1-1.en.quran.test.")
        with self._get(wire) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.getheader("Content-Type"), "application/dns-message")
            self.assertEqual(resp.getheader("Cache-Control"), f"max-age={TTL}")
            body = resp.read()
        msg = dns.message.from_wire(body)
        self.assertEqual(msg.rcode(), dns.rcode.NOERROR)
        self.assertEqual(join_txt(msg.answer[0][0]), "In the name of Allah")

    def test_long_answer_has_no_tc_over_doh(self):
        wire = _query_wire("2-282.en.quran.test.")
        for client in (self._post, self._get):
            with client(wire) as resp:
                self.assertEqual(resp.status, 200)
                body = resp.read()
            msg = dns.message.from_wire(body)
            self.assertFalse(msg.flags & dns.flags.TC)
            self.assertEqual(msg.rcode(), dns.rcode.NOERROR)
            self.assertGreater(len(msg.answer), 0)
            self.assertEqual(join_txt(msg.answer[0][0]), LONG)

    def test_font_naskh_serves_ttf(self):
        url = f"http://127.0.0.1:{self.port}/font/naskh"
        with urllib.request.urlopen(url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.getheader("Content-Type"), "font/ttf")
            body = resp.read()
        self.assertTrue(body[:4] == b"\x00\x01\x00\x00", body[:4])

    def test_font_nastaliq_serves_ttf(self):
        url = f"http://127.0.0.1:{self.port}/font/nastaliq"
        with urllib.request.urlopen(url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read()
        self.assertTrue(body[:4] == b"\x00\x01\x00\x00", body[:4])

    def test_404_on_bad_path(self):
        wire = _query_wire("1-1.en.quran.test.")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post(wire, path="/bad-path")
        self.assertEqual(cm.exception.code, 404)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get(wire, path="/bad-path")
        self.assertEqual(cm.exception.code, 404)

    def test_415_on_bad_content_type(self):
        wire = _query_wire("1-1.en.quran.test.")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post(wire, content_type="text/plain")
        self.assertEqual(cm.exception.code, 415)

    def test_400_on_bad_dns_bytes(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post(b"not-a-dns-message")
        self.assertEqual(cm.exception.code, 400)
        url = f"http://127.0.0.1:{self.port}/dns-query"
        req = urllib.request.Request(url, method="GET")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(cm.exception.code, 400)


    def test_search_finds_verse(self):
        import json
        url = f"http://127.0.0.1:{self.port}/search?q=Allah&lang=en"
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.loads(r.read().decode())
        refs = [h["ref"] for h in data["hits"]]
        self.assertIn("1:1", refs)

    def test_search_rejects_short_query(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(f"http://127.0.0.1:{self.port}/search?q=ab&lang=en",
                                   timeout=5)
        self.assertEqual(cm.exception.code, 400)

    def test_root_serves_reader_page(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=5) as r:
            self.assertEqual(r.status, 200)
            self.assertIn("text/html", r.headers.get("Content-Type"))
            body = r.read().decode("utf-8")
        self.assertIn("dns-query?dns=", body)
        self.assertIn('id="arabic"', body)
        # Memorize mode must hide the reference prompt too, not just answers.
        self.assertIn("#ref.masked", body)
        self.assertIn("#results strong", body)
        # Keybinds for unblurring must be present and documented.
        self.assertIn("toggleTranslations", body)
        self.assertIn("aria-keyshortcuts", body)
        self.assertIn("Memorize mode", body)
        # Navigation/action keybinds must be wired with documented hints.
        self.assertIn('aria-keyshortcuts="n"', body)
        self.assertIn('getElementById("q").focus()', body)
        self.assertIn('id="keys"', body)
        # Night theme is the default; day stays one tap away, remembered.
        self.assertIn('data-theme="dark"', body)
        self.assertIn('id="theme"', body)
        self.assertIn("qr-theme", body)
        self.assertIn("--card", body)
        # Shadda+Kasra-safe default face (kasra stays below baseline).
        self.assertIn("/font/scheherazade", body)


if __name__ == "__main__":
    unittest.main()
