"""Per-verse signing + NSEC khatmah chain + /verify endpoint."""
import json
import time
import unittest
import urllib.request

import dns.dnssec
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qdns.config import ZONE
from qdns.dnssec import DnssecSigner, VerseSigner, verse_chain
from qdns.doh import make_server
from qdns.resolver import Resolver
from qdns.store import VerseStore

STORE = VerseStore({
    "1:1": {"ar": "بسم الله", "en": "In the name of Allah", "ur": "اللہ کے نام سے"},
    "1:2": {"ar": "الحمد لله", "en": "All praise", "ur": "تمام تعریف"},
})
NOW = int(time.time())


def make_resolver():
    ksk = Ed25519PrivateKey.generate()
    zsk = Ed25519PrivateKey.generate()
    signer = DnssecSigner(ksk, zsk, inception=NOW)
    vsigner = VerseSigner(zsk, signer.zsk_dnskey, inception=NOW)
    res = Resolver(STORE, dnssec=signer, verse_signer=vsigner)
    vsigner.set_chain(verse_chain(STORE))
    return res, signer


def ask(res, name, rdtype="TXT", do=False):
    q = dns.message.make_query(name, rdtype,
                               use_edns=0 if do else None, payload=1232)
    if do:
        q.ednsflags |= dns.flags.DO
    return res.handle(q), q


class VerseSigTest(unittest.TestCase):
    def test_no_rrsig_without_do(self):
        res, _ = make_resolver()
        r, _ = ask(res, "1-1.en.quran.test.")
        self.assertFalse([x for x in r.answer if x.rdtype == dns.rdatatype.RRSIG])

    def test_verse_rrsig_validates_with_do(self):
        res, signer = make_resolver()
        r, _ = ask(res, "1-1.en.quran.test.", do=True)
        txt = [x for x in r.answer if x.rdtype == dns.rdatatype.TXT]
        sig = [x for x in r.answer if x.rdtype == dns.rdatatype.RRSIG]
        self.assertEqual((len(txt), len(sig)), (1, 1))
        dns.dnssec.validate(txt[0], sig[0], signer.keyring())  # raises if bad

    def test_nsec_chain_order_and_wrap(self):
        res, _ = make_resolver()
        r, _ = ask(res, "1-1.en.quran.test.", "NSEC")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(r.answer), 1)
        nxt = r.answer[0][0].next.to_text()
        self.assertEqual(nxt, f"1-1.ur.{ZONE}")
        # last name wraps to first
        names = [n.to_text() for n in verse_chain(STORE)]
        r, _ = ask(res, names[-1], "NSEC")
        self.assertEqual(r.answer[0][0].next.to_text(), names[0])

    def test_nsec_rrsig_validates_with_do(self):
        res, signer = make_resolver()
        r, _ = ask(res, "1-1.en.quran.test.", "NSEC", do=True)
        nsec = [x for x in r.answer if x.rdtype == dns.rdatatype.NSEC]
        sig = [x for x in r.answer if x.rdtype == dns.rdatatype.RRSIG]
        self.assertEqual((len(nsec), len(sig)), (1, 1))
        dns.dnssec.validate(nsec[0], sig[0], signer.keyring())

    def test_nsec_unknown_name_is_nodata(self):
        res, _ = make_resolver()
        r, _ = ask(res, "9-9.en.quran.test.", "NSEC")
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)


class VerifyEndpointTest(unittest.TestCase):
    def test_verify_json(self):
        res, _ = make_resolver()
        httpd = make_server(res, "127.0.0.1", 0)
        port = httpd.server_address[1]
        import threading
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/verify?ref=1:1&lang=en",
                    timeout=5) as r:
                data = json.loads(r.read().decode())
            self.assertEqual(data, {"ref": "1:1", "lang": "en", "valid": True})
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/verify?ref=9:9&lang=en",
                    timeout=5) as r:
                data = json.loads(r.read().decode())
            self.assertFalse(data["valid"])
        finally:
            httpd.shutdown()


if __name__ == "__main__":
    unittest.main()
