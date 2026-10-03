"""DNSSEC island tests (spec section B).

Covers: DNSKEY answer at apex, RRSIG present iff DO bit set,
``dns.dnssec.validate`` passes on the apex SOA, verse TXT unsigned.
"""
import time
import unittest

import dns.dnssec
import dns.flags
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qdns.config import ZONE
from qdns.dnssec import DnssecSigner, load_signer
from qdns.resolver import Resolver
from qdns.store import VerseStore

STORE = VerseStore({"1:1": {"ar": "بسم الله", "en": "In the name of Allah"}})
NOW = int(time.time())


def make_signer(**kwargs) -> DnssecSigner:
    kwargs.setdefault("inception", NOW)
    return DnssecSigner(Ed25519PrivateKey.generate(),
                        Ed25519PrivateKey.generate(), **kwargs)


def ask(resolver, name, rdtype="SOA", do=False):
    q = dns.message.make_query(name, rdtype, use_edns=0, payload=4096)
    if do:
        q.ednsflags |= dns.flags.DO
    return resolver.handle(q)


def rrsets(resp, section="answer"):
    return getattr(resp, section)


def types(resp, section="answer"):
    return [r.rdtype for r in rrsets(resp, section)]


class DnssecTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = make_signer()
        cls.res = Resolver(STORE, dnssec=cls.signer)
        cls.zone = dns.name.from_text(ZONE) if isinstance(ZONE, str) else ZONE

    def test_dnskey_answer(self):
        r = ask(self.res, ZONE, "DNSKEY", do=True)
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        dk = [x for x in r.answer if x.rdtype == dns.rdatatype.DNSKEY]
        self.assertEqual(len(dk), 1)
        flags = sorted(rd.flags for rd in dk[0])
        self.assertEqual(flags, [256, 257])
        for rd in dk[0]:
            self.assertEqual(rd.algorithm, 15)      # Ed25519
            self.assertEqual(rd.protocol, 3)

    def test_rrsig_present_iff_do(self):
        for rdtype in ("SOA", "NS", "DNSKEY"):
            with self.subTest(rdtype=rdtype):
                with_do = ask(self.res, ZONE, rdtype, do=True)
                self.assertIn(dns.rdatatype.RRSIG, types(with_do),
                              f"{rdtype} with DO must carry RRSIG")
                covered = {s.type_covered for s in
                           [x for x in with_do.answer
                            if x.rdtype == dns.rdatatype.RRSIG][0]}
                self.assertIn(getattr(dns.rdatatype, rdtype), covered)
                without_do = ask(self.res, ZONE, rdtype, do=False)
                self.assertNotIn(dns.rdatatype.RRSIG, types(without_do),
                                 f"{rdtype} without DO must not carry RRSIG")
                # Same for the no-EDNS-at-all query (DO bit absent).
                plain = self.res.handle(dns.message.make_query(ZONE, rdtype))
                self.assertNotIn(dns.rdatatype.RRSIG, types(plain))

    def test_validate_apex_soa(self):
        r = ask(self.res, ZONE, "SOA", do=True)
        soa = [x for x in r.answer if x.rdtype == dns.rdatatype.SOA][0]
        sigs = [x for x in r.answer if x.rdtype == dns.rdatatype.RRSIG]
        soa_sigs = [x for x in sigs if x[0].type_covered == dns.rdatatype.SOA]
        self.assertEqual(len(soa_sigs), 1)
        # Must not raise.
        dns.dnssec.validate(soa, soa_sigs[0], self.signer.keyring())

    def test_validate_apex_ns_and_dnskey(self):
        for rdtype in ("NS", "DNSKEY"):
            with self.subTest(rdtype=rdtype):
                r = ask(self.res, ZONE, rdtype, do=True)
                rr = [x for x in r.answer
                      if x.rdtype == getattr(dns.rdatatype, rdtype)][0]
                sigs = [x for x in r.answer
                        if x.rdtype == dns.rdatatype.RRSIG
                        and x[0].type_covered == rr.rdtype][0]
                dns.dnssec.validate(rr, sigs, self.signer.keyring())

    def test_verse_txt_unsigned_even_with_do(self):
        r = ask(self.res, "1-1.en.quran.test.", "TXT", do=True)
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len([x for x in r.answer
                              if x.rdtype == dns.rdatatype.TXT]), 1)
        for section in ("answer", "authority", "additional"):
            self.assertNotIn(dns.rdatatype.RRSIG, types(r, section),
                             f"verse TXT must stay unsigned ({section})")

    def test_no_signer_zero_behavior_change(self):
        plain = Resolver(STORE)
        # DNSKEY at apex without a signer -> NODATA + SOA (old behavior).
        r = plain.handle(dns.message.make_query(ZONE, "DNSKEY"))
        self.assertEqual(len(r.answer), 0)
        self.assertEqual(len(r.authority), 1)
        # DO bit without a signer -> no RRSIG anywhere.
        q = dns.message.make_query(ZONE, "SOA", use_edns=0, payload=4096)
        q.ednsflags |= dns.flags.DO
        r = plain.handle(q)
        for section in ("answer", "authority", "additional"):
            self.assertNotIn(dns.rdatatype.RRSIG, types(r, section))

    def test_pem_roundtrip_from_disk(self):
        import tempfile
        from qdns.dnssec import dump_private_key, load_private_key
        with tempfile.TemporaryDirectory() as td:
            from pathlib import Path
            ksk = Ed25519PrivateKey.generate()
            zsk = Ed25519PrivateKey.generate()
            (Path(td) / "ksk.pem").write_bytes(dump_private_key(ksk))
            (Path(td) / "zsk.pem").write_bytes(dump_private_key(zsk))
            self.assertIsInstance(load_private_key(Path(td) / "ksk.pem"),
                                  Ed25519PrivateKey)
            signer = load_signer(td, inception=NOW)
            res = Resolver(STORE, dnssec=signer)
            r = ask(res, ZONE, "SOA", do=True)
            soa = [x for x in r.answer if x.rdtype == dns.rdatatype.SOA][0]
            sigs = [x for x in r.answer if x.rdtype == dns.rdatatype.RRSIG][0]
            dns.dnssec.validate(soa, sigs, signer.keyring())

    def test_fixed_clock_boundaries(self):
        # RRSIG inception/expiration honor the injected clock.
        signer = make_signer(inception=NOW)
        sig = signer._sigs[dns.rdatatype.SOA][0]
        self.assertEqual(int(sig.inception), NOW)
        self.assertEqual(int(sig.expiration), NOW + 14 * 86400)


if __name__ == "__main__":
    unittest.main()
