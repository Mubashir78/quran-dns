"""DNSSEC island of security (apex-only, Ed25519).

Covers the static apex sets (SOA, NS, DNSKEY) with pre-signed RRSIGs.
Verse TXT answers stay unsigned: documented limitation, not a bug.

Local demo only. Production MUST keep the KSK offline (sign the DNSKEY
set in a separate ceremony and publish only the resulting RRSIG); here
both keys live under ``keys/`` for simplicity.

Clock is injectable (``inception``) so tests can use a fixed time.
"""
from __future__ import annotations

import time
from pathlib import Path

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .config import (
    DNSSEC_ALGORITHM,
    DNSSEC_DNSKEY_TTL,
    DNSSEC_LIFETIME,
    KEY_DIR,
    NEG_TTL,
    NS_NAMES,
    SOA_EXPIRE,
    SOA_MNAME,
    SOA_REFRESH,
    SOA_RETRY,
    SOA_RNAME,
    SOA_SERIAL,
    TTL,
    ZONE,
)

IN = dns.rdataclass.IN

KSK_FLAGS = 257          # Zone Key + Secure Entry Point
ZSK_FLAGS = 256          # Zone Key

# (owner suffix, rdtype) pairs covered by pre-signed RRSIGs. All apex-only.
SIGNED_TYPES = frozenset({
    dns.rdatatype.SOA, dns.rdatatype.NS, dns.rdatatype.DNSKEY,
})


def wants_dnssec(query: dns.message.Message) -> bool:
    """True when the query sets the DO bit (RFC 4035 s3)."""
    return bool(query.ednsflags & dns.flags.DO)


def load_private_key(path: str | Path):
    """Load an Ed25519 private key from a PEM file."""
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path}: not an Ed25519 private key")
    return key


def dump_private_key(key: Ed25519PrivateKey) -> bytes:
    """Serialize a private key to PKCS8 PEM bytes (no encryption)."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def make_dnskey_rdata(private_key: Ed25519PrivateKey, flags: int):
    """Build the DNSKEY rdata matching a private key."""
    return dns.dnssec.make_dnskey(
        private_key.public_key(), algorithm=DNSSEC_ALGORITHM,
        flags=flags, protocol=3,
    )


class DnssecSigner:
    """Pre-signed apex RRSIGs; attach them only when the query has DO set."""

    def __init__(
        self,
        ksk_private: Ed25519PrivateKey,
        zsk_private: Ed25519PrivateKey,
        zone: str = ZONE,
        ttl: int = TTL,
        neg_ttl: int = NEG_TTL,
        inception: float | None = None,
        lifetime: int = DNSSEC_LIFETIME,
    ):
        self.zone = dns.name.from_text(zone)
        self.ttl = ttl
        self.neg_ttl = neg_ttl
        self.inception = int(inception) if inception is not None else int(time.time())
        self.expiration = self.inception + lifetime
        self.ksk_private = ksk_private
        self.zsk_private = zsk_private
        self.ksk_dnskey = make_dnskey_rdata(ksk_private, KSK_FLAGS)
        self.zsk_dnskey = make_dnskey_rdata(zsk_private, ZSK_FLAGS)
        self._sigs: dict[int, dns.rrset.RRset] = {}
        self._presign_all()

    # -- canonical apex rrsets (same values as Resolver) -------------------

    def soa_rrset(self) -> dns.rrset.RRset:
        return dns.rrset.from_text(
            self.zone.to_text(), self.neg_ttl, "IN", "SOA",
            f"{SOA_MNAME} {SOA_RNAME} {SOA_SERIAL} "
            f"{SOA_REFRESH} {SOA_RETRY} {SOA_EXPIRE} {self.neg_ttl}",
        )

    def ns_rrset(self) -> dns.rrset.RRset:
        rrset = dns.rrset.RRset(self.zone, IN, dns.rdatatype.NS)
        for ns in NS_NAMES:
            rrset.add(dns.rdata.from_text(IN, dns.rdatatype.NS, ns), self.ttl)
        return rrset

    def dnskey_rrset(self) -> dns.rrset.RRset:
        rrset = dns.rrset.RRset(self.zone, IN, dns.rdatatype.DNSKEY)
        rrset.add(self.ksk_dnskey, DNSSEC_DNSKEY_TTL)
        rrset.add(self.zsk_dnskey, DNSSEC_DNSKEY_TTL)
        return rrset

    # -- signing ------------------------------------------------------------

    def _sign_with(self, rrset, private_key, dnskey_rdata) -> dns.rrset.RRset:
        sig = dns.dnssec.sign(
            rrset, private_key, self.zone, dnskey_rdata,
            inception=self.inception, expiration=self.expiration,
        )
        sigset = dns.rrset.RRset(rrset.name, IN, dns.rdatatype.RRSIG)
        sigset.add(sig, rrset.ttl)
        return sigset

    def _presign_all(self) -> None:
        """Sign the static apex sets once at startup (14-day validity)."""
        dnskey = self.dnskey_rrset()
        self._sigs[dns.rdatatype.DNSKEY] = self._sign_with(
            dnskey, self.ksk_private, self.ksk_dnskey)   # KSK signs DNSKEY
        self._sigs[dns.rdatatype.SOA] = self._sign_with(
            self.soa_rrset(), self.zsk_private, self.zsk_dnskey)
        self._sigs[dns.rdatatype.NS] = self._sign_with(
            self.ns_rrset(), self.zsk_private, self.zsk_dnskey)

    def rrsig_for(self, rrset: dns.rrset.RRset) -> dns.rrset.RRset | None:
        """Pre-signed RRSIG rrset covering *rrset*, or None if unsigned."""
        if rrset.name != self.zone or rrset.rdtype not in SIGNED_TYPES:
            return None
        return self._sigs.get(rrset.rdtype)

    def keyring(self) -> dict:
        """Trust anchor dict for ``dns.dnssec.validate``: {zone: DNSKEY rrset}."""
        return {self.zone: self.dnskey_rrset()}

    def attach(self, query: dns.message.Message,
               resp: dns.message.Message) -> None:
        """Append pre-signed RRSIGs in-section, only when DO bit is set."""
        if not wants_dnssec(query):
            return
        for section in ("answer", "authority"):
            for rrset in list(getattr(resp, section)):
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    continue
                sig = self.rrsig_for(rrset)
                if sig is not None:
                    getattr(resp, section).append(sig)


def load_signer(key_dir: str | Path = KEY_DIR, **kwargs) -> DnssecSigner:
    """Build a signer from PEM files on disk (``keys/ksk.pem`` + ``zsk.pem``)."""
    key_dir = Path(key_dir)
    ksk = load_private_key(key_dir / "ksk.pem")
    zsk = load_private_key(key_dir / "zsk.pem")
    return DnssecSigner(ksk, zsk, **kwargs)


# -- per-verse signing + NSEC khatmah chain ----------------------------------

NSEC_BITMAP = "TXT RRSIG NSEC"
LANG_ORDER = ("ar", "en", "ur")


def verse_chain(store, zone: str = ZONE) -> list[dns.name.Name]:
    """All verse names in reading order: surah, ayah, then lang.

    Last name wraps to first, so the chain is one khatmah loop.
    """
    keys: list[tuple[int, int]] = []
    for ref in store._verses:
        s, a = ref.split(":")
        keys.append((int(s), int(a)))
    keys.sort()
    out = []
    for s, a in keys:
        for lang in LANG_ORDER:
            if store.get(s, a, lang) is not None:
                out.append(dns.name.from_text(f"{s}-{a}.{lang}.{zone}"))
    return out


class VerseSigner:
    """Signs dynamic verse TXT and NSEC rrsets with the ZSK, cached.

    Texts are static, so one signature per owner name is computed once.
    Only used when the query sets DO; otherwise answers stay plain.
    """

    def __init__(self, zsk_private: Ed25519PrivateKey,
                 dnskey_rdata=None, zone: str = ZONE,
                 inception: float | None = None,
                 lifetime: int = DNSSEC_LIFETIME):
        self.zone = dns.name.from_text(zone)
        self.zsk_private = zsk_private
        self.dnskey_rdata = dnskey_rdata
        self.inception = int(inception) if inception is not None else int(time.time())
        self.expiration = self.inception + lifetime
        self._cache: dict[tuple[str, int], dns.rrset.RRset] = {}
        self._next: dict[str, dns.name.Name] = {}

    def set_chain(self, names: list[dns.name.Name]) -> None:
        """Install the khatmah successor map (wraps last to first)."""
        self._next = {n.to_text(): names[(i + 1) % len(names)]
                      for i, n in enumerate(names)}

    def _sign(self, rrset: dns.rrset.RRset) -> dns.rrset.RRset:
        key = (rrset.name.to_text(), rrset.rdtype)
        sig = self._cache.get(key)
        if sig is None:
            r = dns.dnssec.sign(
                rrset, self.zsk_private, self.zone, self.dnskey_rdata,
                inception=self.inception, expiration=self.expiration,
            )
            sig = dns.rrset.RRset(rrset.name, IN, dns.rdatatype.RRSIG)
            sig.add(r, rrset.ttl)
            self._cache[key] = sig
        return sig

    def rrsig_for(self, rrset: dns.rrset.RRset) -> dns.rrset.RRset | None:
        if rrset.name == self.zone or self.dnskey_rdata is None:
            return None
        if rrset.rdtype not in (dns.rdatatype.TXT, dns.rdatatype.NSEC):
            return None
        return self._sign(rrset)

    def nsec_for(self, name: dns.name.Name, ttl: int) -> dns.rrset.RRset | None:
        """NSEC at a verse name pointing at its khatmah successor."""
        nxt = self._next.get(name.to_text())
        if nxt is None:
            return None
        return dns.rrset.from_text(
            name.to_text(), ttl, "IN", "NSEC", f"{nxt.to_text()} {NSEC_BITMAP}",
        )
