"""Step 4: the DNS logic. Message in -> Message out. No sockets here,
which makes it easy to unit-test and to reuse behind other transports
(e.g. DoH in phase 2).
"""
from __future__ import annotations

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from .config import (
    HELP_TEXT,
    NEG_TTL,
    NS_NAMES,
    SERVER_EDNS_MAX,
    SOA_EXPIRE,
    SOA_MNAME,
    SOA_REFRESH,
    SOA_RETRY,
    SOA_RNAME,
    SOA_SERIAL,
    TTL,
    ZONE,
)
from .names import ParsedQuery, QueryParseError, parse_qname
from .store import VerseStore
from .txt import make_txt_rrset

import dns.rrset

from .dnssec import DnssecSigner, wants_dnssec


class Resolver:
    def __init__(self, store: VerseStore, zone: str = ZONE, ttl: int = TTL,
                 dnssec: DnssecSigner | None = None,
                 verse_signer=None):
        self.store = store
        self.zone = dns.name.from_text(zone)
        self.ttl = ttl
        # Optional DNSSEC island signer. None (default) = zero behavior change.
        self.dnssec = dnssec
        self.verse_signer = verse_signer

    def _maybe_sign(self, query: dns.message.Message,
                    resp: dns.message.Message) -> None:
        if self.dnssec is not None:
            self.dnssec.attach(query, resp)
        if self.verse_signer is not None and wants_dnssec(query):
            for rrset in list(resp.answer):
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    continue
                sig = self.verse_signer.rrsig_for(rrset)
                if sig is not None:
                    resp.answer.append(sig)

    def _soa_rrset(self):
        return dns.rrset.from_text(
            self.zone.to_text(), NEG_TTL, "IN", "SOA",
            f"{SOA_MNAME} {SOA_RNAME} {SOA_SERIAL} "
            f"{SOA_REFRESH} {SOA_RETRY} {SOA_EXPIRE} {NEG_TTL}",
        )

    def _ns_rrsets(self):
        out = []
        for ns in NS_NAMES:
            out.append(dns.rrset.from_text(
                self.zone.to_text(), TTL, "IN", "NS", ns,
            ))
        return out

    def handle(self, query: dns.message.Message) -> dns.message.Message:
        resp = dns.message.make_response(query, our_payload=SERVER_EDNS_MAX)
        if query.edns is not None and query.edns > 0:
            resp.set_rcode(dns.rcode.BADVERS)
            return resp
        if resp.edns is not None and resp.edns >= 0:
            if resp.request_payload is not None and resp.request_payload < 512:
                resp.request_payload = 512

        if query.opcode() != dns.opcode.QUERY:
            resp.set_rcode(dns.rcode.NOTIMP)
            return resp
        if len(query.question) != 1:
            resp.set_rcode(dns.rcode.FORMERR)
            return resp

        q = query.question[0]
        if q.rdclass != dns.rdataclass.IN or not q.name.is_subdomain(self.zone):
            resp.set_rcode(dns.rcode.REFUSED)       # not our zone
            return resp

        resp.flags |= dns.flags.AA                  # we are authoritative here

        # Apex direct answers.
        if q.name == self.zone:
            if q.rdtype == dns.rdatatype.SOA:
                resp.answer.append(self._soa_rrset())
                self._maybe_sign(query, resp)
                return resp
            if q.rdtype == dns.rdatatype.NS:
                resp.answer.extend(self._ns_rrsets())
                self._maybe_sign(query, resp)
                return resp
            if q.rdtype == dns.rdatatype.DNSKEY and self.dnssec is not None:
                resp.answer.append(self.dnssec.dnskey_rrset())
                self._maybe_sign(query, resp)
                return resp
            if q.rdtype in (dns.rdatatype.TXT, dns.rdatatype.ANY):
                resp.answer.append(make_txt_rrset(q.name, self.ttl, HELP_TEXT))
                return resp
            # NODATA at apex.
            resp.authority.append(self._soa_rrset())
            self._maybe_sign(query, resp)
            return resp

        try:
            parsed = parse_qname(q.name, self.zone)
        except QueryParseError:
            resp.set_rcode(dns.rcode.NXDOMAIN)
            resp.authority.append(self._soa_rrset())
            self._maybe_sign(query, resp)
            return resp

        text = self._lookup(parsed)
        if text is None:
            resp.set_rcode(dns.rcode.NXDOMAIN)      # e.g. verse 2:999
            resp.authority.append(self._soa_rrset())
            self._maybe_sign(query, resp)
            return resp

        # Name exists. TXT (or ANY) has data; NSEC names the successor;
        # other types -> NODATA.
        if q.rdtype in (dns.rdatatype.TXT, dns.rdatatype.ANY):
            resp.answer.append(make_txt_rrset(q.name, self.ttl, text))
            self._maybe_sign(query, resp)
        elif q.rdtype == dns.rdatatype.NSEC and self.verse_signer is not None:
            nsec = self.verse_signer.nsec_for(q.name, self.ttl)
            if nsec is None:
                resp.authority.append(self._soa_rrset())
                self._maybe_sign(query, resp)
            else:
                resp.answer.append(nsec)
                self._maybe_sign(query, resp)
        else:
            resp.authority.append(self._soa_rrset())
            self._maybe_sign(query, resp)
        return resp

    def _lookup(self, p: ParsedQuery) -> str | None:
        if p.kind == "help":
            return HELP_TEXT
        return self.store.get(p.surah, p.ayah, p.lang)
