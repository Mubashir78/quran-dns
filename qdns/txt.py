"""Step 3: pack text into TXT records.

A TXT record holds one or more "character-strings", each at most 255 BYTES.
Arabic letters take 2 bytes in UTF-8, so we must split on character
boundaries - cutting a multi-byte character in half would corrupt the text.
"""
from __future__ import annotations

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.rrset

from .config import TXT_CHUNK

IN = dns.rdataclass.IN
TXT = dns.rdatatype.TXT


def chunk_utf8(text: str, limit: int = TXT_CHUNK) -> list[bytes]:
    assert 1 <= limit <= 255, "TXT chunk limit must be 1..255"
    chunks: list[bytes] = []
    buf = bytearray()
    for ch in text:
        b = ch.encode("utf-8")
        if len(buf) + len(b) > limit:
            chunks.append(bytes(buf))
            buf = bytearray()
        buf += b
    if buf or not chunks:
        chunks.append(bytes(buf))
    return chunks


def make_txt_rrset(name: dns.name.Name, ttl: int, text: str) -> dns.rrset.RRset:
    rdata = dns.rdtypes.ANY.TXT.TXT(IN, TXT, chunk_utf8(text))
    rrset = dns.rrset.RRset(name, IN, TXT)
    rrset.add(rdata, ttl)
    return rrset


def join_txt(rdata) -> str:
    """Client side: glue the character-strings back together."""
    return b"".join(rdata.strings).decode("utf-8")
