"""Step 3: pack text into TXT records.

A TXT record holds one or more "character-strings", each at most 255 BYTES.
Arabic letters take 2 bytes in UTF-8, so we must split on character
boundaries - cutting a multi-byte character in half would corrupt the text.
"""
from __future__ import annotations

import functools

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.rrset

from .config import TXT_CHUNK

IN = dns.rdataclass.IN
TXT = dns.rdatatype.TXT


@functools.lru_cache(maxsize=None)
def chunk_utf8(text: str, limit: int = TXT_CHUNK) -> list[bytes]:
    """Split on char boundaries. Pure function: cached, so repeat queries
    for the same verse skip re-chunking (identical bytes out)."""
    assert 1 <= limit <= 255, "TXT chunk limit must be 1..255"
    raw = text.encode("utf-8")
    chunks: list[bytes] = []
    start = 0
    while start < len(raw):
        end = min(start + limit, len(raw))
        # Back off to a char boundary: a cut is bad iff the byte after it
        # is a UTF-8 continuation byte (char started before the cut).
        while end > start and end < len(raw) and raw[end] & 0xC0 == 0x80:
            end -= 1
        if end == start:  # limit smaller than one char; can't happen (limit>=1)
            end = start + 1
        chunks.append(raw[start:end])
        start = end
    if not chunks:
        chunks.append(b"")
    return chunks


def make_txt_rrset(name: dns.name.Name, ttl: int, text: str) -> dns.rrset.RRset:
    rdata = dns.rdtypes.ANY.TXT.TXT(IN, TXT, chunk_utf8(text))
    rrset = dns.rrset.RRset(name, IN, TXT)
    rrset.add(rdata, ttl)
    return rrset


def join_txt(rdata) -> str:
    """Client side: glue the character-strings back together."""
    return b"".join(rdata.strings).decode("utf-8")
