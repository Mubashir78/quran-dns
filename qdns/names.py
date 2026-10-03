"""Step 1 of the pipeline: turn a DNS name into a structured request.

    2-255.en.quran.test.   -> verse 2:255, English
    2-255.quran.test.      -> verse 2:255, default language (Arabic)
    help.quran.test.       -> usage text   (the zone apex does the same)
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import dns.name

from .config import DEFAULT_LANG, LANGS


class QueryParseError(ValueError):
    """The name is not one of our supported forms."""


@dataclass(frozen=True)
class ParsedQuery:
    kind: str                  # "verse" | "help"
    surah: int = 0
    ayah: int = 0
    lang: str = DEFAULT_LANG


_REF = re.compile(r"^(\d{1,3})-(\d{1,3})$")


def parse_qname(qname: dns.name.Name, zone: dns.name.Name) -> ParsedQuery:
    if not qname.is_subdomain(zone):
        raise QueryParseError("outside our zone")

    rel = qname.relativize(zone)               # "2-255.en" (labels only)
    try:
        labels = [lbl.decode("ascii").lower() for lbl in rel.labels]
    except UnicodeDecodeError as exc:
        raise QueryParseError("non-ASCII label") from exc

    if not labels or labels == ["help"]:
        return ParsedQuery("help")
    if len(labels) > 2:
        raise QueryParseError("too many labels")

    m = _REF.match(labels[0])
    if not m:
        raise QueryParseError("expected <surah>-<ayah>")
    surah, ayah = int(m.group(1)), int(m.group(2))
    if not 1 <= surah <= 114 or ayah < 1:
        raise QueryParseError("surah/ayah out of range")

    lang = DEFAULT_LANG
    if len(labels) == 2:
        lang = labels[1]
        if lang not in LANGS:
            raise QueryParseError(f"unknown language {lang!r}")
    return ParsedQuery("verse", surah, ayah, lang)
