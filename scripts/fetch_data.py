#!/usr/bin/env python3
"""Build data/quran.json (Arabic, English, Urdu) from the open
fawazahmed0/quran-api dataset on GitHub. Standard library only.

    python scripts/fetch_data.py

Swap editions by editing EDITIONS (list: github.com/fawazahmed0/quran-api,
editions.json). Check each translation's licence before redistributing.
"""
import json
import re
import unicodedata
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/fawazahmed0/quran-api/1/editions/{}.json"
EDITIONS = {
    "ar": ("ara-quranuthmanihaf", "Uthmani script, Hafs"),
    "en": ("eng-mustafakhattaba", "Mustafa Khattab, The Clear Quran"),
    "ur": ("urd-abulaalamaududi", "Abul A'la Maududi"),
}
OUT = Path(__file__).resolve().parent.parent / "data" / "quran.json"

# The source writes the accusative alif detached ("مَرَضࣰ ا" for "مَرَضًا").
# A lone alif is never a word, so rejoin it with its tanwin word. Only
# fathatan takes this alif; other tanwin+space pairs are genuine
# boundaries and stay untouched.
_DETACHED_ALIF = re.compile(
    r"([\u064b\u08f0]) ([\u0627\u0649]"
    r"[\u064e-\u0652\u0670\u06d6-\u06ed\u08e4-\u08fe]*"
    r")(?=[\s\u06d6-\u06ed.,;:!?\u061b\u061f(){}\[\]\"'\u201c\u201d]|$)"
)


# Upstream writes open tanwins (U+08F0-08F2, easily misread) and sukun as
# U+06E1 (renders as a fatha-like tick in most fonts); quran.com uses the
# closed forms + plain U+0652, so normalize to those.
_OPEN_TANWIN = str.maketrans({0x08F0: 0x064B, 0x08F1: 0x064C, 0x08F2: 0x064D,
                              0x06E1: 0x0652})


def normalize_text(text: str) -> str:
    # NFC last: the 06E1->0652 mapping changes combining class
    # (230 -> 34), so the whole mark run must be reordered after it.
    return unicodedata.normalize(
        "NFC", _DETACHED_ALIF.sub(r"\1\2", text).translate(_OPEN_TANWIN))


def download(edition: str) -> list[dict]:
    with urllib.request.urlopen(BASE.format(edition), timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))["quran"]


def main():
    verses: dict[str, dict[str, str]] = {}
    for lang, (edition, _) in EDITIONS.items():
        print(f"downloading {lang}: {edition} ...")
        for v in download(edition):
            verses.setdefault(f"{v['chapter']}:{v['verse']}", {})[lang] = \
                normalize_text(v["text"].strip())

    counts = {len(set(d)) for d in verses.values()}
    assert counts == {len(EDITIONS)}, "some verses are missing a language"
    meta = {
        "source": "https://github.com/fawazahmed0/quran-api",
        "editions": {l: {"edition": e, "note": n} for l, (e, n) in EDITIONS.items()},
    }
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps({"meta": meta, "verses": verses}, ensure_ascii=False),
                   encoding="utf-8")
    print(f"wrote {OUT} ({len(verses)} verses)")


if __name__ == "__main__":
    main()
