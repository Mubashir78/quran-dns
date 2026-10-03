"""Step 2: look the verse up. Tiny in-memory store loaded from data/quran.json."""
from __future__ import annotations

import json
from pathlib import Path


class VerseStore:
    def __init__(self, verses: dict[str, dict[str, str]], meta: dict | None = None):
        self._verses = verses
        self.meta = meta or {}
        self._fold_index: dict[str, list[tuple[str, str]]] = {}

    def _folded(self, lang: str) -> list[tuple[str, str]]:
        """(ref, casefolded text) in reading order, built once per lang:
        search() is substring scans, folding dominated its cost."""
        try:
            return self._fold_index[lang]
        except KeyError:
            idx = [(ref, self._verses[ref].get(lang, "").casefold())
                   for ref in self._ordered_refs]
            self._fold_index[lang] = idx
            return idx

    @classmethod
    def from_file(cls, path: str | Path) -> "VerseStore":
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if "verses" not in data or not isinstance(data["verses"], dict):
            raise ValueError(f"bad data file {path}: missing 'verses' dict")
        verses = data["verses"]
        if len(verses) != 6236:
            import warnings
            warnings.warn(f"expected 6236 verses, got {len(verses)} in {path}")
        return cls(verses, data.get("meta"))

    def get(self, surah: int, ayah: int, lang: str) -> str | None:
        return self._verses.get(f"{surah}:{ayah}", {}).get(lang)

    @property
    def _ordered_refs(self) -> list[str]:
        """Canonical order, computed once (search + range walk reuse it)."""
        try:
            return self.__ordered
        except AttributeError:
            self.__ordered = sorted(
                self._verses, key=lambda r: tuple(map(int, r.split(":"))))
            return self.__ordered

    def refs(self) -> list[str]:
        """All verse refs ('S:A') in canonical order."""
        return list(self._ordered_refs)

    def search(self, query: str, lang: str, limit: int = 20) -> list[tuple[str, str]]:
        """(ref, snippet) substring matches in reading order."""
        qfold = query.casefold()
        hits = []
        for ref, folded in self._folded(lang):
            if qfold in folded:
                hits.append((ref, self._verses[ref].get(lang, "")[:120]))
                if len(hits) >= limit:
                    break
        return hits

    def __len__(self) -> int:
        return len(self._verses)
