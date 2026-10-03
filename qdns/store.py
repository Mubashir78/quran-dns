"""Step 2: look the verse up. Tiny in-memory store loaded from data/quran.json."""
from __future__ import annotations

import json
from pathlib import Path


class VerseStore:
    def __init__(self, verses: dict[str, dict[str, str]], meta: dict | None = None):
        self._verses = verses
        self.meta = meta or {}

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

    def __len__(self) -> int:
        return len(self._verses)
