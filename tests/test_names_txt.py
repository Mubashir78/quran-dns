import unittest

import dns.name

from qdns.names import QueryParseError, parse_qname
from qdns.txt import chunk_utf8

ZONE = dns.name.from_text("quran.test.")


def parse(s):
    return parse_qname(dns.name.from_text(s), ZONE)


class NamesTest(unittest.TestCase):
    def test_verse_with_lang(self):
        p = parse("2-255.en.quran.test.")
        self.assertEqual((p.kind, p.surah, p.ayah, p.lang), ("verse", 2, 255, "en"))

    def test_default_lang_is_arabic(self):
        self.assertEqual(parse("1-1.quran.test.").lang, "ar")

    def test_case_insensitive(self):
        self.assertEqual(parse("2-255.EN.Quran.TEST.").lang, "en")

    def test_help_and_apex(self):
        self.assertEqual(parse("help.quran.test.").kind, "help")
        self.assertEqual(parse("quran.test.").kind, "help")

    def test_rejects_bad_names(self):
        for bad in ("115-1.quran.test.", "0-1.quran.test.", "2-0.quran.test.",
                    "2-255.xx.quran.test.", "abc.quran.test.",
                    "1-1.en.extra.quran.test.", "2.255.quran.test."):
            with self.assertRaises(QueryParseError, msg=bad):
                parse(bad)


class ChunkTest(unittest.TestCase):
    def test_arabic_split_is_lossless_and_utf8_safe(self):
        text = "بِسۡمِ ٱللَّهِ ٱلرَّحۡمَٰنِ ٱلرَّحِيمِ " * 40      # ~2 KB of Arabic
        chunks = chunk_utf8(text)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(c) <= 255 for c in chunks))
        for c in chunks:
            c.decode("utf-8")                 # raises if a character was cut in half
        self.assertEqual(b"".join(chunks).decode("utf-8"), text)

    def test_short_and_empty(self):
        self.assertEqual(chunk_utf8("hi"), [b"hi"])
        self.assertEqual(chunk_utf8(""), [b""])


if __name__ == "__main__":
    unittest.main()
