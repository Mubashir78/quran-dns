import importlib.util
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

_spec = importlib.util.spec_from_loader(
    "verse_cli", importlib.machinery.SourceFileLoader(
        "verse_cli", str(Path(__file__).resolve().parent.parent / "scripts" / "verse")))
verse = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verse)


class ParseRefTest(unittest.TestCase):
    def test_single(self):
        self.assertEqual(verse.parse_ref("2:255"), [(2, 255)])

    def test_range(self):
        self.assertEqual(verse.parse_ref("112:1-3"), [(112, 1), (112, 2), (112, 3)])

    def test_random_in_bounds(self):
        (s, a), = verse.parse_ref("random")
        self.assertTrue(1 <= s <= 114 and 1 <= a <= verse.AYAH_COUNTS[s - 1])

    def test_bad_refs(self):
        for bad in ("foo", "2:999", "115:1", "2:1-99", "0:1"):
            with self.assertRaises(ValueError, msg=bad):
                verse.parse_ref(bad)

    def test_bad_lang_exit2(self):
        self.assertEqual(verse.main(["2:255", "-l", "xx"]), 2)

    def test_default_langs_ar_en(self):
        seen = []
        with mock.patch.object(verse, "get_verse",
                               side_effect=lambda s, a, la, *_: seen.append(la) or "x"):
            self.assertEqual(verse.main(["112:4", "--no-color"]), 0)
        self.assertEqual(seen, ["ar", "en"])

    def test_doh_flag_routes_to_doh_fetch(self):
        with mock.patch.object(verse, "doh_fetch") as df, \
             mock.patch.object(verse, "fetch") as raw:
            df.side_effect = AssertionError("no wire here")
            r = verse.main(["112:4", "--no-color", "--doh", "https://x.invalid"])
            self.assertEqual(r, 2)  # network fail -> exit 2, proves doh path used
            raw.assert_not_called()


class OutputModeTest(unittest.TestCase):
    def _run(self, *argv):
        with mock.patch.object(verse, "get_verse", return_value="TEXT"):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = verse.main(list(argv))
        return rc, buf.getvalue()

    def test_json_shape(self):
        rc, out = self._run("112:4", "-l", "en", "--json")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out), {"ref": "112:4", "en": "TEXT"})

    def test_json_range_is_list(self):
        rc, out = self._run("112:1-2", "-l", "en", "--json")
        self.assertEqual(json.loads(out)[1]["ref"], "112:2")

    def test_no_color_no_ansi(self):
        rc, out = self._run("112:4", "-l", "en", "--no-color")
        self.assertEqual(rc, 0)
        self.assertNotIn("\033", out)
        self.assertIn("112:4", out)

    def test_help_ref(self):
        rc, out = self._run("help")
        self.assertEqual(rc, 0)

    def test_render_modes(self):
        visual = verse.for_terminal("ا ب", "ar", mode="visual")
        self.assertEqual(verse.for_terminal("ا ب", "ar", mode="kitty"), visual)
        self.assertEqual(verse.for_terminal("ا ب", "ar", mode="full"), "ا ب")
        self.assertEqual(verse.for_terminal("text", "en", mode="kitty"), "text")

    def test_detect_render(self):
        with mock.patch.dict("os.environ", {"KITTY_WINDOW_ID": "1"}, clear=False):
            self.assertEqual(verse.detect_render(), "kitty")
        env = {k: v for k, v in os.environ.items() if k != "KITTY_WINDOW_ID"}
        with mock.patch.dict("os.environ", {**env, "VTE_VERSION": "1"}, clear=True):
            self.assertEqual(verse.detect_render(), "full")
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(verse.detect_render(), "visual")

    def test_split_ref_langs(self):
        self.assertEqual(verse.split_ref_langs("112:4 en", ("ar",)),
                         ("112:4", ("en",)))
        self.assertEqual(verse.split_ref_langs("112:4 ar,en", ("ar",)),
                         ("112:4", ("ar", "en")))
        self.assertEqual(verse.split_ref_langs("2:255", ("ar",)), ("2:255", ("ar",)))
        self.assertEqual(verse.split_ref_langs("random ur", ("ar",)),
                         ("random", ("ur",)))


if __name__ == "__main__":
    unittest.main()
