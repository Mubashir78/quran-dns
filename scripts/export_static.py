"""Build a dependency-free static copy of the Qur'an Reader page.

Reads qdns/web.html + data/quran.json, swaps the three server calls
(dns-query ask, /search, /verify) for a baked quran.json + local JS, copies
the four self-hosted fonts, and writes a deployable directory
(default site/: index.html, quran.json, fonts/*.ttf, .nojekyll).

Signature checks need the live DNS signer, so the static page says so
honestly instead of faking a check.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import sys as _sys

_sys.path.insert(0, str(ROOT))

ASK_JS = """var QURAN = null;
function quranData() {
  if (QURAN) return Promise.resolve(QURAN);
  return fetch("quran.json").then(function (r) {
    if (!r.ok) throw new Error("network " + r.status);
    return r.json();
  }).then(function (d) { QURAN = d.verses; return QURAN; });
}
function ask(surah, ayah, lang) {
  return quranData().then(function (v) {
    var t = (v[surah + ":" + ayah] || {})[lang];
    if (t === undefined) throw new Error("not found");
    return t;
  });
}"""

SEARCH_JS = """function runSearch(term) {
  var box = document.getElementById("results");
  term = term.trim();
  if (term.length < 3) { box.innerHTML = ""; return; }
  box.textContent = "Searching…";
  var lang = langEl.value, qfold = term.toLowerCase();
  quranData().then(function (v) {
    box.innerHTML = "";
    var n = 0, frag = document.createDocumentFragment();
    Object.keys(v).sort(function (a, b) {
      a = a.split(":"); b = b.split(":");
      return (+a[0] - +b[0]) || (+a[1] - +b[1]);
    }).some(function (ref) {
      var text = v[ref][lang] || "";
      if (text.toLowerCase().indexOf(qfold) < 0) return false;
      var b = document.createElement("button");
      b.type = "button";
      var strong = document.createElement("strong");
      strong.textContent = ref;
      var small = document.createElement("small");
      small.textContent = text.slice(0, 120);
      b.appendChild(strong); b.appendChild(small);
      b.addEventListener("click", function () {
        var p = parseRef(ref);
        document.getElementById("ref").value = ref;
        box.innerHTML = "";
        show(p.s, p.a);
      });
      frag.appendChild(b);
      return ++n >= 20;
    });
    if (!n) { box.textContent = "No verses contain that word."; return; }
    box.appendChild(frag);
    applyMemorize();
  }).catch(function () { box.textContent = "Search unavailable."; });
}"""

VERIFY_JS = """function checkSignature(s, a, lang) {
  document.getElementById("verify").textContent =
    "Static copy: verses are baked in, so there is no live signature to check.";
}"""


def _replace_once(text: str, old: str, new: str) -> str:
    n = text.count(old)
    assert n == 1, f"expected 1 occurrence, found {n}: {old[:60]!r}"
    return text.replace(old, new)


def _block(text: str, start: str) -> tuple[str, str]:
    """Split out one `function ... { ... }` block (brace-matched)."""
    i = text.index(start)
    depth, j = 0, i + len(start) - 1  # start ends at the opening brace
    while True:
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return text[i:j + 1], text[:i] + "{HERE}" + text[j + 1:]


def build(out: Path) -> None:
    html = (ROOT / "qdns" / "web.html").read_text(encoding="utf-8")

    _, html = _block(html, "function ask(")
    html = html.replace("{HERE}", ASK_JS, 1)
    _, html = _block(html, "function runSearch(term) {")
    html = html.replace("{HERE}", SEARCH_JS, 1)
    _, html = _block(html, "function checkSignature(s, a, lang) {")
    html = html.replace("{HERE}", VERIFY_JS, 1)
    assert '"search?q="' not in html, "search endpoint still referenced"
    assert "dns-query?dns=" not in html, "DoH endpoint still referenced"
    assert "verify?ref=" not in html, "verify endpoint still referenced"
    html = html.replace('src: url("/font/', 'src: url("fonts/')
    html = html.replace("url(\"/font/", "url(\"fonts/")
    html = re.sub(r'url\("fonts/([^"]+)"\)', r'url("fonts/\1.ttf")', html)

    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(html, encoding="utf-8")

    data = json.loads((ROOT / "data" / "quran.json").read_text(encoding="utf-8"))
    (out / "quran.json").write_text(
        json.dumps({"verses": data["verses"]}, ensure_ascii=False),
        encoding="utf-8")

    fonts = out / "fonts"
    fonts.mkdir(exist_ok=True)
    from qdns.web import _FONTS
    for which, pattern in _FONTS.items():
        p = subprocess.run(["fc-match", pattern, "--format=%{file}"],
                           capture_output=True, text=True,
                           timeout=10).stdout.strip()
        shutil.copyfile(p, fonts / f"{which}.ttf")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    print(f"wrote {out}/ ({sum(f.stat().st_size for f in out.rglob('*') if f.is_file()) // 1024} KB)")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Export static reader page")
    ap.add_argument("--out", default="site", help="output dir (default site/)")
    args = ap.parse_args(argv)
    build(ROOT / args.out)


if __name__ == "__main__":
    main()
