"""Publish verse TXT records to deSEC (public DNS hosting).

Needs a free deSEC account + token (desec.io), then:
  export DESEC_TOKEN=<token>
  python scripts/publish_desec.py --domain quran.dedyn.io --limit 5   # probe
  python scripts/publish_desec.py --domain quran.dedyn.io             # full

deSEC signs the zone itself (auto-DNSSEC). Our local Ed25519 signatures
stay a separate demo layer; they are NOT the zone's DNSSEC chain.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
from qdns.store import VerseStore  # noqa: E402
from qdns.config import DEFAULT_DATA  # noqa: E402

API = "https://desec.io/api/v1"
LANGS = ("ar", "en", "ur")


def api(method: str, path: str, token: str, payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(API + path, data=body, method=method,
                                 headers={"Authorization": f"Token {token}",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:500]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Publish verses to deSEC")
    ap.add_argument("--domain", required=True, help="e.g. quran.dedyn.io")
    ap.add_argument("--limit", type=int, default=0, help="only first N verses (probe)")
    ap.add_argument("--dry-run", action="store_true", help="print first RRset, send nothing")
    ap.add_argument("--data", default=str(DEFAULT_DATA))
    args = ap.parse_args(argv)

    token = os.environ.get("DESEC_TOKEN", "")
    if not token and not args.dry_run:
        print("error: set DESEC_TOKEN env", file=sys.stderr)
        return 2

    store = VerseStore.from_file(args.data)
    refs = sorted(store._verses, key=lambda r: tuple(map(int, r.split(":"))))
    if args.limit:
        refs = refs[:args.limit]

    rrsets = []
    for ref in refs:
        s, a = ref.split(":")
        for lang in LANGS:
            text = store.get(int(s), int(a), lang)
            if text is None:
                continue
            quoted = json.dumps(text)  # one JSON string = one TXT character-string set
            rrsets.append({"subname": f"{s}-{a}.{lang}", "type": "TXT",
                           "ttl": 3600, "records": [quoted]})

    if args.dry_run:
        print(json.dumps(rrsets[0], ensure_ascii=False, indent=2))
        print(f"... {len(rrsets)} rrsets total for {len(refs)} verses")
        return 0

    code, out = api("POST", "/domains/", token, {"name": args.domain})
    print(f"domain create: {code} {out}")
    if code not in (200, 201, 409):
        return 1
    # bulk PUT in chunks of 500
    for i in range(0, len(rrsets), 500):
        chunk = rrsets[i:i + 500]
        code, out = api("PUT", f"/domains/{args.domain}/rrsets/", token, chunk)
        print(f"rrsets {i}-{i + len(chunk)}: {code} {str(out)[:200]}")
        if code not in (200, 201, 207):
            return 1
    print(f"published {len(rrsets)} TXT rrsets under {args.domain}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
