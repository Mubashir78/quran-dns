"""CLI client.   python -m qdns.client 2:255 -l en

Sends a TXT query over UDP and automatically retries over TCP when the
server sets the TC flag (dns.query.udp_with_fallback does the retry).
"""
from __future__ import annotations

import argparse
import re
import sys

import dns.exception
import dns.message
import dns.query
import dns.rcode

from .config import DEFAULT_LANG, LANGS, ZONE
from .txt import join_txt


def build_name(ref: str, lang: str, zone: str) -> str:
    if ref.lower() == "help":
        return f"help.{zone}"
    m = re.fullmatch(r"(\d{1,3})[:\-](\d{1,3})", ref.strip())
    if not m:
        raise ValueError("verse must look like 2:255 (or 2-255)")
    return f"{m.group(1)}-{m.group(2)}.{lang}.{zone}"


def fetch(name: str, server: str, port: int, timeout: float):
    query = dns.message.make_query(name, "TXT")
    resp, used_tcp = dns.query.udp_with_fallback(query, server, timeout=timeout, port=port)
    return resp, used_tcp


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fetch a verse over DNS")
    ap.add_argument("ref", help="verse like 2:255, or 'help'")
    ap.add_argument("-l", "--lang", choices=LANGS, default=DEFAULT_LANG)
    ap.add_argument("-s", "--server", default="127.0.0.1")
    ap.add_argument("-p", "--port", type=int, default=5353)
    ap.add_argument("-z", "--zone", default=ZONE)
    ap.add_argument("-t", "--timeout", type=float, default=3.0)
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show transport, rcode and sizes on stderr")
    args = ap.parse_args(argv)

    try:
        name = build_name(args.ref, args.lang, args.zone)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        resp, used_tcp = fetch(name, args.server, args.port, args.timeout)
    except (dns.exception.Timeout, OSError) as exc:
        print(f"error: could not reach {args.server}:{args.port} ({exc})", file=sys.stderr)
        return 2

    if args.verbose:
        print(f"[{name}  rcode={dns.rcode.to_text(resp.rcode())}  "
              f"transport={'udp->tcp fallback' if used_tcp else 'udp'}  "
              f"strings={len(resp.answer[0][0].strings) if resp.answer else 0}]",
              file=sys.stderr)

    if resp.rcode() == dns.rcode.NXDOMAIN:
        print("not found (check surah/ayah numbers)", file=sys.stderr)
        return 1
    if resp.rcode() != dns.rcode.NOERROR or not resp.answer:
        print(f"unexpected response: {dns.rcode.to_text(resp.rcode())}", file=sys.stderr)
        return 1

    try:
        print(join_txt(resp.answer[0][0]))
    except (UnicodeDecodeError, AttributeError, IndexError) as exc:
        print(f"error: bad TXT data ({exc})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
