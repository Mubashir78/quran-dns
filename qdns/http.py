"""Tiny HTTP plumbing: response helpers + method/path router.

One job: HTTP mechanics. Feature code (DoH, reader page, SMS) registers
routes; the handler only dispatches.
"""
from __future__ import annotations

from typing import Callable
from urllib.parse import urlparse


def send_text(h, code: int, text: str) -> None:
    body = text.encode("utf-8")
    h.send_response(code, text)
    h.send_header("Content-Type", "text/plain; charset=utf-8")
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    try:
        h.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        pass


def send_bytes(h, code: int, body: bytes, ctype: str,
               extra: dict | None = None) -> None:
    h.send_response(code)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(body)))
    for k, v in (extra or {}).items():
        h.send_header(k, v)
    h.end_headers()
    try:
        h.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        pass


RouteFn = Callable[..., None]


class Router:
    """Exact (method, path) routes plus path-prefix routes.

    Unknown path -> 404. Known path + wrong method -> 405.
    """

    def __init__(self):
        self.exact: dict[tuple[str, str], RouteFn] = {}
        self.prefix: list[tuple[str, str, RouteFn]] = []

    def add(self, method: str, path: str, fn: RouteFn) -> None:
        self.exact[(method, path)] = fn

    def add_prefix(self, method: str, prefix: str, fn: RouteFn) -> None:
        self.prefix.append((method, prefix, fn))

    def known_path(self, path: str) -> bool:
        if any(p == path for (_, p) in self.exact):
            return True
        return any(path.startswith(pre) for (_, pre, _) in self.prefix)

    def dispatch(self, h, method: str, raw_path: str) -> None:
        from urllib.parse import parse_qs
        parsed = urlparse(raw_path)
        fn = self.exact.get((method, parsed.path))
        if fn is None:
            for m, pre, pfn in self.prefix:
                if m == method and parsed.path.startswith(pre):
                    fn = pfn
                    break
        if fn is None:
            send_text(h, 404 if not self.known_path(parsed.path) else 405,
                      "not found" if not self.known_path(parsed.path)
                      else "method not allowed")
            return
        qs = parse_qs(parsed.query, keep_blank_values=True)
        fn(h, h.server, parsed, qs)
