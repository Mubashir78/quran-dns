#!/usr/bin/env python3
"""Asyncio DNS benchmark (spec section D): QPS + latency p50/p99 for UDP,
TCP, and UDP-with-fallback transports against a live server, plus TC rate.

DNS-only: the question for this prototype is UDP vs TCP/fallback cost.

Usage:
    python scripts/bench.py [--host 127.0.0.1] [--port PORT]
                            [--count 300] [--concurrency 10] [--timeout 3.0]
                            [--mode all|udp|tcp|fallback]

If --port is omitted, a server is started on 127.0.0.1:<free> via
qdns.server.start_servers (with a permissive limiter so the benchmark
measures transport cost, not rate limiting). If --port is given, the
benchmark runs against that already-running server.
"""
from __future__ import annotations

import argparse
import asyncio
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dns.flags
import dns.message
import dns.query

from qdns.resolver import Resolver
from qdns.server import RateLimiter, start_servers
from qdns.store import VerseStore

SHORT_NAME = "1-1.en.quran.test."     # small answer: fits UDP
LONG_NAME = "2-282.en.quran.test."   # ~5 KB answer: TC over UDP, full over TCP

LONG_TEXT = "الحمد لله رب العالمين " * 120

BENCH_STORE = VerseStore({
    "1:1": {"ar": "بسم الله", "en": "In the name of Allah"},
    "2:282": {"en": LONG_TEXT},
})


def percentile(xs: list[float], p: float) -> float:
    s = sorted(xs)
    if not s:
        return float("nan")
    k = (len(s) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


async def run_mode(mode: str, names: list[str], host: str, port: int,
                   concurrency: int, timeout: float) -> dict:
    sem = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    tc = 0
    errors = 0

    async def one(name: str):
        nonlocal tc, errors
        q = dns.message.make_query(name, "TXT")
        try:
            async with sem:
                t0 = time.perf_counter()
                if mode == "udp":
                    resp = await asyncio.to_thread(
                        dns.query.udp, q, host, timeout=timeout, port=port)
                elif mode == "tcp":
                    resp = await asyncio.to_thread(
                        dns.query.tcp, q, host, timeout=timeout, port=port)
                else:  # fallback
                    resp, _used_tcp = await asyncio.to_thread(
                        dns.query.udp_with_fallback, q, host,
                        timeout=timeout, port=port)
            latencies.append(time.perf_counter() - t0)
            if resp.flags & dns.flags.TC:
                tc += 1
        except Exception:
            errors += 1

    t0 = time.perf_counter()
    await asyncio.gather(*(one(n) for n in names))
    wall = time.perf_counter() - t0
    done = len(latencies)
    return {
        "mode": mode,
        "queries": done,
        "wall_s": wall,
        "qps": done / wall if wall > 0 else 0.0,
        "p50_ms": percentile(latencies, 0.50) * 1000,
        "p99_ms": percentile(latencies, 0.99) * 1000,
        "tc_rate": tc / done if done else 0.0,
        "errors": errors,
    }


def free_port(host: str) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def amain(args) -> int:
    cleanup = None
    if args.port is not None:
        host, port = args.host, args.port
        target = f"external server {host}:{port}"
    else:
        host = args.host
        port = free_port(host)
        resolver = Resolver(BENCH_STORE)
        # Permissive limiter: measure transport cost, not rate limiting.
        udp, tcp = await start_servers(
            resolver, host, port,
            limiter=RateLimiter(rate=100_000.0, burst=100_000.0))
        cleanup = (udp, tcp)
        target = f"self-started server {host}:{port}"
    try:
        # 90% short answers + 10% long answers so the UDP TC rate is meaningful.
        names = [LONG_NAME if i % 10 == 0 else SHORT_NAME
                 for i in range(args.count)]
        modes = ["udp", "tcp", "fallback"] if args.mode == "all" else [args.mode]
        print(f"bench: {target}  count={args.count}/mode "
              f"concurrency={args.concurrency} timeout={args.timeout}s")
        print(f"{'mode':<9}{'qps':>10}{'p50_ms':>10}{'p99_ms':>10}"
              f"{'tc_rate':>10}{'errors':>9}")
        for mode in modes:
            r = await run_mode(mode, names, host, port,
                               args.concurrency, args.timeout)
            print(f"{r['mode']:<9}{r['qps']:>10.1f}{r['p50_ms']:>10.2f}"
                  f"{r['p99_ms']:>10.2f}{r['tc_rate']:>10.1%}{r['errors']:>9d}")
        return 0
    finally:
        if cleanup is not None:
            udp, tcp = cleanup
            udp.close()
            tcp.close()
            await tcp.wait_closed()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="DNS transport benchmark (DNS-only)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=None,
                    help="benchmark a running server; omit to self-start one")
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("--concurrency", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--mode", choices=("all", "udp", "tcp", "fallback"),
                    default="all")
    return asyncio.run(amain(ap.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
