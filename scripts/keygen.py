#!/usr/bin/env python3
"""Generate Ed25519 KSK + ZSK for the DNSSEC island of security.

    python scripts/keygen.py [--key-dir keys]

Writes ``ksk.pem`` (flag 257) and ``zsk.pem`` (flag 256) as PKCS8 PEM,
prints the DNSKEY rrset text plus the DS record for manual trust-anchor
setup, and the key tags.

LOCAL DEMO ONLY: both keys land on disk next to each other. In production
the KSK MUST stay offline (air-gapped signing ceremony for the DNSKEY set;
publish only the resulting RRSIG + DS at the parent).
"""
import argparse
import sys
from pathlib import Path

import dns.dnssec
import dns.name
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qdns.config import DNSSEC_ALGORITHM, DNSSEC_DNSKEY_TTL, ZONE  # noqa: E402
from qdns.dnssec import dump_private_key, make_dnskey_rdata  # noqa: E402
from qdns.dnssec import KSK_FLAGS, ZSK_FLAGS  # noqa: E402

ALG_NAME = {15: "ED25519"}.get(DNSSEC_ALGORITHM, str(DNSSEC_ALGORITHM))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generate DNSSEC island keys (Ed25519)")
    ap.add_argument("--key-dir", default="keys",
                    help="directory for ksk.pem/zsk.pem (created if missing)")
    ap.add_argument("--zone", default=ZONE, help="apex owner name")
    args = ap.parse_args(argv)

    key_dir = Path(args.key_dir)
    if not key_dir.is_absolute():
        key_dir = Path(__file__).resolve().parent.parent / key_dir
    key_dir.mkdir(parents=True, exist_ok=True)

    zone = dns.name.from_text(args.zone)
    keys = {}
    for role, flags in (("ksk", KSK_FLAGS), ("zsk", ZSK_FLAGS)):
        priv = Ed25519PrivateKey.generate()
        path = key_dir / f"{role}.pem"
        path.write_bytes(dump_private_key(priv))
        try:
            path.chmod(0o600)
        except OSError:
            pass
        dnskey = make_dnskey_rdata(priv, flags)
        keys[role] = (priv, dnskey)
        print(f"wrote {path} ({len(path.read_bytes())} bytes)")

    print()
    print(f"; {args.zone} DNSKEY set (TTL {DNSSEC_DNSKEY_TTL})")
    for role in ("ksk", "zsk"):
        _, dnskey = keys[role]
        print(f"{args.zone} {DNSSEC_DNSKEY_TTL} IN DNSKEY {dnskey.to_text()}")
    print()
    ksk_tag = dns.dnssec.key_id(keys["ksk"][1])
    print(f"; key tags: KSK {ksk_tag}, ZSK {dns.dnssec.key_id(keys['zsk'][1])}")
    print("; DS record for the KSK (manual trust anchor at the parent):")
    ds = dns.dnssec.make_ds(zone, keys["ksk"][1], "SHA256")
    print(f"{args.zone} IN DS {ds.key_tag} {ds.algorithm} {ds.digest_type} "
          f"{ds.digest.hex()}")
    print()
    print("NOTE: local demo keys. Production must keep the KSK offline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
