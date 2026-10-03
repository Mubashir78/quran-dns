"""Central configuration for qdns."""
from pathlib import Path

ZONE = "quran.test."          # .test is reserved (RFC 2606): safe for local demos
DEFAULT_LANG = "ar"
LANGS = ("ar", "en", "ur")
TTL = 3600

UDP_LIMIT = 512               # classic DNS/UDP limit (RFC 1035). EDNS0 would raise it.
TXT_CHUNK = 255               # max bytes in ONE TXT character-string (RFC 1035)
SERVER_EDNS_MAX = 1232        # negotiated server UDP max (flag-day safe)
NEG_TTL = 300                 # negative caching TTL (SOA minimum, RFC 2308)

NS_NAMES = ("ns1.quran.test.",)
SOA_MNAME = "ns1.quran.test."
SOA_RNAME = "hostmaster.quran.test."
SOA_SERIAL = 2026100201
SOA_REFRESH = 3600
SOA_RETRY = 600
SOA_EXPIRE = 86400

DEFAULT_DATA = Path(__file__).resolve().parent.parent / "data" / "quran.json"

# --- DNSSEC island of security (spec section B, local demo only) ---
KEY_DIR = Path(__file__).resolve().parent.parent / "keys"
KSK_PATH = KEY_DIR / "ksk.pem"      # Ed25519 KSK, flag 257
ZSK_PATH = KEY_DIR / "zsk.pem"      # Ed25519 ZSK, flag 256
DNSSEC_ALGORITHM = 15               # Ed25519 (RFC 8080)
DNSSEC_LIFETIME = 14 * 86400        # pre-signed RRSIG validity: 14 days
DNSSEC_DNSKEY_TTL = TTL             # TTL for the apex DNSKEY rrset

HELP_TEXT = (
    "Qur'an over DNS. Ask for TXT records named <surah>-<ayah>.<lang>.quran.test "
    "(lang: ar en ur; default ar). "
    "Example: dig @127.0.0.1 -p 5353 2-255.en.quran.test TXT +short"
)
