"""Step 6: SMS gateway (option B). Android relay app forwards texts here,
we answer through the phone's send API. Pure logic; HTTP lives in doh.py."""
from __future__ import annotations

import re
import time
import urllib.request
import json

from .store import VerseStore

LANGS_SMS = ("ar", "en", "ur")
DEFAULT_LANG_SMS = "en"
MAX_SMS_CHARS = 400
SENDER_COOLDOWN = 30.0

HELP_SMS = ("Quran SMS: send chapter:verse + lang, e.g. '112:4 en'. "
            "Langs: ar en ur. Reply always includes Arabic.")

TAIL = " [full text on reader page]"


class SmsParseError(ValueError):
    pass


def parse_request(body: str) -> tuple[int, int, str]:
    """'112:4 en' -> (112, 4, 'en'). Raises SmsParseError."""
    m = re.fullmatch(r"\s*(\d{1,3})\s*[:\-]\s*(\d{1,3})(?:\s+([A-Za-z]{2}))?\s*",
                     body or "")
    if not m:
        raise SmsParseError(HELP_SMS)
    lang = (m.group(3) or DEFAULT_LANG_SMS).lower()
    if lang not in LANGS_SMS:
        raise SmsParseError(f"lang must be ar/en/ur. {HELP_SMS}")
    return int(m.group(1)), int(m.group(2)), lang


def build_reply(store: VerseStore, surah: int, ayah: int, lang: str) -> str:
    arabic = store.get(surah, ayah, "ar")
    if arabic is None:
        return f"{surah}:{ayah} not found. Check chapter/verse numbers."
    if lang == "ar":
        text = arabic
    else:
        trans = store.get(surah, ayah, lang)
        if trans is None:
            return f"{surah}:{ayah} not found. Check chapter/verse numbers."
        text = f"{arabic}\n{trans}"
    if len(text) > MAX_SMS_CHARS:
        text = text[:MAX_SMS_CHARS].rstrip() + "…" + TAIL
    return text


class Cooldown:
    """One reply per sender per window. Clock injectable for tests."""

    def __init__(self, window: float = SENDER_COOLDOWN, clock=time.monotonic):
        self.window = window
        self._clock = clock
        self._last: dict[str, float] = {}

    def allowed(self, sender: str) -> bool:
        now = self._clock()
        if now - self._last.get(sender, 0.0) < self.window:
            return False
        self._last[sender] = now
        return True


class PhoneGateway:
    """POSTs replies to the relay app's send API.

    Generic JSON mode (default): POST {"to", "message"}, optional Bearer token.
    SMSGate mode (smsgate=True): POST {"textMessage": {"text"},
    "phoneNumbers": [...]} with HTTP Basic auth (its local API shape).
    """

    def __init__(self, send_url: str, token: str = "",
                 username: str = "", password: str = "", smsgate: bool = False):
        self.send_url = send_url
        self.token = token
        self.username = username
        self.password = password
        self.smsgate = smsgate

    def send(self, to: str, text: str, timeout: float = 10.0) -> None:
        import base64
        if self.smsgate:
            body = json.dumps({"textMessage": {"text": text},
                               "phoneNumbers": [to]}).encode("utf-8")
        else:
            body = json.dumps({"to": to, "message": text}).encode("utf-8")
        req = urllib.request.Request(self.send_url, data=body,
                                     headers={"Content-Type": "application/json"})
        if self.smsgate and self.username:
            cred = base64.b64encode(
                f"{self.username}:{self.password}".encode()).decode()
            req.add_header("Authorization", f"Basic {cred}")
        elif self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()


def fetch_inbox(base_url: str, username: str, password: str,
                limit: int = 20, timeout: float = 10.0) -> list[dict]:
    """GET SMSGate local /inbox. Returns list of message dicts."""
    import base64
    from urllib.parse import urlencode
    url = base_url.rstrip("/") + "/inbox?" + urlencode({"type": "SMS", "limit": limit})
    req = urllib.request.Request(url)
    cred = base64.b64encode(f"{username}:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {cred}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


class InboxPoller:
    """Polls the phone inbox (webhooks can't point at LAN http).
    Remembers seen IDs; replies to new messages only."""

    def __init__(self, base_url: str, username: str, password: str,
                 store: VerseStore, gateway: PhoneGateway,
                 cooldown: Cooldown | None = None):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.store = store
        self.gateway = gateway
        self.cooldown = cooldown or Cooldown()
        self.seen: set[str] = set()

    def poll_once(self) -> int:
        """Fetch, reply to new arrivals. Returns count handled."""
        try:
            msgs = fetch_inbox(self.base_url, self.username, self.password)
        except Exception:
            return 0
        handled = 0
        for m in msgs:
            mid = m.get("id", "")
            if not mid or mid in self.seen:
                continue
            self.seen.add(mid)
            sender = m.get("sender", "")
            body = m.get("contentPreview", "") or m.get("message", "")
            if not sender:
                continue
            if not self.cooldown.allowed(sender):
                continue
            try:
                s, a, lang = parse_request(body)
            except SmsParseError as exc:
                reply = str(exc)
            else:
                reply = build_reply(self.store, s, a, lang)
            try:
                self.gateway.send(sender, reply)
                handled += 1
            except Exception:
                pass
        return handled


def poll_forever(poller: InboxPoller, interval: float = 10.0) -> None:
    import time as _time
    while True:
        poller.poll_once()
        _time.sleep(interval)


def handle_incoming(payload: dict, store: VerseStore, token_expected: str,
                    cooldown: Cooldown) -> tuple[str, str] | None:
    """Shared receiver logic. Returns (sender, reply) or None if cooldown
    hit. Raises PermissionError on bad token, KeyError on bad payload.

    Accepts flat payloads {from, body, token} (template-style forwarder apps)
    and SMSGate webhooks {event: sms:received, payload: {phoneNumber, message}}.
    """
    if "payload" in payload and "from" not in payload:  # SMSGate shape
        inner = payload.get("payload", {})
        payload = {"from": inner.get("phoneNumber", ""),
                   "body": inner.get("message", ""),
                   "token": payload.get("token", token_expected)}
    if token_expected and payload.get("token", "") != token_expected:
        raise PermissionError("bad sms token")
    sender = payload["from"]
    body = payload.get("body", "")
    if not cooldown.allowed(sender):
        return None
    try:
        s, a, lang = parse_request(body)
    except SmsParseError as exc:
        return sender, str(exc)
    return sender, build_reply(store, s, a, lang)
