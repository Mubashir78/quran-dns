import unittest

from qdns.config import DEFAULT_DATA
from qdns.sms import (
    Cooldown,
    PhoneGateway,
    SmsParseError,
    build_reply,
    handle_incoming,
    parse_request,
)
from qdns.store import VerseStore

STORE = VerseStore.from_file(DEFAULT_DATA)


class ParseTest(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(parse_request("112:4 en"), (112, 4, "en"))
        self.assertEqual(parse_request("2:255"), (2, 255, "en"))
        self.assertEqual(parse_request(" 1-1  ur "), (1, 1, "ur"))

    def test_bad(self):
        for bad in ("hello", "112", "112:4:1 en", "112:4 xx", ""):
            with self.assertRaises(SmsParseError, msg=bad):
                parse_request(bad)


class ReplyTest(unittest.TestCase):
    def test_arabic_plus_translation(self):
        r = build_reply(STORE, 112, 4, "en")
        self.assertIn(STORE.get(112, 4, "ar"), r)
        self.assertIn(STORE.get(112, 4, "en"), r)

    def test_ar_only(self):
        self.assertEqual(build_reply(STORE, 112, 4, "ar"), STORE.get(112, 4, "ar"))

    def test_missing_is_not_found(self):
        self.assertIn("not found", build_reply(STORE, 114, 99, "en"))

    def test_long_truncated(self):
        r = build_reply(STORE, 2, 282, "en")
        self.assertLessEqual(len(r), 400 + 60)
        self.assertIn("reader page", r)


class CooldownTest(unittest.TestCase):
    def test_second_sender_blocked(self):
        now = [100.0]
        cd = Cooldown(window=30.0, clock=lambda: now[0])
        self.assertTrue(cd.allowed("+1"))
        self.assertFalse(cd.allowed("+1"))
        now[0] += 31.0
        self.assertTrue(cd.allowed("+1"))


class IncomingTest(unittest.TestCase):
    def test_ok_and_help(self):
        cd = Cooldown()
        sender, reply = handle_incoming(
            {"from": "+1", "body": "112:4 en", "token": "t"}, STORE, "t", cd)
        self.assertEqual(sender, "+1")
        self.assertIn("none comparable", reply)
        cd2 = Cooldown()
        _, help_reply = handle_incoming(
            {"from": "+2", "body": "???", "token": "t"}, STORE, "t", cd2)
        self.assertIn("112:4 en", help_reply)

    def test_bad_token(self):
        with self.assertRaises(PermissionError):
            handle_incoming({"from": "+1", "body": "112:4"}, STORE, "t", Cooldown())

    def test_cooldown_returns_none(self):
        cd = Cooldown()
        p = {"from": "+1", "body": "112:4", "token": ""}
        self.assertIsNotNone(handle_incoming(p, STORE, "", cd))
        self.assertIsNone(handle_incoming(p, STORE, "", cd))

    def test_smsgate_webhook_shape(self):
        cd = Cooldown()
        p = {"event": "sms:received",
             "payload": {"phoneNumber": "+1", "message": "112:4 en"}}
        sender, reply = handle_incoming(p, STORE, "", cd)
        self.assertEqual(sender, "+1")
        self.assertIn("comparable", reply)


class PollerTest(unittest.TestCase):
    def _patch(self, inbox):
        import json
        import urllib.request
        real = urllib.request.urlopen

        class FakeResp:
            def __init__(self, data): self.data = data
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return self.data

        def fake(req, timeout=10):
            if req.full_url.endswith("/message"):
                fake.sent.append(json.loads(req.data))
                return FakeResp(b"ok")
            return FakeResp(json.dumps(inbox).encode())
        fake.sent = []
        urllib.request.urlopen = fake
        self.addCleanup(setattr, urllib.request, "urlopen", real)
        return fake

    def test_new_message_gets_reply_once(self):
        from qdns.sms import InboxPoller
        inbox = [{"id": "m1", "sender": "+1", "contentPreview": "112:4 en"}]
        fake = self._patch(inbox)
        gw = PhoneGateway("http://phone:8080/message", smsgate=True)
        p = InboxPoller("http://phone:8080", "u", "p", STORE, gw)
        self.assertEqual(p.poll_once(), 1)
        self.assertIn("comparable", fake.sent[0]["textMessage"]["text"])
        self.assertEqual(p.poll_once(), 0)  # seen, no duplicate

    def test_bad_input_gets_help(self):
        from qdns.sms import InboxPoller
        inbox = [{"id": "m2", "sender": "+2", "contentPreview": "hello"}]
        fake = self._patch(inbox)
        gw = PhoneGateway("http://phone:8080/message", smsgate=True)
        p = InboxPoller("http://phone:8080", "u", "p", STORE, gw)
        self.assertEqual(p.poll_once(), 1)
        self.assertIn("112:4 en", fake.sent[0]["textMessage"]["text"])


class SenderTest(unittest.TestCase):
    def test_json_shape(self):
        seen = {}

        class FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b"ok"

        import urllib.request
        real = urllib.request.urlopen
        urllib.request.urlopen = lambda req, timeout=10: (
            seen.update(url=req.full_url, body=req.data,
                        auth=req.headers.get("Authorization")),
            FakeResp())[1]
        try:
            PhoneGateway("http://phone:8080/send", "sek").send("+1", "hi")
        finally:
            urllib.request.urlopen = real
        import json
        self.assertEqual(json.loads(seen["body"]), {"to": "+1", "message": "hi"})
        self.assertEqual(seen["auth"], "Bearer sek")

    def test_smsgate_shape(self):
        seen = {}

        class FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b"ok"

        import urllib.request
        real = urllib.request.urlopen
        urllib.request.urlopen = lambda req, timeout=10: (
            seen.update(url=req.full_url, body=req.data,
                        auth=req.headers.get("Authorization")),
            FakeResp())[1]
        try:
            PhoneGateway("http://phone:8080/message", username="u",
                         password="p", smsgate=True).send("+1", "hi")
        finally:
            urllib.request.urlopen = real
        import json
        self.assertEqual(json.loads(seen["body"]),
                         {"textMessage": {"text": "hi"}, "phoneNumbers": ["+1"]})
        self.assertTrue(seen["auth"].startswith("Basic "))


class EndpointTest(unittest.TestCase):
    def _serve(self, **kw):
        import threading
        from qdns.doh import make_server
        from qdns.resolver import Resolver
        sent = []

        class FakeGateway:
            def send(self, to, text):
                sent.append((to, text))

        store_kw = dict(store=STORE, gateway=FakeGateway(), sms_token="t")
        store_kw.update(kw)
        httpd = make_server(Resolver(STORE), "127.0.0.1", 0, **store_kw)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        return httpd.server_address[1], sent

    def _post(self, port, payload):
        import json
        import urllib.request
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/sms/incoming",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()

    def test_e2e_reply_reaches_gateway(self):
        import urllib.error
        port, sent = self._serve()
        status, body = self._post(port, {"from": "+1", "body": "112:4 en", "token": "t"})
        self.assertEqual(status, 200)
        self.assertEqual(sent[0][0], "+1")
        self.assertIn("comparable", sent[0][1])

    def test_bad_token_403(self):
        import urllib.error
        port, _ = self._serve()
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post(port, {"from": "+1", "body": "112:4", "token": "wrong"})
        self.assertEqual(cm.exception.code, 403)

    def test_unconfigured_503(self):
        import urllib.error
        port, _ = self._serve(gateway=None)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post(port, {"from": "+1", "body": "112:4", "token": "t"})
        self.assertEqual(cm.exception.code, 503)


if __name__ == "__main__":
    unittest.main()
