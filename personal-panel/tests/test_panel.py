import base64
import copy
import json
import os
from pathlib import Path
import secrets
import socket
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from werkzeug.security import generate_password_hash
import manage
from app import create_app
from core import Core, PanelError, clean_node, clean_state, share_link, xray_config


def node(protocol="vless-reality", port=20000):
    key = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    c = {"id": str(uuid.uuid4()), "name": "测试用户", "secret": str(uuid.uuid4()), "enabled": True,
         "expires_at": 0, "quota_bytes": 0}
    if protocol in ("trojan-tls", "hysteria2"):
        c["secret"] = "a-long-random-password-for-test"
    if protocol == "shadowsocks2022":
        c["secret"] = base64.b64encode(b"user-secret-1234").decode()
    return {"id": str(uuid.uuid4()), "name": "测试入站", "protocol": protocol, "listen": "::", "port": port,
            "address": "2001:db8::1", "sni": "example.com", "dest": "example.com", "dest_port": 443,
            "private_key": key, "public_key": key, "short_id": "1234567890abcdef", "path": "/private-ws",
            "server_key": base64.b64encode(b"server-key-12345").decode(), "enabled": True, "clients": [c]}


class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.core = Core(Path(self.tmp.name) / "data", Path(self.tmp.name) / "xray", test_mode=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_protocols_roundtrip_and_ipv6_share(self):
        for p in ("vless-reality", "vless-ws-tls", "vmess-ws-tls", "trojan-tls", "shadowsocks2022"):
            n = clean_node(node(p))
            link = share_link(n, n["clients"][0], "")
            if p == "vmess-ws-tls":
                payload = json.loads(base64.b64decode(link[8:]))
                self.assertEqual(payload["add"], "2001:db8::1")
            else:
                self.assertIn("@[2001:db8::1]:20000", link)
            self.assertNotIn("private_key", link)

    def test_expires_disabled_and_quotas_remove_authentication_entries(self):
        n = clean_node(node())
        c = n["clients"][0]
        self.core.apply(lambda s: dict(s, nodes=[n]))
        for field, value in (("expires_at", 100), ("enabled", False), ("quota_bytes", 10)):
            sample = copy.deepcopy(n)
            sample["clients"][0][field] = value
            s = dict(self.core.state(), nodes=[sample])
            config = xray_config(s, {c["id"]: {"up": 6, "down": 4}}, now=200)
            self.assertEqual(len(config["inbounds"]), 1, field)

    def test_ipv4_and_private_network_policy(self):
        config = xray_config(self.core.state())
        self.assertEqual(config["outbounds"][0]["sendThrough"], "0.0.0.0")
        self.assertEqual(config["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"], "ForceIPv4")
        self.assertEqual(config["routing"]["rules"][0]["outboundTag"], "panel-api")
        self.assertTrue(any("127.0.0.0/8" in r.get("ip", []) for r in config["routing"]["rules"]))

    def test_bad_values_and_duplicate_ports_do_not_mutate(self):
        before = self.core.state()
        for bad in (0, 65536, True, "20000"):
            with self.assertRaises(PanelError):
                self.core.apply(lambda s: dict(s, nodes=[dict(node(), port=bad)]))
        n = node()
        other = node()
        with self.assertRaises(PanelError):
            self.core.apply(lambda s: dict(s, nodes=[n, other]))
        self.assertEqual(before, self.core.state())
        n["port"] = self.core.stats_port
        with self.assertRaises(PanelError):
            clean_state(dict(before, nodes=[n]), self.core.stats_port)

    def test_config_rejection_preserves_database_and_live_config(self):
        self.core.apply(lambda s: s)
        before = self.core.state()
        config = (self.core.config_dir / "config.json").read_bytes()
        with patch.object(self.core, "validate_config", side_effect=PanelError("rejected")):
            with self.assertRaises(PanelError):
                self.core.apply(lambda s: dict(s, nodes=[node()]))
        self.assertEqual(self.core.state(), before)
        self.assertEqual((self.core.config_dir / "config.json").read_bytes(), config)

    def test_durable_stats_generation_and_counter_reset(self):
        c = str(uuid.uuid4())
        name = f"user>>>{c}@personal-panel>>>traffic>>>uplink"
        for value, generation in ((100, "a"), (150, "a"), (50, "b"), (60, "b"), (4, "b")):
            self.core.record_stats([{"name": name, "value": value}], generation)
        self.assertEqual(self.core.usage()[c]["up"], 214)
        other = Core(self.core.data, self.core.config_dir, test_mode=True)
        self.assertEqual(other.usage()[c]["up"], 214)

    def test_backup_restore_whitelisted_state_and_not_admin(self):
        self.core.apply(lambda s: dict(s, nodes=[node()]))
        backup = self.core.backup()
        with self.core.db() as db:
            db.execute("INSERT INTO admin VALUES(1,'actual','hash')")
        backup["admin"] = {"username": "attacker"}
        backup["state"]["nodes"][0]["certificateFile"] = "/etc/shadow"
        backup["state"]["nodes"][0]["name"] = "恢复的节点"
        self.core.restore(backup)
        self.assertEqual(self.core.state()["nodes"][0]["name"], "恢复的节点")
        self.assertNotIn("certificateFile", self.core.state()["nodes"][0])
        with self.core.db() as db:
            self.assertEqual(db.execute("SELECT username FROM admin").fetchone()[0], "actual")
        with self.assertRaises(PanelError):
            self.core.restore({"format": "legacy", "state": {}})

    def test_auto_backup_and_expiry_reconcile(self):
        n = node()
        self.core.apply(lambda s: dict(s, nodes=[n]))
        self.core.maintain()
        self.assertEqual(len(list((self.core.data / "auto-backups").glob("*.json"))), 1)
        n["clients"][0]["expires_at"] = 1
        # Simulate reaching an expiry without a web request.
        with self.core.db() as db:
            state = self.core.state()
            state["nodes"] = [clean_node(n)]
            db.execute("UPDATE state SET body=?", (json.dumps(state),))
        self.core.maintain()
        self.assertEqual(len(json.loads((self.core.config_dir / "config.json").read_text())["inbounds"]), 1)


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = generate_password_hash("a-secure-test-password", method="scrypt:32768:8:1")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.core = Core(Path(self.tmp.name) / "data", Path(self.tmp.name) / "xray", test_mode=True)
        with self.core.db() as db:
            db.execute("INSERT INTO admin VALUES(1,?,?)", ("admin", self.password_hash))
        self.app = create_app(self.core, testing=True)
        self.client = self.app.test_client()
        self.csrf = None

    def tearDown(self):
        self.tmp.cleanup()

    def login(self):
        response = self.client.post("/api/login", json={"username": "admin", "password": "a-secure-test-password"})
        self.assertEqual(response.status_code, 200)
        self.csrf = response.json["csrf"]
        return response

    def post(self, path, data=None, method="POST"):
        return self.client.open(path, method=method, json=data or {}, headers={"X-CSRF-Token": self.csrf or ""})

    def test_auth_csrf_origin_host_and_cookie(self):
        self.assertEqual(self.client.get("/api/state").status_code, 401)
        response = self.login()
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertEqual(self.client.post("/api/settings", json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/settings", json={}, headers={"X-CSRF-Token": self.csrf, "Origin": "https://evil.example"}).status_code, 403)
        self.assertEqual(self.client.get("/", headers={"Host": "evil.example"}).status_code, 400)
        self.assertEqual(self.client.post("/api/login", data="user=x").status_code, 415)
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_rate_limit_persists_between_app_instances(self):
        for _ in range(8):
            self.assertEqual(self.client.post("/api/login", json={"username": "wrong", "password": "wrong"}).status_code, 401)
        client = create_app(self.core, testing=True).test_client()
        self.assertEqual(client.post("/api/login", json={"username": "admin", "password": "a-secure-test-password"}).status_code, 429)

    def test_interactive_admin_retries_and_keeps_the_username(self):
        self.login()
        with patch.object(manage.os, "geteuid", return_value=1000), patch.object(manage, "Core", return_value=self.core), \
             patch("builtins.input", side_effect=["invalid name", ""]) as username, \
             patch.object(manage.getpass, "getpass", side_effect=[
                 "123456", "x" * 129, "1234567", "mismatch", "1234567", "1234567"
             ]) as password:
            manage.admin(SimpleNamespace(username=None))
        self.assertEqual(username.call_count, 2)
        self.assertEqual(password.call_count, 6)
        self.assertEqual(self.client.get("/api/session").status_code, 401)
        self.assertEqual(self.client.post("/api/login", json={"username": "admin", "password": "1234567"}).status_code, 200)

    def test_account_change_validates_credentials_and_revokes_all_sessions(self):
        old = "a-secure-test-password"
        update = dict(username="owner", current_password=old, new_password="1234567", confirm_password="1234567")
        self.assertEqual(self.post("/api/account", update).status_code, 401)
        self.login()
        other = self.app.test_client()
        self.assertEqual(other.post("/api/login", json={"username": "admin", "password": old}).status_code, 200)
        self.assertEqual(self.client.post("/api/account", json=update).status_code, 403)
        for changes, status in [
            (dict(current_password="wrong"), 403), (dict(username="bad name"), 400),
            (dict(new_password="123456", confirm_password="123456"), 400),
            (dict(new_password="x"*129, confirm_password="x"*129), 400),
            (dict(confirm_password="different"), 400)
        ]:
            with self.subTest(changes=changes):
                self.assertEqual(self.post("/api/account", dict(update, **changes)).status_code, status)
        self.assertEqual(self.client.get("/api/session").json["username"], "admin")
        self.assertEqual(self.post("/api/account", update).status_code, 200)
        for client in (self.client, other):
            self.assertEqual(client.get("/api/session").status_code, 401)
        for username, password in [("admin", old), ("owner", old), ("admin", "1234567")]:
            self.assertEqual(self.client.post("/api/login", json=dict(username=username, password=password)).status_code, 401)
        self.assertEqual(self.client.post("/api/login", json={"username": "owner", "password": "1234567"}).status_code, 200)

    def test_rename_only_and_password_only(self):
        self.login()
        old = "a-secure-test-password"
        self.assertEqual(self.post("/api/account", dict(username="owner", current_password=old)).status_code, 200)
        response = self.client.post("/api/login", json=dict(username="owner", password=old))
        self.assertEqual(response.status_code, 200)
        self.csrf = response.json["csrf"]
        password = "x" * 128
        self.assertEqual(self.post("/api/account", dict(username="owner", current_password=old,
                              new_password=password, confirm_password=password)).status_code, 200)
        self.assertEqual(self.client.post("/api/login", json=dict(username="owner", password=password)).status_code, 200)

    def test_account_reauthentication_is_rate_limited(self):
        self.login()
        for _ in range(8):
            self.assertEqual(self.post("/api/account", dict(username="owner", current_password="wrong")).status_code, 403)
        self.assertEqual(self.post("/api/account", dict(username="owner", current_password="a-secure-test-password")).status_code, 429)

    def test_login_cannot_issue_session_after_concurrent_credential_change(self):
        def finish_old_password_check(*args):
            with self.core.db() as db:
                db.execute("UPDATE admin SET password_hash=? WHERE id=1", ("changed",))
            return True
        with patch("app.check_password_hash", side_effect=finish_old_password_check):
            response = self.client.post("/api/login", json={"username": "admin", "password": "a-secure-test-password"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.client.get("/api/session").status_code, 401)

    def test_ip_allowlist_does_not_trust_forwarded_headers(self):
        app = create_app(self.core, testing=False)
        response = app.test_client().get("/", environ_base={"REMOTE_ADDR": "203.0.113.1"}, headers={"X-Forwarded-For": "127.0.0.1"})
        self.assertEqual(response.status_code, 403)

    def test_node_client_crud_qr_and_restore(self):
        self.login()
        n = node()
        response = self.post("/api/nodes", n)
        self.assertEqual(response.status_code, 200, response.json)
        n["clients"].append(dict(n["clients"][0], id=str(uuid.uuid4()), name="第二个用户", secret=str(uuid.uuid4())))
        self.assertEqual(self.post('/api/nodes/' + n["id"], n, method="PUT").status_code, 200)
        cid = n["clients"][0]["id"]
        self.assertTrue(self.client.get(f'/api/share/{n["id"]}/{cid}').json["link"].startswith("vless://"))
        qr = self.client.get(f'/api/qr/{n["id"]}/{cid}')
        self.assertEqual(qr.status_code, 200)
        self.assertIn(b"<svg", qr.data)
        backup = self.client.get("/api/backup").json
        self.assertNotIn("admin", backup)
        self.assertEqual(self.post('/api/nodes/' + n["id"], method="DELETE").status_code, 200)
        self.assertEqual(self.post('/api/restore', backup).status_code, 200)
        self.assertEqual(len(self.core.state()["nodes"][0]["clients"]), 2)
        self.assertEqual(self.post(f"/api/usage/{cid}/reset").status_code, 200)
        self.assertEqual(self.post('/api/restart-core').status_code, 200)

    def test_new_node_selects_and_persists_a_free_port(self):
        self.login()
        existing = dict(node(port=20000), enabled=False)
        self.assertEqual(self.post("/api/nodes", existing).json["port"], 20000)
        new = dict(node("shadowsocks2022"), listen="127.0.0.1")
        del new["port"]
        random_offset = secrets.randbelow
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp, \
             patch.dict(os.environ, PANEL_SITE_DOMAIN="test.example", PANEL_SITE_PORT="24443"):
            tcp.bind(("127.0.0.1", 0))
            tcp.listen()
            udp.bind(("127.0.0.1", 0))
            blocked = [20000, self.app.extensions["access"].port, self.core.stats_port, 24443,
                       tcp.getsockname()[1], udp.getsockname()[1]]
            candidates = iter(blocked)
            def next_offset(limit):
                candidate = next(candidates, None)
                return candidate - 10000 if candidate is not None else random_offset(limit)
            with patch("core.secrets.randbelow", side_effect=next_offset) as choose:
                response = self.post("/api/nodes", new)
            self.assertEqual(response.status_code, 200, response.json)
            port = response.json["port"]
            self.assertGreater(choose.call_count, len(blocked))
            self.assertNotIn(port, blocked)
            self.assertTrue(10000 <= port <= 65535)
        saved = self.core.state()["nodes"][-1]
        self.assertEqual((saved["id"], saved["port"]), (new["id"], port))
        share = self.client.get(f'/api/share/{saved["id"]}/{saved["clients"][0]["id"]}').json["link"]
        self.assertIn(f":{port}", share)
        path = "/api/nodes/" + saved["id"]
        self.assertEqual(self.post(path, dict(saved, name="renamed"), method="PUT").status_code, 200)
        self.assertEqual(self.post(path, dict(saved, port=None), method="PUT").status_code, 400)
        self.assertEqual(self.core.state()["nodes"][-1]["port"], port)
        for blank in (None, ""):
            another = self.post("/api/nodes", dict(node(), port=blank, listen="127.0.0.1"))
            self.assertEqual(another.status_code, 200, another.json)
        ports = [n["port"] for n in self.core.state()["nodes"]]
        self.assertEqual(len(set(ports)), len(ports))
        for invalid in (0, 65536, True, "20000", 20000, self.app.extensions["access"].port):
            self.assertEqual(self.post("/api/nodes", dict(node(), port=invalid)).status_code, 400)

    def test_oversize_invalid_backup_and_no_file_disclosure(self):
        self.login()
        self.assertEqual(self.client.post("/api/settings", data=b"x"*(1024*1024+1), content_type="application/json", headers={"X-CSRF-Token":self.csrf}).status_code, 413)
        self.assertEqual(self.post("/api/restore", {"format": "personal-panel-v1", "state": {"nodes": "bad"}}).status_code, 400)
        self.assertEqual(self.client.get('/static/../../core.py').status_code, 404)
        self.assertEqual(self.client.get('/api/cloudflare').status_code, 404)

    def test_backup_restore_has_larger_authenticated_budget(self):
        backup = self.core.backup()
        backup['ignored_export_metadata'] = 'x' * (1024 * 1024)
        self.assertEqual(self.client.post('/api/restore', json=backup).status_code, 401)
        self.login()
        self.assertEqual(self.post('/api/restore', backup).status_code, 200)
        response = self.client.post('/api/restore', content_type='application/json',
                                   headers={'X-CSRF-Token': self.csrf},
                                   environ_overrides={'CONTENT_LENGTH': str(32*1024*1024+1)})
        self.assertEqual(response.status_code, 413)

    def test_logout_and_revoked_sessions(self):
        self.login()
        self.assertEqual(self.post('/api/logout').status_code, 200)
        self.assertEqual(self.client.get('/api/state').status_code, 401)
        self.login()
        with self.core.db() as db:
            db.execute("DELETE FROM sessions")
        self.assertEqual(self.client.get('/api/state').status_code, 401)


if __name__ == "__main__":
    unittest.main()
