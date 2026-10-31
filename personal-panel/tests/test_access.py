import http.client
from http.cookies import SimpleCookie
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

from werkzeug.security import generate_password_hash
from access import AccessPolicy, access_url
from app import create_app
from core import Core, PanelError
import manage

PUBLIC = {"PANEL_ACCESS": "public", "PANEL_BIND": "0.0.0.0:54322",
          "PANEL_ALLOWED_CLIENTS": "0.0.0.0/0,::/0", "PANEL_TLS": "off"}


class AccessPolicyTests(unittest.TestCase):
    def test_public_ipv4_ipv6_and_mobile_sources_without_domain(self):
        p = AccessPolicy.from_env(PUBLIC)
        self.assertTrue(p.accepts_host("203.0.113.10:54322"))
        self.assertTrue(p.accepts_host("[2001:db8::10]:54322"))
        self.assertTrue(p.accepts_client("198.51.100.11"))
        self.assertTrue(p.accepts_client("2001:db8::11"))
        self.assertFalse(p.tls)

    def test_dns_rebinding_and_malformed_host_rejected(self):
        p = AccessPolicy.from_env(PUBLIC)
        for bad in ("attacker.example:54322", "203.0.113.10.attacker.example", "user@203.0.113.10", "203.0.113.10/bad", "[::1]:invalid", ""):
            self.assertFalse(p.accepts_host(bad), bad)
        p = AccessPolicy.from_env(dict(PUBLIC, PANEL_ALLOWED_HOSTS="panel.example.com"))
        self.assertTrue(p.accepts_host("panel.example.com:54322"))
        self.assertFalse(p.accepts_host("other.panel.example.com"))

    def test_private_mode_and_explicit_allowlist_remain_available(self):
        p = AccessPolicy.from_env({})
        self.assertTrue(p.accepts_host("127.0.0.1:54322"))
        self.assertFalse(p.accepts_host("203.0.113.10:54322"))
        self.assertFalse(p.accepts_client("198.51.100.11"))
        p = AccessPolicy.from_env(dict(PUBLIC, PANEL_ALLOWED_CLIENTS="198.51.100.11/32"))
        self.assertTrue(p.accepts_client("::ffff:198.51.100.11"))
        self.assertFalse(p.accepts_client("198.51.100.12"))
        with self.assertRaises(ValueError):
            AccessPolicy.from_env({"PANEL_BIND": "0.0.0.0:54322"})

    def test_ports_tls_and_ipv6_url(self):
        for bind in ("0.0.0.0:22", "0.0.0.0:70000", "not-an-ip:54322"):
            with self.assertRaises(ValueError):
                AccessPolicy.from_env(dict(PUBLIC, PANEL_BIND=bind))
        p = AccessPolicy.from_env(dict(PUBLIC, PANEL_BIND="[::]:55444", PANEL_TLS="on"))
        self.assertEqual(access_url(p, "2001:db8::10"), "https://[2001:db8::10]:55444/")


class AccessCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = Path(self.tmp.name) / "panel.env"
        self.original = "PANEL_BIND=127.0.0.1:55444\nPANEL_ALLOWED_HOSTS=localhost,127.0.0.1,[::1]\nPANEL_ALLOWED_CLIENTS=127.0.0.0/8,::1/128\nPANEL_TLS=off\nPANEL_STATS_PORT=18387\nPANEL_CUSTOM=keep\n"
        self.env.write_text(self.original)

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, **changes):
        return types.SimpleNamespace(**dict(dict(mode="public", port=None, address="203.0.113.10", listen=None,
             allow_client=None, http=False, https=False, no_restart=False, no_firewall=True), **changes))

    def configure(self, args, failure=False):
        with patch.object(manage, "PANEL_ENV", self.env), patch.object(manage, "root_only"), patch.object(manage, "panel_health"), patch.object(manage, "service") as service, patch("builtins.print"):
            if failure:
                service.side_effect = [subprocess.CalledProcessError(1, "systemctl"), None]
            manage.configure_access(args)
            return service

    def test_upgrade_switches_old_loopback_config_and_keeps_custom_settings(self):
        service = self.configure(self.args())
        values = manage.env_values(self.env)
        self.assertEqual(values["PANEL_ACCESS"], "public")
        self.assertEqual(values["PANEL_BIND"], "0.0.0.0:55444")
        self.assertEqual(values["PANEL_ALLOWED_CLIENTS"], "0.0.0.0/0,::/0")
        self.assertEqual(values["PANEL_CUSTOM"], "keep")
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o600)
        service.assert_called_once_with("restart", "personal-panel.service")
        self.assertEqual(self.env.with_suffix('.env.previous').read_text(), self.original)

    def test_custom_port_and_return_to_private(self):
        self.configure(self.args(port=54323))
        self.assertEqual(manage.env_values(self.env)["PANEL_BIND"], "0.0.0.0:54323")
        self.configure(self.args(mode="private"))
        values = manage.env_values(self.env)
        self.assertEqual(values["PANEL_BIND"], "127.0.0.1:54323")
        self.assertEqual(values["PANEL_ALLOWED_CLIENTS"], "127.0.0.0/8,::1/128")

    def test_failed_restart_rolls_back_without_touching_xray(self):
        with self.assertRaisesRegex(PanelError, "已恢复原设置"):
            self.configure(self.args(), failure=True)
        self.assertEqual(self.env.read_text(), self.original)

    def test_invalid_port_does_not_change_config(self):
        for port in (22, 18387, 65536):
            with self.assertRaises(PanelError):
                self.configure(self.args(port=port))
            self.assertEqual(self.env.read_text(), self.original)

    def test_ufw_only_adds_management_rule_and_never_enables_firewall(self):
        with patch.object(manage.shutil, "which", return_value="/usr/sbin/ufw"), patch.object(manage.subprocess, "run", return_value=types.SimpleNamespace(stdout="Status: active\n")) as run:
            manage.open_management_firewall(54322)
            self.assertEqual(run.call_args_list[1].args[0], ["/usr/sbin/ufw", "allow", "54322/tcp", "comment", "Personal Panel management"])
            self.assertFalse(any("enable" in call.args[0] for call in run.call_args_list))
        with patch.object(manage.shutil, "which", return_value="/usr/sbin/ufw"), patch.object(manage.subprocess, "run", return_value=types.SimpleNamespace(stdout="Status: inactive\n")) as run:
            manage.open_management_firewall(54322)
            self.assertEqual(run.call_count, 1)


class PublicAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.core = Core(Path(self.tmp.name)/"data", Path(self.tmp.name)/"xray", test_mode=True)
        with self.core.db() as db:
            db.execute("INSERT INTO admin VALUES(1,?,?)", ("admin", generate_password_hash("a-secure-public-password")))
        with patch.dict(os.environ, PUBLIC):
            self.app = create_app(self.core, testing=False)
        self.client = self.app.test_client()
        self.base = "http://203.0.113.10:54322"

    def tearDown(self):
        self.tmp.cleanup()

    def login(self, base=None):
        return self.client.post("/api/login", json={"username":"admin","password":"a-secure-public-password"},
                                base_url=base or self.base, environ_base={"REMOTE_ADDR":"198.51.100.11"})

    def test_public_mobile_login_and_authenticated_mutation(self):
        response = self.client.get("/", base_url=self.base, environ_base={"REMOTE_ADDR":"198.51.100.11"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/state", base_url=self.base).status_code, 401)
        response = self.login()
        self.assertEqual(response.status_code, 200)
        csrf = response.json["csrf"]
        self.assertIn("HttpOnly", response.headers["Set-Cookie"])
        self.assertEqual(self.client.post("/api/settings", json={}, base_url=self.base).status_code, 403)
        response = self.client.post("/api/settings", json={"public_address":"203.0.113.10"}, base_url=self.base,
                                    headers={"X-CSRF-Token":csrf,"Origin":self.base}, environ_base={"REMOTE_ADDR":"198.51.100.12"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.core.state()["settings"]["public_address"], "203.0.113.10")

    def test_ipv6_literal_and_unconfigured_domain(self):
        self.assertEqual(self.client.get("/", base_url="http://[2001:db8::10]:54322").status_code, 200)
        self.assertEqual(self.client.get("/", base_url="http://attacker.example:54322").status_code, 400)

    def test_attackers_on_other_ips_do_not_lock_out_owner(self):
        with self.core.db() as db:
            db.executemany("INSERT INTO attempts VALUES(?,?)", [(f"192.0.2.{i}", time.time()) for i in range(1, 45)])
        self.assertEqual(self.login().status_code, 200)

    def test_https_retains_secure_cookie(self):
        with patch.dict(os.environ, dict(PUBLIC, PANEL_TLS="on")):
            self.client = create_app(self.core, testing=False).test_client()
        response = self.login("https://203.0.113.10:54322")
        self.assertEqual(response.status_code, 200)
        self.assertIn("; Secure", response.headers["Set-Cookie"])
        self.assertIn("Strict-Transport-Security", response.headers)


class PublicListenerTests(unittest.TestCase):
    def test_gunicorn_public_listener_really_serves_login_without_tls(self):
        self.listener_roundtrip(False)

    def test_gunicorn_public_listener_retains_optional_https(self):
        self.listener_roundtrip(True)

    def test_domain_https_login_validates_certificate_and_opens_workspace(self):
        self.listener_roundtrip(True, domain="panel.example.test")

    def listener_roundtrip(self, tls, domain=None):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            core = Core(folder/"data", folder/"xray", test_mode=True)
            with core.db() as db:
                db.execute("INSERT INTO admin VALUES(1,?,?)", ("admin", generate_password_hash("a-secure-public-password")))
            with socket.socket() as s:
                s.bind(("127.0.0.1",0))
                port = s.getsockname()[1]
            env = dict(os.environ, **PUBLIC)
            env.update(PANEL_BIND=f"0.0.0.0:{port}", PANEL_DATA_DIR=str(core.data), PANEL_XRAY_DIR=str(core.config_dir))
            if domain:
                env.update(PANEL_ALLOWED_HOSTS=f"localhost,127.0.0.1,[::1],{domain}", PANEL_PUBLIC_ADDRESS=domain)
            if tls:
                subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1",
                                "-subj",f"/CN={domain or '127.0.0.1'}","-addext",f"subjectAltName=DNS:{domain}" if domain else "subjectAltName=IP:127.0.0.1",
                                "-keyout",str(folder/"key.pem"),"-out",str(folder/"fullchain.pem")],
                               check=True,capture_output=True)
                env.update(PANEL_TLS="on",PANEL_TLS_DIR=str(folder))
                context=ssl.create_default_context(cafile=str(folder/"fullchain.pem"))
            def connect(timeout):
                connection = http.client.HTTPSConnection(domain or "127.0.0.1",port,timeout=timeout,context=context) if tls else http.client.HTTPConnection("127.0.0.1",port,timeout=timeout)
                if domain:
                    # Resolve only the fixture domain locally; keep TLS hostname
                    # verification and the real HTTPS login fully enabled.
                    connection._create_connection = lambda address, timeout, source_address=None: socket.create_connection(("127.0.0.1", port), timeout, source_address)
                return connection
            authority = f"{domain or '203.0.113.10'}:{port}"
            process = subprocess.Popen([sys.executable,"-m","gunicorn","--config","gunicorn.conf.py","wsgi:application"],
                                       cwd=Path(__file__).resolve().parents[1], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(60):
                    if process.poll() is not None:
                        self.fail("Gunicorn public listener failed to start")
                    try:
                        connection=connect(.5)
                        connection.request("GET","/",headers={"Host":authority})
                        response=connection.getresponse()
                        self.assertEqual(response.status,200)
                        self.assertIn(b"Personal Panel",response.read())
                        connection.close()
                        break
                    except OSError:
                        time.sleep(.1)
                else:
                    self.fail("Public listener did not become ready")
                connection=connect(3)
                body=json.dumps({"username":"admin","password":"a-secure-public-password"})
                connection.request("POST","/api/login",body,headers={"Host":authority,"Content-Type":"application/json"})
                response=connection.getresponse()
                self.assertEqual(response.status,200,response.read())
                if tls:
                    self.assertIn("; Secure",response.getheader("Set-Cookie"))
                cookie = response.getheader("Set-Cookie").split(";", 1)[0]
                connection.close()
                if domain:
                    connection = connect(3)
                    connection.request("GET", "/api/state", headers={"Host": authority, "Cookie": cookie})
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertIn("nodes", json.loads(response.read())["state"])
                    connection.close()
            finally:
                process.terminate()
                process.wait(timeout=10)
