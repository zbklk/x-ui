import argparse
import copy
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
from urllib.request import urlopen, Request

import manage
import ownsite
from core import Core, DEFAULT_SETTINGS, PanelError, clean_node, owned_site, xray_config
from test_panel import node
from test_xray_integration import port, wait_port

ROOT = Path(__file__).resolve().parents[1]


class SiteConfigurationTests(unittest.TestCase):
    def test_only_owned_target_maps_to_loopback_and_prevents_self_loop(self):
        env = {"PANEL_SITE_DOMAIN": "example.com", "PANEL_SITE_PORT": "8443"}
        n = clean_node(dict(node(), dest_port=8443))
        original = copy.deepcopy(n)
        state = {"settings": DEFAULT_SETTINGS, "nodes": [n]}
        with patch.dict(os.environ, env):
            self.assertEqual(owned_site()["url"], "https://example.com:8443/")
            reality = xray_config(state)["inbounds"][1]["streamSettings"]["realitySettings"]
            self.assertEqual(reality["target"], "127.0.0.1:8443")
            self.assertEqual(reality["serverNames"], ["example.com"])
            self.assertEqual(n, original)
            n["dest"] = "other.example.com"
            self.assertEqual(xray_config(state)["inbounds"][1]["streamSettings"]["realitySettings"]["target"], "other.example.com:8443")
            n.update(dest="example.com", dest_port=n["port"])
            with self.assertRaisesRegex(PanelError, "目标端口"):
                xray_config(state)
            n.update(dest_port=8443, port=8443)
            with self.assertRaisesRegex(PanelError, "小站端口"):
                xray_config(state)

    def test_occupied_port_falls_back_without_stopping_anything(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            occupied = listener.getsockname()[1]
            self.assertFalse(ownsite.port_available(occupied))
            with self.assertRaisesRegex(PanelError, "占用"):
                ownsite.choose_port(occupied, None, False, set())
        with patch.object(ownsite, "port_available", side_effect=lambda p: p == 8443):
            self.assertEqual(ownsite.choose_port(None, None, False, set()), 8443)
        self.assertEqual(ownsite.choose_port(None, 9443, True, set()), 9443)
        with self.assertRaises(PanelError):
            ownsite.choose_port(54322, None, False, {54322})

    def test_invalid_domain_rejected(self):
        for bad in ("127.0.0.1", "::1", "localhost", "*.example.com", "https://example.com", "example.com\nOTHER=bad"):
            with self.assertRaises(PanelError, msg=bad):
                ownsite.domain_name(bad)

    def test_setup_refuses_to_break_an_existing_enabled_node(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            core = Core(root / "data", root / "xray", test_mode=True)
            existing = clean_node(node())
            core.apply(lambda state: dict(state, nodes=[existing]))
            before = core.state()
            values = {"PANEL_DATA_DIR": str(core.data)}
            with self.assertRaisesRegex(PanelError, "原节点未改动"):
                ownsite.check_existing_nodes(values, "example.com", 8443)
            self.assertEqual(core.state(), before)
            ownsite.check_existing_nodes(values, "example.com", 443)
            with self.assertRaises(PanelError):
                ownsite.check_existing_nodes(values, "different.example.com", existing["port"])

    def test_setup_preserves_panel_access_and_rolls_back_on_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as folder:
                panel = Path(folder) / "panel.env"
                site = Path(folder) / "site.env"
                original = "PANEL_ACCESS=public\nPANEL_BIND=0.0.0.0:54322\nPANEL_TLS=off\nPANEL_ALLOWED_CLIENTS=0.0.0.0/0\n"
                panel.write_text(original)
                service = Mock(return_value=types.SimpleNamespace(returncode=3))
                ops = types.SimpleNamespace(root_only=Mock(), PANEL_ENV=panel, env_values=manage.env_values,
                    atomic_write=manage.atomic_write, service=service, certificate=Mock(), panel_health=Mock(),
                    AccessPolicy=manage.AccessPolicy, open_management_firewall=Mock(return_value="firewall checked"))
                with patch.object(ownsite, "SITE_ENV", site), patch.object(ownsite, "choose_port", return_value=8443), patch.object(ownsite, "wait_health", side_effect=PanelError("failed") if fail else None):
                    args = argparse.Namespace(domain="example.com", port=None)
                    if fail:
                        with self.assertRaisesRegex(PanelError, "恢复"):
                            ownsite.setup(args, ops)
                        self.assertEqual(panel.read_text(), original)
                        self.assertFalse(site.exists())
                    else:
                        ownsite.setup(args, ops)
                        values = manage.env_values(panel)
                        self.assertEqual(values["PANEL_TLS"], "off")
                        self.assertEqual(values["PANEL_BIND"], "0.0.0.0:54322")
                        self.assertEqual(values["PANEL_SITE_PORT"], "8443")
                        self.assertEqual(site.stat().st_mode & 0o777, 0o600)
                self.assertFalse(ops.certificate.call_args.args[0].panel_https)

    def test_existing_cloudflare_credentials_are_reused_without_prompt(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env = root / "cloudflare.env"
            env.write_text("CF_Token=" + "x"*32 + "\nCF_Zone_ID=" + "0"*32 + "\nPANEL_DOMAIN=example.com\n")
            (root / "acme").mkdir()
            (root / "acme/acme.sh").touch()
            with patch.object(manage, "CLOUDFLARE_ENV", env), patch.object(manage, "INSTALL", root), patch.object(manage, "root_only"), patch.object(manage, "service") as service, patch.object(manage.getpass, "getpass", side_effect=AssertionError("must not prompt")):
                manage.certificate(argparse.Namespace(domain="example.com", panel_https=False, replace_token=False))
            service.assert_any_call("enable", "--now", "personal-acme.timer")

    def test_shared_certificate_https_keeps_listener_and_rolls_back_failed_panel(self):
        for mode, fail in (("public", False), ("private", False), ("public", True)):
            with self.subTest(mode=mode, fail=fail), tempfile.TemporaryDirectory() as folder:
                panel, site = Path(folder) / "panel.env", Path(folder) / "site.env"
                bind = "0.0.0.0:55444" if mode == "public" else "127.0.0.1:55444"
                clients = "127.0.0.0/8,198.51.100.11/32" if mode == "public" else "127.0.0.0/8,::1/128"
                original = f"PANEL_ACCESS={mode}\nPANEL_BIND={bind}\nPANEL_TLS=off\nPANEL_ALLOWED_CLIENTS={clients}\nPANEL_PUBLIC_ADDRESS=203.0.113.10\n"
                panel.write_text(original)
                ops = types.SimpleNamespace(root_only=Mock(), PANEL_ENV=panel, env_values=manage.env_values,
                    atomic_write=manage.atomic_write, service=Mock(return_value=types.SimpleNamespace(returncode=3)),
                    certificate=Mock(), panel_health=Mock(side_effect=PanelError("HTTPS startup failed") if fail else None),
                    AccessPolicy=manage.AccessPolicy, show_access=Mock(), open_management_firewall=Mock(return_value="firewall checked"))
                with patch.object(ownsite, "SITE_ENV", site), patch.object(ownsite, "choose_port", return_value=8443), patch.object(ownsite, "wait_health"):
                    args = argparse.Namespace(domain="example.com", port=None, panel_https=True)
                    if fail:
                        with self.assertRaisesRegex(PanelError, "恢复"):
                            ownsite.setup(args, ops)
                        self.assertEqual(panel.read_text(), original)
                        self.assertFalse(site.exists())
                        ops.show_access.assert_not_called()
                    else:
                        ownsite.setup(args, ops)
                        values = manage.env_values(panel)
                        self.assertEqual(values["PANEL_TLS"], "on")
                        self.assertEqual(values["PANEL_PUBLIC_ADDRESS"], "example.com")
                        self.assertEqual(values["PANEL_BIND"], bind)
                        self.assertEqual(values["PANEL_ALLOWED_CLIENTS"], clients)
                        self.assertIn("example.com", values["PANEL_ALLOWED_HOSTS"].split(","))
                        self.assertTrue(ops.panel_health.call_args.args[0].tls)
                        if mode == "public":
                            self.assertEqual(manage.access_url(ops.panel_health.call_args.args[0], values["PANEL_PUBLIC_ADDRESS"]),
                                             "https://example.com:55444/")
                        ops.show_access.assert_called_once_with(values)
                self.assertFalse(ops.certificate.call_args.args[0].panel_https)

    def test_certificate_deployment_reloads_owned_site(self):
        with tempfile.TemporaryDirectory() as folder:
            site = Path(folder) / "site.env"
            site.touch()
            with patch.object(manage, "root_only"), patch.object(manage.ssl, "SSLContext"), patch.object(manage, "env_values", return_value={}), patch.object(ownsite, "SITE_ENV", site), patch.object(manage, "service") as service:
                manage.cert_deployed()
            service.assert_any_call("try-restart", "personal-site.service")


class RealSiteTests(unittest.TestCase):
    def test_https13_http2_hostname_and_read_only_page(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", str(root / "key.pem"),
                "-out", str(root / "fullchain.pem")], capture_output=True, check=True)
            site_port = port()
            log = root / "site.log"
            with log.open("wb") as output:
                process = subprocess.Popen([sys.executable, str(ROOT / "site_server.py")],
                    env=dict(os.environ, PANEL_SITE_PORT=str(site_port), PANEL_TLS_DIR=str(root)), stdout=output, stderr=output)
            process.panel_log = log
            try:
                wait_port(site_port, process)
                ownsite.health("localhost", site_port, cafile=str(root / "fullchain.pem"))
                with self.assertRaises(ssl.SSLCertVerificationError):
                    ownsite.health("wrong.example.com", site_port, cafile=str(root / "fullchain.pem"))
                context = ssl.create_default_context(cafile=str(root / "fullchain.pem"))
                with urlopen(f"https://localhost:{site_port}/", context=context, timeout=3) as response:
                    self.assertIn(b"Quiet Pages", response.read())
                from urllib.error import HTTPError
                for path, method, expected in (("/../core.py", "GET", 404), ("/", "POST", 405)):
                    with self.assertRaises(HTTPError) as error:
                        urlopen(Request(f"https://localhost:{site_port}{path}", method=method), context=context, timeout=3)
                    self.assertEqual(error.exception.code, expected)
                    error.exception.close()
            finally:
                process.terminate()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
