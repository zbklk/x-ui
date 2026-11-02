"""Real sing-box server tests, including REALITY without an ML-KEM ClientHello."""
import copy
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from urllib.parse import parse_qs, unquote, urlsplit
from unittest.mock import patch

from core import Core, DEFAULT_SETTINGS, PanelError, clean_node, share_link
from singbox import singbox_config
from stats_rpc import decode_stats, query_stats
import test_panel as panel_tests
from test_xray_integration import port, wait_port

SINGBOX = os.environ.get("SINGBOX_TEST_BINARY")
XRAY = os.environ.get("XRAY_TEST_BINARY")
ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = b"sing-box-panel-data-plane-ok\n" * 2048


class SingboxAPITests(panel_tests.APITests):
    def setUp(self):
        super().setUp()
        self.core.engine = "sing-box"
        self.core.service = "personal-core.service"

    def test_hysteria2_crud_share_backup_preserves_existing_nodes_and_usage(self):
        self.login()
        old = [panel_tests.node("vless-reality", 21001), panel_tests.node("trojan-tls", 21002)]
        for n in old:
            self.assertEqual(self.post("/api/nodes", n).status_code, 200)
        cid = old[0]["clients"][0]["id"]
        self.core.record_stats([{"name": f"user>>>{cid}@personal-panel>>>traffic>>>downlink", "value": 1234}], "old-core")
        before = self.core.backup()
        n = panel_tests.node("hysteria2", 21003)
        n["obfs_password"] = "optional-salamander-password"
        n["clients"].append(dict(n["clients"][0], id=str(uuid.uuid4()), secret="second-hysteria-password"))
        self.assertEqual(self.post("/api/nodes", n).status_code, 200)
        self.assertEqual(self.core.state()["nodes"][:2], before["state"]["nodes"])
        self.assertEqual(self.core.usage(), before["usage"])
        n["clients"][1]["enabled"] = False
        n["name"] = "更新 HY2"
        self.assertEqual(self.post("/api/nodes/" + n["id"], n, method="PUT").status_code, 200)
        path = f'/api/share/{n["id"]}/{n["clients"][0]["id"]}'
        self.assertTrue(self.client.get(path).json["link"].startswith("hysteria2://"))
        qr = self.client.get(path.replace("/share/", "/qr/"))
        self.assertEqual(qr.status_code, 200)
        self.assertIn(b"<svg", qr.data)
        backup = self.client.get("/api/backup").json
        self.assertEqual(self.post("/api/nodes/" + n["id"], method="DELETE").status_code, 200)
        self.assertEqual(self.post("/api/restore", backup).status_code, 200)
        self.assertEqual(self.core.state(), backup["state"])
        self.assertEqual(self.core.usage(), before["usage"])


class ConfigTests(unittest.TestCase):
    def test_hysteria2_tls_users_quota_expiry_and_obfuscation(self):
        n = clean_node(dict(panel_tests.node("hysteria2"), obfs_password="salamander-password"))
        c = n["clients"][0]
        state = {"settings": dict(DEFAULT_SETTINGS), "nodes": [n]}
        config = singbox_config(state)
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["type"], "hysteria2")
        self.assertEqual(inbound["users"], [{"name": c["id"] + "@personal-panel", "password": c["secret"]}])
        self.assertEqual(inbound["tls"]["min_version"], "1.3")
        self.assertEqual(inbound["tls"]["alpn"], ["h3"])
        self.assertTrue(inbound["tls"]["certificate_path"].endswith("/fullchain.pem"))
        self.assertEqual(inbound["obfs"], {"type": "salamander", "password": "salamander-password"})
        for field, value in (("enabled", False), ("expires_at", 10), ("quota_bytes", 100)):
            sample = copy.deepcopy(state)
            sample["nodes"][0]["clients"][0][field] = value
            self.assertEqual(singbox_config(sample, {c["id"]: {"up": 50, "down": 50}}, now=20)["inbounds"], [])
        n["obfs_password"] = ""
        self.assertNotIn("obfs", singbox_config(state)["inbounds"][0])

    def test_hysteria2_share_escapes_secrets_and_uses_standard_uri(self):
        n = panel_tests.node("hysteria2")
        n["obfs_password"] = "mix : / ? & 中文"
        n["clients"][0]["secret"] = "password : / ? & 中文"
        n = clean_node(n)
        uri = urlsplit(share_link(n, n["clients"][0], ""))
        self.assertEqual(uri.scheme, "hysteria2")
        self.assertEqual(uri.hostname, "2001:db8::1")
        self.assertEqual(unquote(uri.username), n["clients"][0]["secret"])
        self.assertEqual(parse_qs(uri.query), {"sni": ["example.com"], "obfs": ["salamander"], "obfs-password": [n["obfs_password"]]})
        self.assertNotIn("insecure", uri.query)
        self.assertNotIn("security", uri.query)
        n["obfs_password"] = ""
        self.assertEqual(parse_qs(urlsplit(share_link(n, n["clients"][0], "")).query), {"sni": ["example.com"]})

    def test_hysteria2_rejects_ambiguous_users_and_invalid_secrets(self):
        n = panel_tests.node("hysteria2")
        for value in ("short", None):
            with self.assertRaises(PanelError):
                clean_node(dict(n, clients=[dict(n["clients"][0], secret=value)]))
        with self.assertRaises(PanelError):
            clean_node(dict(n, obfs_password="short"))
        with self.assertRaisesRegex(PanelError, "不能重复"):
            clean_node(dict(n, clients=[n["clients"][0], dict(n["clients"][0], id=str(uuid.uuid4()))]))

    def test_hysteria2_checks_udp_ports_and_tcp_protocol_switches(self):
        with tempfile.TemporaryDirectory() as folder:
            core = Core(Path(folder) / "data", Path(folder) / "core", test_mode=True, engine="sing-box")
            current = {"nodes": []}
            n = clean_node(panel_tests.node("hysteria2"))
            n["listen"] = "127.0.0.1"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
                listener.bind(("127.0.0.1", 0))
                n["port"] = listener.getsockname()[1]
                with self.assertRaisesRegex(PanelError, "不可绑定"):
                    core.check_new_ports(current, {"nodes": [n]}, {})
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0)); listener.listen()
                n["port"] = listener.getsockname()[1]
                core.check_new_ports(current, {"nodes": [n]}, {})
                changed = dict(n, protocol="trojan-tls")
                with self.assertRaisesRegex(PanelError, "不可绑定"):
                    core.check_new_ports({"nodes": [n]}, {"nodes": [changed]}, {})

    def test_owned_target_limits_and_default_network_protection(self):
        n = clean_node(dict(panel_tests.node(), dest_port=8443))
        state = {"settings": dict(DEFAULT_SETTINGS), "nodes": [n]}
        with patch.dict(os.environ, PANEL_SITE_DOMAIN="example.com", PANEL_SITE_PORT="8443"):
            config = singbox_config(state)
            inbound = config["inbounds"][0]
            self.assertEqual(inbound["tls"]["reality"]["handshake"], {"server": "127.0.0.1", "server_port": 8443})
            self.assertEqual(inbound["users"][0]["flow"], "xtls-rprx-vision")
            self.assertEqual(config["outbounds"][0]["inet4_bind_address"], "0.0.0.0")
            self.assertEqual(config["route"]["rules"][0]["action"], "resolve")
            self.assertTrue(any("127.0.0.0/8" in rule.get("ip_cidr", []) for rule in config["route"]["rules"]))
            self.assertEqual(config["experimental"]["v2ray_api"]["listen"], "127.0.0.1:18387")
            c = n["clients"][0]
            c["quota_bytes"] = 1
            self.assertEqual(singbox_config(state, {c["id"]: {"up": 1, "down": 0}})["inbounds"], [])
            c["quota_bytes"] = 0
            n["port"] = 8443
            with self.assertRaises(PanelError):
                singbox_config(state)

    def test_malformed_stats_messages_are_rejected(self):
        for body in (b"", b"\x00\x00\x00\x00\x10", b"\x01\x00\x00\x00\x00", b"\x00\x00\x00\x00\x02\x0a\xff"):
            with self.assertRaises(ValueError):
                decode_stats(body)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, *_):
        pass


@unittest.skipUnless(SINGBOX and XRAY, "set SINGBOX_TEST_BINARY and XRAY_TEST_BINARY")
class SingboxIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.core = Core(self.root / "data", self.root / "core", binary=SINGBOX, tls_dir=str(self.root), stats_port=port(), engine="sing-box")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=example.com",
            "-addext", "subjectAltName=DNS:example.com", "-keyout", str(self.root / "key.pem"), "-out", str(self.root / "fullchain.pem")],
            capture_output=True, check=True)
        self.processes, self.httpds = [], []

    def tearDown(self):
        for process in self.processes:
            process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        for httpd, worker in self.httpds:
            httpd.shutdown(); httpd.server_close(); worker.join(timeout=2)
        self.tmp.cleanup()

    def sample(self, protocol):
        n = panel_tests.node(protocol, port())
        n["listen"] = "127.0.0.1"
        if protocol == "vless-reality":
            n.update(self.core.keypair())
        return clean_node(n)

    def start(self, config, name, engine="sing-box"):
        path, logfile = self.root / (name + ".json"), self.root / (name + ".log")
        path.write_text(json.dumps(config))
        binary = SINGBOX if engine == "sing-box" else XRAY
        args = [binary, "run", "-c", str(path)] if engine == "sing-box" else [binary, "run", "-config", str(path)]
        with logfile.open("wb") as output:
            process = subprocess.Popen(args, stdout=output, stderr=output)
        process.panel_log = logfile
        self.processes.append(process)
        return process

    def origin(self, tls=False):
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(self.root / "fullchain.pem", self.root / "key.pem")
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        worker = threading.Thread(target=httpd.serve_forever, daemon=True)
        worker.start()
        self.httpds.append((httpd, worker))
        return httpd.server_port

    def xray_client(self, node, client, socks_port, fingerprint="chrome"):
        protocol = node["protocol"]
        server = {"address": "127.0.0.1", "port": node["port"]}
        outbound = {"protocol": protocol.split("-")[0], "settings": {}}
        if protocol == "shadowsocks2022":
            outbound["protocol"] = "shadowsocks"
            outbound["settings"] = {"servers": [dict(server, method="2022-blake3-aes-128-gcm", password=node["server_key"] + ":" + client["secret"])]}
        elif protocol == "trojan-tls":
            outbound["settings"] = {"servers": [dict(server, password=client["secret"])]}
        else:
            user = {"id": client["secret"], "encryption": "none"}
            if protocol == "vless-reality":
                user["flow"] = "xtls-rprx-vision"
            outbound["settings"] = {"vnext": [dict(server, users=[user])]}
        if protocol == "vless-reality":
            outbound["streamSettings"] = {"network": "tcp", "security": "reality", "realitySettings": {
                "serverName": node["sni"], "fingerprint": fingerprint, "password": node["public_key"], "shortId": node["short_id"]}}
        elif protocol != "shadowsocks2022":
            outbound["streamSettings"] = {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "example.com", "disableSystemRoot": True,
                "certificates": [{"usage": "verify", "certificateFile": str(self.root / "fullchain.pem")} ]}}
            if "ws" in protocol:
                outbound["streamSettings"].update(network="ws", wsSettings={"path": node["path"], "host": node["sni"]})
        return {"log": {"loglevel": "info"}, "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"auth": "noauth"}}], "outbounds": [outbound]}

    def transfer(self, socks_port, origin, tls=False, domain=None, timeout=8):
        with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as raw:
            raw.settimeout(timeout)
            raw.sendall(b"\x05\x01\x00")
            self.assertEqual(raw.recv(2), b"\x05\x00")
            destination = b"\x03" + bytes([len(domain)]) + domain.encode() if domain else b"\x01\x7f\x00\x00\x01"
            raw.sendall(b"\x05\x01\x00" + destination + struct.pack("!H", origin))
            self.assertEqual(raw.recv(10)[:2], b"\x05\x00")
            connection = raw
            if tls:
                context = ssl.create_default_context(cafile=str(self.root / "fullchain.pem"))
                connection = context.wrap_socket(raw, server_hostname="example.com")
            try:
                connection.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
                output = b""
                while PAYLOAD not in output:
                    data = connection.recv(65536)
                    if not data:
                        break
                    output += data
                return output
            finally:
                if connection is not raw:
                    connection.close()

    def hysteria_client(self, node, client, socks_port):
        outbound = {"type": "hysteria2", "server": "127.0.0.1", "server_port": node["port"], "password": client["secret"],
                    "tls": {"enabled": True, "server_name": node["sni"], "certificate_path": str(self.root / "fullchain.pem")}}
        if node.get("obfs_password"):
            outbound["obfs"] = {"type": "salamander", "password": node["obfs_password"]}
        return {"inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}], "outbounds": [outbound]}

    def udp_transfer(self, socks_port, destination, payload):
        def receive(raw, count):
            data = b""
            while len(data) < count:
                chunk = raw.recv(count - len(data))
                if not chunk:
                    raise ConnectionError("SOCKS association closed")
                data += chunk
            return data
        with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as raw:
            raw.sendall(b"\x05\x01\x00")
            self.assertEqual(receive(raw, 2), b"\x05\x00")
            raw.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            header = receive(raw, 4)
            self.assertEqual(header, b"\x05\x00\x00\x01")
            address = socket.inet_ntoa(receive(raw, 4))
            relay_port = struct.unpack("!H", receive(raw, 2))[0]
            if address == "0.0.0.0":
                address = "127.0.0.1"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(5)
                udp.sendto(b"\x00\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", destination) + payload, (address, relay_port))
                response = udp.recv(65535)
            self.assertEqual(response[:4], b"\x00\x00\x00\x01")
            self.assertEqual(response[10:], payload)

    def test_hysteria2_obfuscation_authentication_udp_and_user_stats(self):
        origin = self.origin()
        n = self.sample("hysteria2")
        n["obfs_password"] = "shared-salamander-password"
        n["clients"].append(dict(n["clients"][0], id=str(uuid.uuid4()), secret="second-hysteria-password"))
        state = self.core.state()
        state["settings"]["block_private"] = False
        state["nodes"] = [n]
        self.core.check_materials(state, {})
        wrong_sni = copy.deepcopy(state)
        wrong_sni["nodes"][0]["sni"] = "wrong.example.com"
        with self.assertRaisesRegex(PanelError, "未被当前证书覆盖"):
            self.core.check_materials(wrong_sni, {})
        server = self.start(self.core.compile(state), "hy2-obfs-server")
        wait_port(self.core.stats_port, server)
        echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        echo.bind(("127.0.0.1", 0)); echo.settimeout(.1)
        stop = threading.Event()
        def respond():
            while not stop.is_set():
                try:
                    data, address = echo.recvfrom(65535)
                    echo.sendto(data, address)
                except socket.timeout:
                    continue
        worker = threading.Thread(target=respond, daemon=True); worker.start()
        try:
            for index, user in enumerate(n["clients"]):
                socks_port = port()
                client = self.start(self.hysteria_client(n, user, socks_port), f"hy2-obfs-client-{index}")
                wait_port(socks_port, client)
                try:
                    self.assertIn(PAYLOAD, self.transfer(socks_port, origin))
                    self.udp_transfer(socks_port, echo.getsockname()[1], b"hysteria2-udp-echo" * 128)
                except (OSError, AssertionError) as error:
                    self.fail(str(error) + server.panel_log.read_text() + client.panel_log.read_text())
                finally:
                    client.terminate(); client.wait(timeout=5)
            for bad_user, bad_obfs in ((True, False), (False, True)):
                bad = copy.deepcopy(n)
                if bad_user:
                    bad["clients"][0]["secret"] += "-incorrect"
                if bad_obfs:
                    bad["obfs_password"] += "-incorrect"
                socks_port = port()
                client = self.start(self.hysteria_client(bad, bad["clients"][0], socks_port), f"hy2-rejected-{bad_user}")
                wait_port(socks_port, client)
                try:
                    try:
                        response = self.transfer(socks_port, origin, timeout=1)
                    except (OSError, AssertionError):
                        response = b""
                    self.assertNotIn(PAYLOAD, response)
                finally:
                    client.terminate(); client.wait(timeout=5)
        finally:
            stop.set(); worker.join(timeout=2); echo.close()
        time.sleep(.1)
        self.core.record_stats(query_stats(self.core.stats_port), "hy2-generation")
        for user in n["clients"]:
            self.assertGreater(self.core.usage()[user["id"]]["up"], 0)
            self.assertGreaterEqual(self.core.usage()[user["id"]]["down"], len(PAYLOAD))
        n["clients"][0]["quota_bytes"] = 1
        limited = self.core.compile(state, self.core.usage())["inbounds"][0]
        self.assertEqual([u["name"] for u in limited["users"]], [n["clients"][1]["id"] + "@personal-panel"])

    def test_all_protocols_multi_user_transfer_stats_and_legacy_reality(self):
        origin, https_origin = self.origin(), self.origin(tls=True)
        site_port = port()
        with (self.root / "site.log").open("wb") as output:
            site = subprocess.Popen([sys.executable, str(ROOT / "site_server.py")], env=dict(os.environ, PANEL_SITE_PORT=str(site_port), PANEL_TLS_DIR=str(self.root)), stdout=output, stderr=output)
        site.panel_log = self.root / "site.log"
        self.processes.append(site)
        wait_port(site_port, site)
        nodes = [self.sample(protocol) for protocol in ("shadowsocks2022", "trojan-tls", "vless-ws-tls", "vmess-ws-tls", "hysteria2", "vless-reality")]
        for n in nodes:
            extra = dict(n["clients"][0], id=str(uuid.uuid4()), name="second")
            if n["protocol"].startswith(("vless", "vmess")):
                extra["secret"] = str(uuid.uuid4())
            elif n["protocol"] in ("trojan-tls", "hysteria2"):
                extra["secret"] += "-second"
            else:
                import base64
                extra["secret"] = base64.b64encode(b"another-user-key").decode()
            n["clients"].append(extra)
            if n["protocol"] == "vless-reality":
                n["dest_port"] = site_port
        state = self.core.state()
        state["settings"]["block_private"] = False  # Loopback fixtures only.
        state["nodes"] = nodes
        with patch.dict(os.environ, PANEL_SITE_DOMAIN="example.com", PANEL_SITE_PORT=str(site_port)):
            config = self.core.compile(state)
        self.core.validate_config(config)
        server = self.start(config, "server")
        wait_port(self.core.stats_port, server)
        from ownsite import health
        health("example.com", nodes[-1]["port"], cafile=str(self.root / "fullchain.pem"))
        for n in nodes:
            for index, user in enumerate(n["clients"]):
                with self.subTest(protocol=n["protocol"], user=index):
                    socks_port = port()
                    hy2 = n["protocol"] == "hysteria2"
                    client = self.start(self.hysteria_client(n, user, socks_port) if hy2 else self.xray_client(n, user, socks_port),
                                        n["protocol"] + str(index), engine="sing-box" if hy2 else "xray")
                    wait_port(socks_port, client)
                    try:
                        self.assertIn(PAYLOAD, self.transfer(socks_port, origin))
                        if n["protocol"] == "vless-reality":
                            self.assertIn(PAYLOAD, self.transfer(socks_port, https_origin, tls=True))
                    except (OSError, AssertionError) as error:
                        self.fail(str(error) + server.panel_log.read_text() + client.panel_log.read_text())
                    finally:
                        client.terminate(); client.wait(timeout=5)
        reality = nodes[-1]
        # This exact no-ML-KEM profile was rejected by Xray 26.10.29. It must
        # authenticate and carry real HTTPS traffic with the replacement server.
        socks_port = port()
        client = self.start(self.xray_client(reality, reality["clients"][0], socks_port, "edge"), "legacy-client", engine="xray")
        wait_port(socks_port, client)
        self.assertIn(PAYLOAD, self.transfer(socks_port, https_origin, tls=True))
        client.terminate(); client.wait(timeout=5)
        socks_port = port()
        sb_client = {"inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}], "outbounds": [{
            "type": "vless", "server": "127.0.0.1", "server_port": reality["port"], "uuid": reality["clients"][0]["secret"], "flow": "xtls-rprx-vision",
            "tls": {"enabled": True, "server_name": reality["sni"], "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {"enabled": True, "public_key": reality["public_key"], "short_id": reality["short_id"]}}}]}
        client = self.start(sb_client, "singbox-client")
        wait_port(socks_port, client)
        self.assertIn(PAYLOAD, self.transfer(socks_port, https_origin, tls=True))
        client.terminate(); client.wait(timeout=5)
        time.sleep(.1)
        stats = query_stats(self.core.stats_port)
        self.core.record_stats(stats, "singbox-generation")
        for n in nodes:
            for user in n["clients"]:
                self.assertGreaterEqual(self.core.usage()[user["id"]]["down"], len(PAYLOAD))
        before = self.core.usage()
        self.core.record_stats(query_stats(self.core.stats_port), "singbox-generation")
        self.assertEqual(before, self.core.usage())
        reality["clients"][0]["quota_bytes"] = 1
        with patch.dict(os.environ, PANEL_SITE_DOMAIN="example.com", PANEL_SITE_PORT=str(site_port)):
            limited = self.core.compile(state, self.core.usage())
        self.assertEqual(len(limited["inbounds"][-1]["users"]), 1)

    def test_private_destinations_are_blocked_after_dns_resolution(self):
        origin = self.origin()
        n = self.sample("shadowsocks2022")
        state = self.core.state(); state["nodes"] = [n]
        config = self.core.compile(state)
        # A local DNS answer maps a public-looking domain to loopback.
        dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns.bind(("127.0.0.1", 0)); dns.settimeout(.1)
        stop = threading.Event()
        def respond():
            while not stop.is_set():
                try:
                    data, address = dns.recvfrom(4096)
                    answer = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + data[12:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
                    dns.sendto(answer, address)
                except socket.timeout:
                    continue
        worker = threading.Thread(target=respond, daemon=True); worker.start()
        config["dns"]["servers"][0].update(server="127.0.0.1", server_port=dns.getsockname()[1])
        server = self.start(config, "guard-server"); wait_port(n["port"], server)
        socks_port = port()
        client = self.start(self.xray_client(n, n["clients"][0], socks_port), "guard-client", engine="xray")
        wait_port(socks_port, client)
        try:
            for domain in (None, "fixture.example"):
                try:
                    response = self.transfer(socks_port, origin, domain=domain)
                except (ConnectionResetError, TimeoutError):
                    response = b""
                self.assertNotIn(PAYLOAD, response)
        finally:
            stop.set(); worker.join(timeout=2); dns.close()
