"""Opt-in tests against the real, checksum-verified official Xray binary.

XRAY_TEST_BINARY=/absolute/path/to/xray python -m unittest discover -s tests -v
All connections stay on loopback; no public certificate or external proxy is used.
"""
import copy
import http.server
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from core import Core, PanelError, clean_node, xray_config
from test_panel import node

BINARY = os.environ.get("XRAY_TEST_BINARY")


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(p, process):
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError("Xray exited before listening: " + process.panel_log.read_text())
        try:
            with socket.create_connection(("127.0.0.1", p), timeout=.1):
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError("Xray did not listen")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"private-panel-data-plane-ok" * 128
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


@unittest.skipUnless(BINARY, "set XRAY_TEST_BINARY for real core integration")
class XrayIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.core = Core(root / "data", root / "xray", binary=BINARY, tls_dir=str(root), stats_port=port())
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=example.com", "-addext", "subjectAltName=DNS:example.com",
                        "-keyout", str(root / "key.pem"), "-out", str(root / "fullchain.pem")],
                       capture_output=True, check=True)
        self.processes = []

    def tearDown(self):
        for process in self.processes:
            process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        self.tmp.cleanup()

    def sample(self, protocol):
        n = node(protocol, port())
        n["listen"] = "127.0.0.1"
        if protocol == "vless-reality":
            n.update(self.core.keypair())
        return clean_node(n)

    def test_all_generated_protocols_accepted_by_real_core(self):
        protocols = ("vless-reality", "vless-ws-tls", "vmess-ws-tls", "trojan-tls", "shadowsocks2022")
        nodes = [self.sample(p) for p in protocols]
        # Verify multiple users on one port as well as all stream settings.
        import uuid
        for n in nodes:
            extra = dict(n["clients"][0], id=str(uuid.uuid4()), name="second")
            if n["protocol"].startswith(("vless", "vmess")):
                extra["secret"] = str(uuid.uuid4())
            n["clients"].append(extra)
        self.core.apply(lambda s: dict(s, nodes=nodes))
        config = json.loads((self.core.config_dir / "config.json").read_text())
        self.assertEqual(len(config["inbounds"]), 6)

    def test_mismatched_reality_pair_and_wrong_tls_sni_rejected(self):
        n = self.sample("vless-reality")
        n["public_key"] = self.core.keypair()["public_key"]
        with self.assertRaisesRegex(PanelError, "不匹配"):
            self.core.apply(lambda s: dict(s, nodes=[n]))
        n = self.sample("trojan-tls")
        n["sni"] = "other.example.com"
        with self.assertRaisesRegex(PanelError, "未被当前证书覆盖"):
            self.core.apply(lambda s: dict(s, nodes=[n]))
        self.assertEqual(self.core.state()["nodes"], [])

    def test_occupied_new_port_rejected_before_mutation(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            n = self.sample("shadowsocks2022")
            n["port"] = listener.getsockname()[1]
            with self.assertRaisesRegex(PanelError, "不可绑定"):
                self.core.apply(lambda s: dict(s, nodes=[n]))
        self.assertEqual(self.core.state()["nodes"], [])

    def start(self, config, name):
        path = Path(self.tmp.name) / (name + ".json")
        path.write_text(json.dumps(config))
        log = open(Path(self.tmp.name) / (name + ".log"), "wb")
        process = subprocess.Popen([BINARY, "run", "-config", str(path)], stdout=log, stderr=log)
        process.panel_log = Path(self.tmp.name) / (name + ".log")
        log.close()
        self.processes.append(process)
        return process

    def test_real_data_plane_and_per_user_accounting(self):
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=httpd.serve_forever, daemon=True)
        worker.start()
        try:
            for protocol in ("shadowsocks2022", "trojan-tls", "vless-ws-tls", "vmess-ws-tls"):
                with self.subTest(protocol=protocol):
                    n = self.sample(protocol)
                    state = self.core.state()
                    state["settings"]["block_private"] = False  # Only for loopback fixtures.
                    state["settings"]["loglevel"] = "info"
                    state["nodes"] = [n]
                    server_config = xray_config(state, stats_port=self.core.stats_port, tls_dir=self.core.tls_dir)
                    self.core.validate_config(server_config)
                    server = self.start(server_config, "server-" + protocol)
                    wait_port(n["port"], server)
                    socks_port = port()
                    c = n["clients"][0]
                    outbound = {"protocol": protocol.split("-")[0], "settings": {"servers": []}}
                    server_entry = {"address": "127.0.0.1", "port": n["port"]}
                    if protocol == "shadowsocks2022":
                        outbound["protocol"] = "shadowsocks"
                        server_entry.update({"method": "2022-blake3-aes-128-gcm", "password": n["server_key"] + ":" + c["secret"]})
                    elif protocol == "trojan-tls":
                        server_entry["password"] = c["secret"]
                    else:
                        outbound["settings"] = {"vnext": [dict(server_entry, users=[{"id": c["secret"], "encryption": "none"}])]}
                    if "servers" in outbound["settings"]:
                        outbound["settings"]["servers"] = [server_entry]
                    if protocol != "shadowsocks2022":
                        outbound["streamSettings"] = {"security": "tls", "network": "tcp", "tlsSettings": {"serverName": "example.com", "disableSystemRoot": True,
                            "certificates": [{"usage": "verify", "certificateFile": str(Path(self.tmp.name) / "fullchain.pem")} ]}}
                        if "ws" in protocol:
                            outbound["streamSettings"].update({"network": "ws", "wsSettings": {"path": n["path"], "host": "example.com"}})
                    client_config = {"log": {"loglevel": "error"}, "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"auth": "noauth"}}], "outbounds": [outbound]}
                    client = self.start(client_config, "client-" + protocol)
                    wait_port(socks_port, client)
                    with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as s:
                        s.settimeout(8)
                        s.sendall(b"\x05\x01\x00")
                        self.assertEqual(s.recv(2), b"\x05\x00")
                        s.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", httpd.server_port))
                        reply = s.recv(10)
                        self.assertEqual(reply[:2], b"\x05\x00")
                        s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                        response = b""
                        while True:
                            try:
                                chunk = s.recv(65536)
                            except TimeoutError:
                                self.fail("Proxy read timed out: " + repr(response[:200]) + server.panel_log.read_text() + client.panel_log.read_text())
                            if not chunk:
                                break
                            response += chunk
                            if response.count(b"private-panel-data-plane-ok") >= 128:
                                break
                    self.assertIn(b"private-panel-data-plane-ok", response)
                    time.sleep(.1)
                    stats = subprocess.run([BINARY, "api", "statsquery", f"--server=127.0.0.1:{self.core.stats_port}", "-pattern", "user>>>"], capture_output=True, text=True, check=True, timeout=5)
                    self.core.record_stats(json.loads(stats.stdout).get("stat", []), protocol)
                    self.assertGreater(self.core.usage()[c["id"]]["down"], 0)
                    # An over-quota user must disappear from the next compiled config.
                    n["clients"][0]["quota_bytes"] = 1
                    limited = xray_config(state, self.core.usage(), stats_port=self.core.stats_port, tls_dir=self.core.tls_dir)
                    self.assertEqual(len(limited["inbounds"]), 1)
                    server.terminate(); client.terminate()
                    server.wait(timeout=5); client.wait(timeout=5)
        finally:
            httpd.shutdown()
            httpd.server_close()
            worker.join(timeout=2)
