"""Personal Panel: validated state, Xray configuration and durable accounting.

New implementation. No legacy x-ui database or binaries are loaded.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import time
import uuid
from urllib.parse import quote, urlencode

VERSION = "0.2.0"
PROTOCOLS = ("vless-reality", "vless-ws-tls", "vmess-ws-tls", "trojan-tls", "shadowsocks2022")
DEFAULT_SETTINGS = {"public_address": "", "ipv4_only": True, "block_private": True, "loglevel": "warning"}
PRIVATE_IPS = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
               "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
               "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"]


class PanelError(ValueError):
    pass


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".panel-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data.encode() if isinstance(data, str) else data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        dirfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def text(value, name, limit=200, empty=False):
    if not isinstance(value, str) or (not empty and not value) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise PanelError(f"{name}格式不正确")
    return value


def host(value, empty=False):
    value = text(value, "域名或 IP", 253, empty).strip().strip("[]")
    if not value and empty:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", value):
            raise PanelError("域名或 IP 格式不正确") from None
        return value.lower()


def integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise PanelError(f"{name}必须在 {low}–{high} 之间")
    return value


def boolean(value, name):
    if type(value) is not bool:
        raise PanelError(f"{name}必须为布尔值")
    return value


def uid(value):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise PanelError("ID 必须为 UUID") from None


def b64key(value, size=32):
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        if len(raw) != size:
            raise ValueError()
    except (ValueError, TypeError):
        raise PanelError(f"密钥必须为 {size} 字节 Base64") from None
    return value


def clean_node(data):
    if not isinstance(data, dict):
        raise PanelError("入站格式不正确")
    protocol = data.get("protocol")
    if protocol not in PROTOCOLS:
        raise PanelError("不支持的协议")
    try:
        listen = str(ipaddress.ip_address(data.get("listen", "::")))
    except ValueError:
        raise PanelError("监听地址必须是 IP") from None
    n = {"id": uid(data.get("id", str(uuid.uuid4()))),
         "name": text(data.get("name", "新入站"), "名称", 80),
         "protocol": protocol, "listen": listen,
         "port": integer(data.get("port"), "端口", 1, 65535),
         "enabled": boolean(data.get("enabled", True), "启用状态"),
         "address": host(data.get("address", ""), empty=True)}
    if protocol == "vless-reality":
        n["sni"] = host(data.get("sni", ""))
        n["dest"] = host(data.get("dest", n["sni"]))
        n["dest_port"] = integer(data.get("dest_port", 443), "目标端口", 1, 65535)
        n["private_key"] = b64key(data.get("private_key", ""))
        n["public_key"] = b64key(data.get("public_key", ""))
        n["short_id"] = text(data.get("short_id", ""), "Short ID", 16)
        if not re.fullmatch(r"(?:[0-9a-f]{2}){1,8}", n["short_id"]):
            raise PanelError("Short ID 需要 2–16 位偶数长度的小写十六进制")
    elif protocol != "shadowsocks2022":
        n["sni"] = host(data.get("sni", ""))
    if "ws" in protocol:
        n["path"] = text(data.get("path", "/ws"), "WebSocket 路径", 200)
        if not n["path"].startswith("/") or "?" in n["path"] or "#" in n["path"]:
            raise PanelError("WebSocket 路径需以 / 开头且不含查询串")
    if protocol == "shadowsocks2022":
        n["server_key"] = b64key(data.get("server_key", ""), 16)
    clients = data.get("clients", [])
    if not isinstance(clients, list) or not 1 <= len(clients) <= 200:
        raise PanelError("每个入站需要 1–200 个用户")
    n["clients"] = []
    for c in clients:
        if not isinstance(c, dict):
            raise PanelError("用户格式不正确")
        password = text(c.get("secret", ""), "用户密钥", 128)
        if protocol.startswith(("vless", "vmess")):
            password = uid(password)
        elif protocol == "shadowsocks2022":
            password = b64key(password, 16)
        elif len(password) < 16:
            raise PanelError("Trojan 密码至少 16 字符")
        n["clients"].append({"id": uid(c.get("id", str(uuid.uuid4()))),
                             "name": text(c.get("name", "用户"), "用户名称", 80), "secret": password,
                             "enabled": boolean(c.get("enabled", True), "用户启用状态"),
                             "expires_at": integer(c.get("expires_at", 0), "到期时间", 0, 253402300799),
                             "quota_bytes": integer(c.get("quota_bytes", 0), "流量上限", 0, 10**18)})
    return n


def clean_state(data, stats_port=18387):
    if not isinstance(data, dict) or not isinstance(data.get("nodes"), list) or len(data["nodes"]) > 100:
        raise PanelError("备份或状态格式不正确（最多 100 个入站）")
    raw = data.get("settings", {})
    if not isinstance(raw, dict):
        raise PanelError("设置格式不正确")
    settings = dict(DEFAULT_SETTINGS, **{k: v for k, v in raw.items() if k in DEFAULT_SETTINGS})
    settings["public_address"] = host(settings["public_address"], empty=True)
    boolean(settings["ipv4_only"], "IPv4 出站")
    boolean(settings["block_private"], "内网保护")
    if settings["loglevel"] not in ("warning", "error", "info"):
        raise PanelError("日志等级不正确")
    nodes = [clean_node(n) for n in data["nodes"]]
    ids, ports, client_ids = set(), set(), set()
    for n in nodes:
        if n["id"] in ids or n["port"] in ports or n["port"] == stats_port:
            raise PanelError("入站 ID 或端口重复，或与统计端口冲突")
        ids.add(n["id"])
        ports.add(n["port"])
        for c in n["clients"]:
            if c["id"] in client_ids:
                raise PanelError("用户 ID 重复")
            client_ids.add(c["id"])
    return {"settings": settings, "nodes": nodes}


def active_client(c, usage, now):
    u = usage.get(c["id"], {})
    return c["enabled"] and (not c["expires_at"] or c["expires_at"] > now) and (
        not c["quota_bytes"] or u.get("up", 0) + u.get("down", 0) < c["quota_bytes"])


def xray_config(state, usage=None, now=None, stats_port=18387, tls_dir="/var/lib/personal-panel-tls"):
    usage, now = usage or {}, time.time() if now is None else now
    settings = state["settings"]
    config = {"log": {"loglevel": settings["loglevel"]},
              "stats": {}, "api": {"tag": "panel-api", "services": ["StatsService"]},
              "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
              "dns": {"servers": ["1.1.1.1", "8.8.8.8"],
                      "queryStrategy": "UseIPv4" if settings["ipv4_only"] else "UseIP"},
              "inbounds": [{"tag": "panel-api-in", "listen": "127.0.0.1", "port": stats_port,
                            "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}}],
              "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}},
                            {"tag": "block", "protocol": "blackhole", "settings": {}}],
              "routing": {"domainStrategy": "IPOnDemand", "rules": [
                  {"type": "field", "inboundTag": ["panel-api-in"], "outboundTag": "panel-api"}]}}
    if settings["ipv4_only"]:
        config["outbounds"][0].update({"sendThrough": "0.0.0.0", "streamSettings": {
            "sockopt": {"domainStrategy": "ForceIPv4"}}})
        config["routing"]["rules"].append({"type": "field", "ip": ["::/0"], "outboundTag": "block"})
    if settings["block_private"]:
        config["routing"]["rules"].append({"type": "field", "ip": PRIVATE_IPS, "outboundTag": "block"})
        # Enforce again after DNS resolution, including DNS rebinding targets.
        config["outbounds"][0]["settings"]["finalRules"] = [{"action": "block", "ip": PRIVATE_IPS, "blockDelay": "0-0"}]
    else:
        # Current Xray also blocks private destinations by default. Make the UI
        # switch explicit rather than leaving that hidden default in effect.
        config["outbounds"][0]["settings"]["finalRules"] = [{"action": "allow", "ip": ["0.0.0.0/0", "::/0"]}]
    for n in state["nodes"]:
        clients = [c for c in n["clients"] if active_client(c, usage, now)]
        if not n["enabled"] or not clients:
            continue
        protocol = n["protocol"].split("-")[0]
        inbound = {"tag": n["id"], "listen": n["listen"], "port": n["port"], "protocol": protocol,
                   "settings": {"clients": []}, "streamSettings": {"network": "tcp"}}
        for c in clients:
            entry = {"email": c["id"] + "@personal-panel", "level": 0}
            entry["id" if protocol in ("vless", "vmess") else "password"] = c["secret"]
            if n["protocol"] == "vless-reality":
                entry["flow"] = "xtls-rprx-vision"
            inbound["settings"]["clients"].append(entry)
        if protocol == "vless":
            inbound["settings"]["decryption"] = "none"
        if n["protocol"] == "shadowsocks2022":
            inbound["protocol"] = "shadowsocks"
            inbound["settings"].update({"method": "2022-blake3-aes-128-gcm", "password": n["server_key"], "network": "tcp,udp"})
        elif n["protocol"] == "vless-reality":
            dest = f"[{n['dest']}]" if ":" in n["dest"] else n["dest"]
            inbound["streamSettings"].update({"security": "reality", "realitySettings": {
                "show": False, "target": f"{dest}:{n['dest_port']}", "xver": 0,
                "serverNames": [n["sni"]], "privateKey": n["private_key"], "shortIds": [n["short_id"]]}})
        else:
            inbound["streamSettings"].update({"security": "tls", "tlsSettings": {
                "minVersion": "1.2", "certificates": [{"certificateFile": tls_dir + "/fullchain.pem",
                                                         "keyFile": tls_dir + "/key.pem"}]}})
            if "ws" in n["protocol"]:
                inbound["streamSettings"].update({"network": "ws", "wsSettings": {"path": n["path"]}})
        config["inbounds"].append(inbound)
    return config


def share_link(n, c, default_address):
    address = n["address"] or default_address
    if not address:
        raise PanelError("请先设置分享地址（公网 IP 或域名）")
    address = f"[{address}]" if ":" in address else address
    label = n["name"] + " / " + c["name"]
    if n["protocol"] == "shadowsocks2022":
        auth = base64.urlsafe_b64encode(f"2022-blake3-aes-128-gcm:{n['server_key']}:{c['secret']}".encode()).decode().rstrip("=")
        return f"ss://{auth}@{address}:{n['port']}#{quote(label)}"
    if n["protocol"].startswith("vmess"):
        body = {"v": "2", "ps": label, "add": n["address"] or default_address, "port": str(n["port"]),
                "id": c["secret"], "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": n["sni"],
                "path": n["path"], "tls": "tls", "sni": n["sni"]}
        return "vmess://" + base64.b64encode(json.dumps(body, ensure_ascii=False).encode()).decode()
    params = {"security": "tls", "sni": n["sni"], "type": "ws" if "ws" in n["protocol"] else "tcp"}
    if n["protocol"].startswith("vless"):
        params["encryption"] = "none"
    if "ws" in n["protocol"]:
        params.update({"path": n["path"], "host": n["sni"]})
    if n["protocol"] == "vless-reality":
        params.update({"security": "reality", "flow": "xtls-rprx-vision", "fp": "chrome", "pbk": n["public_key"], "sid": n["short_id"]})
    return f"{n['protocol'].split('-')[0]}://{quote(c['secret'], safe='')}@{address}:{n['port']}?{urlencode(params)}#{quote(label)}"


class Core:
    def __init__(self, data_dir=None, config_dir=None, binary=None, tls_dir=None, stats_port=None, test_mode=False):
        self.data = Path(data_dir or os.environ.get("PANEL_DATA_DIR", "/var/lib/personal-panel"))
        self.config_dir = Path(config_dir or os.environ.get("PANEL_XRAY_DIR", "/var/lib/personal-xray"))
        self.binary = str(binary or os.environ.get("PANEL_XRAY_BINARY", "/opt/personal-panel/core/xray"))
        self.tls_dir = str(tls_dir or os.environ.get("PANEL_TLS_DIR", "/var/lib/personal-panel-tls"))
        self.stats_port = int(stats_port or os.environ.get("PANEL_STATS_PORT", "18387"))
        self.test_mode = test_mode
        for d in (self.data, self.config_dir):
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db_path = self.data / "panel.sqlite3"
        with self.db() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS admin(id INTEGER PRIMARY KEY CHECK(id=1),username TEXT, password_hash TEXT);
                CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,csrf TEXT,expires REAL);
                CREATE TABLE IF NOT EXISTS attempts(ip TEXT,at REAL);
                CREATE TABLE IF NOT EXISTS usage(client_id TEXT PRIMARY KEY,up INTEGER DEFAULT 0,down INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER,generation TEXT);
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at REAL,action TEXT);
            """)
            db.execute("INSERT OR IGNORE INTO state VALUES(1,?)", (json.dumps({"settings": DEFAULT_SETTINGS, "nodes": []}),))
        os.chmod(self.db_path, 0o600)

    @contextlib.contextmanager
    def db(self):
        db = sqlite3.connect(self.db_path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @contextlib.contextmanager
    def lock(self):
        with open(self.data / "mutation.lock", "a", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            yield

    def state(self):
        with self.db() as db:
            return json.loads(db.execute("SELECT body FROM state WHERE id=1").fetchone()[0])

    def usage(self):
        with self.db() as db:
            return {r["client_id"]: {"up": r["up"], "down": r["down"]} for r in db.execute("SELECT * FROM usage")}

    def audit(self, action):
        with self.db() as db:
            db.execute("INSERT INTO audit(at,action) VALUES(?,?)", (time.time(), action))
            db.execute("DELETE FROM audit WHERE id <= (SELECT coalesce(max(id),0)-500 FROM audit)")

    def validate_config(self, config):
        content = json.dumps(config, indent=2)
        if self.test_mode:
            return content
        fd, path = tempfile.mkstemp(prefix="validate-", suffix=".json", dir=self.config_dir)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            try:
                result = subprocess.run([self.binary, "run", "-test", "-config", path], capture_output=True, text=True, timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                raise PanelError("Xray 配置校验未完成，请检查核心安装及证书") from None
            if result.returncode:
                # Do not send core output, which can contain paths or credentials, to browsers.
                raise PanelError("Xray 拒绝该配置，请检查协议参数、密钥及 TLS 证书；原配置未改动")
            return content
        finally:
            os.unlink(path)

    def apply(self, transform, action="更新配置", imported_usage=None):
        with self.lock():
            self.collect_stats()
            current = self.state()
            state = clean_state(transform(copy.deepcopy(current)), self.stats_port)
            usage = self.usage() if imported_usage is None else imported_usage
            if not self.test_mode:
                self.check_materials(state, usage)
                self.check_new_ports(current, state, usage)
            content = self.validate_config(xray_config(state, usage, stats_port=self.stats_port, tls_dir=self.tls_dir))
            # Commit desired state first. A failed disk write is reconciled by the timer.
            previous = json.dumps({"format": "personal-panel-v1", "state": current, "usage": self.usage()})
            atomic_write(self.data / "previous.json", previous)
            with self.db() as db:
                db.execute("UPDATE state SET body=? WHERE id=1", (json.dumps(state),))
                if imported_usage is not None:
                    db.execute("DELETE FROM usage")
                    db.executemany("INSERT INTO usage VALUES(?,?,?)", [(k, v["up"], v["down"]) for k, v in usage.items()])
            self.write_config(content)
            self.audit(action)
        return state

    def check_materials(self, state, usage):
        import ssl
        certificate = None
        for n in state["nodes"]:
            if not n["enabled"] or not any(active_client(c, usage, time.time()) for c in n["clients"]):
                continue
            if n["protocol"] == "vless-reality":
                private = base64.b64decode(n["private_key"] + "=" * (-len(n["private_key"]) % 4), altchars=b"-_")
                public = base64.b64decode(n["public_key"] + "=" * (-len(n["public_key"]) % 4), altchars=b"-_")
                # PKCS#8 X25519: send the private material over stdin, never argv.
                try:
                    result = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                                            input=bytes.fromhex("302e020100300506032b656e04220420") + private,
                                            capture_output=True, timeout=5, check=True)
                except (OSError, subprocess.SubprocessError):
                    raise PanelError("REALITY 密钥检查失败") from None
                if result.stdout[-32:] != public:
                    raise PanelError("REALITY 公钥与私钥不匹配，请重新生成密钥对")
            elif n["protocol"] != "shadowsocks2022":
                try:
                    if certificate is None:
                        certificate = ssl._ssl._test_decode_cert(self.tls_dir + "/fullchain.pem")
                    matches = [v.lower() for k, v in certificate.get("subjectAltName", []) if k == "DNS"]
                    sni = n["sni"].lower()
                    if not any(sni == v or (v.startswith("*.") and sni.split(".", 1)[-1] == v[2:] and sni.count(".") == v.count(".")) for v in matches):
                        raise PanelError("TLS 入站 SNI 未被当前证书覆盖")
                    if ssl.cert_time_to_seconds(certificate["notAfter"]) <= time.time():
                        raise PanelError("TLS 证书已过期，请先续签")
                except PanelError:
                    raise
                except (OSError, ValueError, ssl.SSLError):
                    raise PanelError("请先通过 panelctl cert 配置可用的 TLS 证书") from None

    def check_new_ports(self, current, state, usage):
        def live(n):
            return n["enabled"] and any(active_client(c, usage, time.time()) for c in n["clients"])
        old_tcp = {(n["listen"], n["port"]) for n in current["nodes"] if live(n)}
        old_udp = {(n["listen"], n["port"]) for n in current["nodes"] if live(n) and n["protocol"] == "shadowsocks2022"}
        for n in state["nodes"]:
            if not live(n):
                continue
            for kind, old in ((socket.SOCK_STREAM, old_tcp), (socket.SOCK_DGRAM, old_udp)):
                if kind == socket.SOCK_DGRAM and n["protocol"] != "shadowsocks2022":
                    continue
                if (n["listen"], n["port"]) in old:
                    continue
                try:
                    with socket.socket(socket.AF_INET6 if ":" in n["listen"] else socket.AF_INET, kind) as check:
                        check.bind((n["listen"], n["port"]))
                except OSError as error:
                    if n["port"] < 1024 and error.errno in (errno.EACCES, errno.EPERM):
                        # Only the separate Xray unit has CAP_NET_BIND_SERVICE.
                        continue
                    raise PanelError(f"端口 {n['port']} 不可绑定，请检查端口占用、监听 IP 以及低端口权限") from None

    def write_config(self, content):
        path = self.config_dir / "config.json"
        if not path.exists() or path.read_text() != content:
            if path.exists():
                atomic_write(self.config_dir / "config.previous.json", path.read_bytes())
            atomic_write(path, content)
            atomic_write(self.config_dir / "reload.trigger", str(time.time_ns()))

    def backup(self):
        with self.lock():
            return {"format": "personal-panel-v1", "created_at": int(time.time()), "state": self.state(), "usage": self.usage()}

    def restore(self, data):
        if not isinstance(data, dict) or data.get("format") != "personal-panel-v1":
            raise PanelError("只支持 Personal Panel v1 JSON 备份，不能导入旧 x-ui 数据库")
        state = clean_state(data.get("state"), self.stats_port)
        raw = data.get("usage", {})
        if not isinstance(raw, dict) or len(raw) > 20000:
            raise PanelError("流量备份格式不正确")
        usage = {}
        for k, v in raw.items():
            if not isinstance(v, dict):
                raise PanelError("流量备份格式不正确")
            usage[uid(k)] = {"up": integer(v.get("up", 0), "上传量", 0, 10**18),
                             "down": integer(v.get("down", 0), "下载量", 0, 10**18)}
        return self.apply(lambda _: state, "恢复备份", imported_usage=usage)

    def keypair(self):
        try:
            result = subprocess.run([self.binary, "x25519"], text=True, capture_output=True, timeout=5, check=True)
            private = re.search(r"PrivateKey:\s*(\S+)", result.stdout)[1]
            public = re.search(r"(?:PublicKey|Password(?: \(PublicKey\))?):\s*(\S+)", result.stdout)[1]
            return {"private_key": b64key(private), "public_key": b64key(public), "short_id": secrets.token_hex(8)}
        except (OSError, subprocess.SubprocessError, TypeError):
            raise PanelError("密钥生成失败，请检查 Xray 核心") from None

    def collect_stats(self):
        if self.test_mode:
            return
        try:
            pid = subprocess.run(["systemctl", "show", "personal-xray.service", "--property=MainPID", "--value"],
                                 capture_output=True, text=True, timeout=3, check=True).stdout.strip()
            start = Path(f"/proc/{int(pid)}/stat").read_text().rsplit(")", 1)[1].split()[19]
            generation = Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + pid + ":" + start
            result = subprocess.run([self.binary, "api", "statsquery", f"--server=127.0.0.1:{self.stats_port}", "-pattern", "user>>>"],
                                    capture_output=True, text=True, timeout=5, check=True)
            stats = json.loads(result.stdout).get("stat", [])
            self.record_stats(stats, generation)
        except (OSError, ValueError, subprocess.SubprocessError, IndexError):
            with self.db() as db:
                db.execute("INSERT OR REPLACE INTO meta VALUES('stats_error',?)", (str(int(time.time())),))

    def record_stats(self, stats, generation):
        with self.db() as db:
            for s in stats:
                m = re.fullmatch(r"user>>>([0-9a-f-]{36})@personal-panel>>>traffic>>>(uplink|downlink)", s.get("name", ""))
                if not m:
                    continue
                value = int(s.get("value", 0))
                if value < 0:
                    continue
                old = db.execute("SELECT value,generation FROM counters WHERE name=?", (s["name"],)).fetchone()
                before = old["value"] if old and old["generation"] == generation else 0
                delta = value - before if value >= before else value
                column = "up" if m[2] == "uplink" else "down"
                db.execute("INSERT OR IGNORE INTO usage(client_id) VALUES(?)", (m[1],))
                db.execute(f"UPDATE usage SET {column}={column}+? WHERE client_id=?", (delta, m[1]))
                db.execute("INSERT OR REPLACE INTO counters VALUES(?,?,?)", (s["name"], value, generation))
            db.execute("INSERT OR REPLACE INTO meta VALUES('stats_success',?)", (str(int(time.time())),))
            db.execute("DELETE FROM meta WHERE key='stats_error'")

    def maintain(self):
        with self.lock():
            self.collect_stats()
            config = xray_config(self.state(), self.usage(), stats_port=self.stats_port, tls_dir=self.tls_dir)
            content = json.dumps(config, indent=2)
            path = self.config_dir / "config.json"
            if not path.exists() or path.read_text() != content:
                self.write_config(self.validate_config(config))
            with self.db() as db:
                db.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
                db.execute("DELETE FROM attempts WHERE at < ?", (time.time() - 900,))
            backups = self.data / "auto-backups"
            backups.mkdir(mode=0o700, exist_ok=True)
            today = backups / (time.strftime("%Y-%m-%d", time.gmtime()) + ".json")
            if not today.exists():
                atomic_write(today, json.dumps({"format": "personal-panel-v1", "created_at": int(time.time()),
                                               "state": self.state(), "usage": self.usage()}))
                for stale in sorted(backups.glob("????-??-??.json"))[:-7]:
                    stale.unlink()

    def status(self):
        try:
            version = subprocess.run([self.binary, "version"], capture_output=True, text=True, timeout=3).stdout.splitlines()[0]
            running = subprocess.run(["systemctl", "is-active", "personal-xray.service"], capture_output=True, text=True, timeout=3).stdout.strip()
        except (OSError, IndexError, subprocess.TimeoutExpired):
            version, running = "未安装", "unknown"
        with self.db() as db:
            meta = {r["key"]: r["value"] for r in db.execute("SELECT * FROM meta")}
            audit = [dict(r) for r in db.execute("SELECT at,action FROM audit ORDER BY id DESC LIMIT 10")]
        cert = {"present": False}
        try:
            import ssl
            parsed = ssl._ssl._test_decode_cert(self.tls_dir + "/fullchain.pem")
            expires = ssl.cert_time_to_seconds(parsed["notAfter"])
            cert = {"present": True, "expires_at": expires, "days_left": int((expires - time.time()) / 86400),
                    "names": [v for k, v in parsed.get("subjectAltName", []) if k == "DNS"]}
        except (OSError, ValueError, ssl.SSLError):
            pass
        return {"version": VERSION, "core": version, "core_status": running,
                "stats": meta, "certificate": cert, "audit": audit}
