"""Root-only setup of an optional owned REALITY target. No web administration API."""
import argparse
import errno
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import sqlite3
import subprocess
import time

import h2.config
import h2.connection
import h2.events

from core import PanelError, host

SITE_ENV = Path("/etc/personal-panel/site.env")


def domain_name(value):
    domain = host(value)
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        if "." in domain:
            return domain
    raise PanelError("小站需要已解析到本机的完整域名，不能使用 IP 或通配符")


def port_available(port):
    sockets = []
    try:
        for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            try:
                listener = socket.socket(family, socket.SOCK_STREAM)
                sockets.append(listener)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind((address, port))
            except OSError as error:
                if family == socket.AF_INET6 and error.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL, errno.ENETUNREACH):
                    continue
                return False
        return True
    finally:
        for listener in sockets:
            listener.close()


def choose_port(requested, previous, active, reserved):
    candidates = [requested] if requested is not None else list(dict.fromkeys([previous, 443, 8443, 9443]))
    for port in candidates:
        if port is None or not 1 <= port <= 65535 or port in reserved:
            continue
        if (active and port == previous) or port_available(port):
            return port
    raise PanelError("小站端口已占用或与管理/统计端口冲突；可用 --port 指定其他端口。现有服务未被停止")


def health(domain, port, cafile=None):
    """Verify hostname, chain, TLS 1.3, ALPN h2 and a real HTTP/2 response locally."""
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2"])
    with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as conn:
            if conn.selected_alpn_protocol() != "h2":
                raise PanelError("小站未协商 HTTP/2")
            client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
            client.initiate_connection()
            client.send_headers(1, [(":method", "GET"), (":scheme", "https"), (":authority", domain), (":path", "/")], end_stream=True)
            conn.sendall(client.data_to_send())
            status, body = None, b""
            for _ in range(32):
                data = conn.recv(16384)
                if not data:
                    break
                for event in client.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        status = dict(event.headers).get(":status")
                    elif isinstance(event, h2.events.DataReceived):
                        body += event.data
                        client.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        if status == "200" and b"<!doctype html>" in body.lower():
                            return
                        raise PanelError("小站首页未通过 HTTP/2 检查")
                if len(body) > 128 * 1024:
                    break
                pending = client.data_to_send()
                if pending:
                    conn.sendall(pending)
    raise PanelError("小站未返回完整首页")


def wait_health(domain, port):
    for _ in range(12):
        try:
            health(domain, port)
            return
        except (OSError, PanelError):
            time.sleep(.25)
    raise PanelError("小站未通过 TLS 1.3 / HTTP/2 / 域名证书检查，请查看 personal-site 服务日志")


def check_existing_nodes(values, domain, port):
    database = Path(values.get("PANEL_DATA_DIR", "/var/lib/personal-panel")) / "panel.sqlite3"
    if not database.exists():
        return
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
        row = db.execute("SELECT body FROM state WHERE id=1").fetchone()
    for node in json.loads(row[0])["nodes"] if row else []:
        if not node["enabled"]:
            continue
        if node["port"] == port or (node["protocol"] == "vless-reality" and node["dest"] == domain and node["dest_port"] != port):
            raise PanelError("现有启用入站与小站端口/目标设置冲突；请先在面板调整或停用该入站，再创建小站。原节点未改动")


def setup(args, ops):
    ops.root_only()
    domain = domain_name(args.domain)
    values = ops.env_values(ops.PANEL_ENV)
    if not values:
        raise PanelError("请先安装 Personal Panel")
    old_site = SITE_ENV.read_bytes() if SITE_ENV.exists() else None
    old_panel = ops.PANEL_ENV.read_bytes()
    previous = ops.env_values(SITE_ENV)
    active = ops.service("is-active", "--quiet", "personal-site.service", check=False).returncode == 0
    from urllib.parse import urlsplit
    manager_port = urlsplit("//" + values.get("PANEL_BIND", "0.0.0.0:54322")).port or 54322
    port = choose_port(args.port, int(previous["PANEL_SITE_PORT"]) if previous else None, active,
                       {manager_port, int(values.get("PANEL_STATS_PORT", "18387"))})
    check_existing_nodes(values, domain, port)
    tls_dir = values.get("PANEL_TLS_DIR", "/var/lib/personal-panel-tls")
    if tls_dir != "/var/lib/personal-panel-tls":
        raise PanelError("小站目前使用安装器管理的标准证书目录")
    # DNS-01 doesn't need port 80. Credentials remain exclusive to the ACME job.
    ops.certificate(argparse.Namespace(domain=domain, panel_https=False, replace_token=False))
    try:
        ops.atomic_write(SITE_ENV, f"PANEL_SITE_DOMAIN={domain}\nPANEL_SITE_PORT={port}\nPANEL_TLS_DIR={tls_dir}\n", 0o600)
        ops.service("enable", "personal-site.service")
        ops.service("restart", "personal-site.service")
        wait_health(domain, port)
        values.update(PANEL_SITE_DOMAIN=domain, PANEL_SITE_PORT=str(port))
        if getattr(args, "panel_https", False):
            values.update(PANEL_TLS="on", PANEL_PUBLIC_ADDRESS=domain)
        hosts = values.get("PANEL_ALLOWED_HOSTS", "").split(",")
        values["PANEL_ALLOWED_HOSTS"] = ",".join(dict.fromkeys(h for h in hosts + [domain] if h))
        ops.atomic_write(ops.PANEL_ENV, "".join(f"{k}={v}\n" for k, v in values.items()), 0o600)
        ops.service("restart", "personal-panel.service")
        ops.panel_health(ops.AccessPolicy.from_env(values))
    except (OSError, PanelError, subprocess.SubprocessError):
        ops.atomic_write(ops.PANEL_ENV, old_panel, 0o600)
        if old_site is None:
            SITE_ENV.unlink(missing_ok=True)
            ops.service("disable", "--now", "personal-site.service", check=False)
        else:
            ops.atomic_write(SITE_ENV, old_site, 0o600)
            if active:
                ops.service("restart", "personal-site.service", check=False)
            else:
                ops.service("stop", "personal-site.service", check=False)
        ops.service("restart", "personal-panel.service", check=False)
        raise PanelError("小站设置未完成，已恢复原面板与小站设置；已签发的证书保留，可修复后重试") from None
    print(ops.open_management_firewall(port))
    suffix = "" if port == 443 else f":{port}"
    print(f"小站已启用：https://{domain}{suffix}/ （TLS 1.3 / HTTP/2 本机检查通过）")
    print(f"新建 REALITY 自动填写：SNI={domain}，目标域名={domain}，目标端口={port}。入站端口请使用其他端口。")
    print("证书定时续签并自动通知网站及已启用 HTTPS 的面板加载。")
    if getattr(args, "panel_https", False):
        ops.show_access(values)
        print("请使用上方 HTTPS 域名地址登录面板，再创建节点；管理端口和访问范围已保留。")
