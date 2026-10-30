#!/usr/bin/env python3
"""Local-only administration. Privileged operations are never exposed to the web API."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen
import zipfile

from werkzeug.security import generate_password_hash
from core import Core, PanelError, atomic_write, host

ROOT = Path(__file__).resolve().parent
INSTALL = Path("/opt/personal-panel")


def root_only():
    if os.geteuid() != 0:
        raise PanelError("此操作需要 sudo / root")


def download(url, limit=100 * 1024 * 1024):
    if not url.startswith("https://"):
        raise PanelError("下载地址必须使用 HTTPS")
    with urlopen(Request(url, headers={"User-Agent": "zbklk-personal-panel/0.1"}), timeout=60) as response:
        if not response.geturl().startswith("https://"):
            raise PanelError("拒绝非 HTTPS 下载重定向")
        content = response.read(limit + 1)
    if len(content) > limit:
        raise PanelError("下载内容超过大小限制")
    return content


def service(*args, check=True):
    return subprocess.run(["systemctl", *args], check=check, capture_output=True, text=True, timeout=90)


def check_core(path):
    user = pwd.getpwnam("personal-panel")
    permissions = {"user": user.pw_uid, "group": user.pw_gid, "extra_groups": [], "umask": 0o077}
    subprocess.run([str(path), "version"], capture_output=True, check=True, timeout=10, **permissions)
    config = Path(os.environ.get("PANEL_XRAY_DIR", "/var/lib/personal-xray")) / "config.json"
    if config.exists():
        result = subprocess.run([str(path), "run", "-test", "-config", str(config)], capture_output=True, timeout=15, **permissions)
        if result.returncode:
            raise PanelError("新核心无法通过现有配置校验，已保留原核心")


def core_install(args):
    root_only()
    folder = INSTALL / "core"
    folder.mkdir(mode=0o755, exist_ok=True)
    arch = {"x86_64": "Xray-linux-64.zip", "aarch64": "Xray-linux-arm64-v8a.zip"}.get(platform.machine())
    if not arch:
        raise PanelError("目前只支持 Linux amd64 / arm64")
    if args.action == "install":
        metadata = json.loads((ROOT / "upstream.json").read_text())["xray"]
    else:
        metadata = json.loads(download("https://api.github.com/repos/XTLS/Xray-core/releases/latest", 2 * 1024 * 1024))
    asset = next((a for a in metadata["assets"] if a["name"] == arch), None)
    if not asset or not re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest", "")):
        raise PanelError("上游未提供有效 SHA-256，拒绝安装")
    expected = asset["digest"].split(":")[1]
    blob = download(asset["browser_download_url"])
    if hashlib.sha256(blob).hexdigest() != expected:
        raise PanelError("Xray 下载的 SHA-256 不匹配，拒绝安装")
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        info = archive.getinfo("xray")
        if info.file_size > 100 * 1024 * 1024:
            raise PanelError("核心文件大小异常")
        executable = archive.read(info)  # Only this exact file; no archive path extraction.
    candidate = folder / "xray.candidate"
    atomic_write(candidate, executable, 0o755)
    try:
        check_core(candidate)
        active, previous = folder / "xray", folder / "xray.previous"
        if active.exists():
            atomic_write(previous, active.read_bytes(), 0o755)
        os.replace(candidate, active)
        if args.action == "update":
            try:
                service("restart", "personal-xray.service")
                time.sleep(1)
                service("is-active", "--quiet", "personal-xray.service")
            except subprocess.SubprocessError:
                if previous.exists():
                    atomic_write(active, previous.read_bytes(), 0o755)
                    service("restart", "personal-xray.service", check=False)
                raise PanelError("核心启动失败，已恢复前一二进制；请检查服务日志") from None
        print("Xray 已安装：", metadata["tag_name"], "（SHA-256 已验证）")
    finally:
        candidate.unlink(missing_ok=True)


def core_rollback():
    root_only()
    active, previous = INSTALL / "core/xray", INSTALL / "core/xray.previous"
    if not previous.exists():
        raise PanelError("没有上一个核心版本")
    check_core(previous)
    old, replacement = active.read_bytes(), previous.read_bytes()
    atomic_write(active, replacement, 0o755)
    try:
        service("restart", "personal-xray.service")
        time.sleep(1)
        service("is-active", "--quiet", "personal-xray.service")
    except subprocess.SubprocessError:
        atomic_write(active, old, 0o755)
        service("restart", "personal-xray.service", check=False)
        raise PanelError("旧核心启动失败，已撤销此次回滚") from None
    atomic_write(previous, old, 0o755)
    print("已回滚到前一个 Xray 核心")


def install_acme():
    root_only()
    metadata = json.loads((ROOT / "upstream.json").read_text())["acme"]
    folder = INSTALL / "acme"
    for item in metadata["files"]:
        content = download(f"https://raw.githubusercontent.com/acmesh-official/acme.sh/{metadata['commit']}/{item['path']}", 2 * 1024 * 1024)
        if hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise PanelError("acme.sh 源文件 SHA-256 不匹配")
        atomic_write(folder / item["path"], content, 0o755)
    print("acme.sh 已固定到已校验的上游提交")


def env_values(path):
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            values[k] = v
    return values


def certificate(args):
    root_only()
    domain = host(args.domain)
    if "." not in domain or ":" in domain or re.fullmatch(r"[\d.]+", domain):
        raise PanelError("需要可公开验证的域名，不能使用 IP 或通配符")
    path = Path("/etc/personal-panel/cloudflare.env")
    existing = env_values(path)
    if existing.get("PANEL_DOMAIN") and existing["PANEL_DOMAIN"] != domain:
        raise PanelError("本安装仅管理一个证书域名；更换域名请先备份并清理专用 ACME 状态，勿修改旧 x-ui 的 ACME 目录")
    token = getpass.getpass("Cloudflare API Token（输入不显示）：").strip()
    zone = input("该域名所属 Cloudflare Zone ID：").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,512}", token) or not re.fullmatch(r"[0-9a-fA-F]{32}", zone):
        raise PanelError("Token 或 Zone ID 格式不正确")
    if not (INSTALL / "acme/acme.sh").exists():
        install_acme()
    # Only this dedicated service receives the DNS token. The web service cannot read it.
    atomic_write(path, f"CF_Token={token}\nCF_Zone_ID={zone}\nPANEL_DOMAIN={domain}\n", 0o600)
    service("start", "personal-acme.service")
    service("enable", "--now", "personal-acme.timer")
    if args.panel_https:
        panel_env = Path("/etc/personal-panel/panel.env")
        values = env_values(panel_env)
        values["PANEL_TLS"] = "on"
        hosts = values.get("PANEL_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")
        values["PANEL_ALLOWED_HOSTS"] = ",".join(dict.fromkeys(hosts + [domain]))
        atomic_write(panel_env, "".join(f"{k}={v}\n" for k, v in values.items()), 0o600)
        service("restart", "personal-panel.service")
    print("证书已配置；专用 systemd timer 会自动续签。Token 未回显，网页用户无权读取。")
    if args.panel_https:
        print("本机面板已改用 HTTPS，监听地址未改变。隧道访问时请使用证书域名并将其在客户端解析到 127.0.0.1。")


def cert_deployed():
    root_only()
    cert = Path("/var/lib/personal-panel-tls")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert / "fullchain.pem", cert / "key.pem")
    # A renewal is not complete until the services actually load the installed pair.
    config = Path("/var/lib/personal-xray/config.json")
    if config.exists() and '"certificateFile"' in config.read_text():
        atomic_write(config.parent / "reload.trigger", str(time.time_ns()))
        os.chown(config.parent / "reload.trigger", pwd.getpwnam("personal-panel").pw_uid, pwd.getpwnam("personal-panel").pw_gid)
    if env_values(Path("/etc/personal-panel/panel.env")).get("PANEL_TLS") == "on":
        service("reload", "personal-panel.service")


def admin(args):
    if os.geteuid() == 0:
        user = pwd.getpwnam("personal-panel")
        os.initgroups(user.pw_name, user.pw_gid)
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
    username = args.username or input("管理员用户名 [admin]：").strip() or "admin"
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", username):
        raise PanelError("用户名仅支持 1–80 位英文字母、数字、点、下划线和短横线")
    password = getpass.getpass("设置密码（至少 14 字符，输入不显示）：")
    if not 14 <= len(password) <= 128:
        raise PanelError("密码需要 14–128 字符")
    if getpass.getpass("再次输入密码：") != password:
        raise PanelError("两次密码不一致")
    core = Core()
    with core.db() as db:
        db.execute("INSERT OR REPLACE INTO admin VALUES(1,?,?)", (username, generate_password_hash(password, method="scrypt:32768:8:1")))
        db.execute("DELETE FROM sessions")
        db.execute("DELETE FROM attempts")
    core.audit("本机重设管理员；所有会话失效")
    print("管理员已保存：", username)


def unprivileged_cli():
    if os.geteuid() == 0:
        for key, value in env_values(Path("/etc/personal-panel/panel.env")).items():
            if key.startswith("PANEL_"):
                os.environ.setdefault(key, value)
        user = pwd.getpwnam("personal-panel")
        os.initgroups(user.pw_name, user.pw_gid)
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)


def main():
    parser = argparse.ArgumentParser(description="Personal Panel 本机管理工具")
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("admin", help="创建或重设管理员，不在命令行传递密码")
    p.add_argument("--username")
    commands.add_parser("maintain")
    commands.add_parser("status")
    commands.add_parser("install-acme")
    commands.add_parser("cert-deployed")
    p = commands.add_parser("cert")
    p.add_argument("domain")
    p.add_argument("--panel-https", action="store_true")
    p = commands.add_parser("core")
    p.add_argument("action", choices=("install", "update", "rollback"))
    args = parser.parse_args()
    try:
        if args.command in ("admin", "maintain", "status"):
            unprivileged_cli()
        if args.command == "admin":
            admin(args)
        elif args.command == "core":
            core_rollback() if args.action == "rollback" else core_install(args)
        elif args.command == "install-acme":
            install_acme()
        elif args.command == "cert":
            certificate(args)
        elif args.command == "cert-deployed":
            cert_deployed()
        elif args.command == "maintain":
            Core().maintain()
        elif args.command == "status":
            print(json.dumps(Core().status(), ensure_ascii=False, indent=2))
    except PanelError as e:
        print(str(e), file=sys.stderr)
        return 1
    except Exception as e:
        print(f"操作失败（{type(e).__name__}），请检查服务状态及网络；不会输出凭据", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
