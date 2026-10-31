"""Root-only deployment and checked migration to the statistics-enabled sing-box build."""
import io
import json
import os
from pathlib import Path
import platform
import pwd
import re
import subprocess
import tarfile
import time

from core import PanelError
from stats_rpc import query_stats

CONFIG_DIR = Path("/var/lib/personal-core")
SERVICE = "personal-core.service"


def permissions():
    user = pwd.getpwnam("personal-panel")
    return {"user": user.pw_uid, "group": user.pw_gid, "extra_groups": [], "umask": 0o077}


def panel_owned(path):
    user = pwd.getpwnam("personal-panel")
    os.chown(path, user.pw_uid, user.pw_gid)


def fetch_candidate(ops):
    import hashlib
    source = json.loads((ops.ROOT / "singbox-source.json").read_text())
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if not arch:
        raise PanelError("目前只支持 Linux amd64 / arm64")
    release = json.loads((ops.ROOT / "upstream.json").read_text())["singbox"]
    if release["tag_name"] != source["release_tag"]:
        raise PanelError("sing-box 发布版本与源码清单不匹配")
    prefix = f"personal-sing-box-{source['version']}-linux-{arch}"
    asset = next((a for a in release["assets"] if a["name"] == prefix + ".tar.gz"), None)
    if not asset or not re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest", "")):
        raise PanelError("统计版 sing-box 发布包缺少有效 SHA-256，拒绝安装")
    data = ops.download(asset["browser_download_url"])
    if "sha256:" + hashlib.sha256(data).hexdigest() != asset["digest"]:
        raise PanelError("sing-box 下载的 SHA-256 不匹配，拒绝安装")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        info, provenance = archive.getmember(prefix + "/sing-box"), archive.getmember(prefix + "/SOURCE.json")
        if not info.isfile() or info.size > 128 * 1024 * 1024 or not provenance.isfile() or provenance.size > 4096:
            raise PanelError("核心发布包结构或大小异常")
        if json.loads(archive.extractfile(provenance).read()) != source:
            raise PanelError("sing-box 源码版本与构建清单不匹配")
        executable = archive.extractfile(info).read()  # No archive paths extracted.
    folder = ops.INSTALL / "core"
    folder.mkdir(mode=0o755, parents=True, exist_ok=True)
    candidate = folder / "sing-box.candidate"
    ops.atomic_write(candidate, executable, 0o755)
    return candidate, source


def check_candidate(candidate, config):
    result = subprocess.run([str(candidate), "version"], capture_output=True, text=True, timeout=10, check=True, **permissions())
    if not all(tag in result.stdout for tag in ("with_utls", "with_v2ray_api")):
        raise PanelError("sing-box 缺少 REALITY 或逐用户统计模块，拒绝替换")
    result = subprocess.run([str(candidate), "check", "-c", str(config)], capture_output=True, timeout=15, **permissions())
    if result.returncode:
        raise PanelError("sing-box 无法通过现有节点配置校验；原核心未改动")


def compile_snapshot(ops, values, candidate):
    # Run DB initialization, accounting and key/certificate checks as the panel
    # user. Capture the secret-bearing JSON directly into a private file.
    script = """import json,os
from core import Core
old=Core()
old.collect_stats()
new=Core(engine='sing-box',config_dir=os.environ['PANEL_MIGRATION_DIR'],binary=os.environ['PANEL_MIGRATION_BINARY'])
state,usage=new.state(),new.usage()
new.check_materials(state,usage)
print(json.dumps(new.compile(state,usage)))
"""
    env = dict(os.environ)
    env.update({k: v for k, v in values.items() if k.startswith("PANEL_")})
    env.update(PANEL_MIGRATION_DIR=str(CONFIG_DIR), PANEL_MIGRATION_BINARY=str(candidate), PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([str(ops.INSTALL / "venv/bin/python"), "-c", script], cwd=ops.INSTALL,
                            env=env, capture_output=True, text=True, timeout=30, **permissions())
    if result.returncode:
        raise PanelError("原节点、密钥或证书未通过迁移检查；原核心未改动，请先在面板检查现有配置")
    # Ensure stdout is only a complete configuration, never diagnostics.
    json.loads(result.stdout)
    return result.stdout


def wait_runtime(ops, stats_port):
    for _ in range(15):
        try:
            ops.service("is-active", "--quiet", SERVICE)
            query_stats(stats_port, timeout=.5)
            return
        except (OSError, ValueError, subprocess.SubprocessError):
            time.sleep(.25)
    raise PanelError("sing-box 未通过启动及统计 API 检查")


def migrate(ops):
    ops.root_only()
    values = ops.env_values(ops.PANEL_ENV)
    if not values:
        raise PanelError("请先运行安装脚本")
    active_binary = ops.INSTALL / "core/sing-box"
    if values.get("PANEL_CORE_ENGINE") == "sing-box" and active_binary.exists():
        ops.service("enable", "--now", SERVICE, "personal-core.path")
        wait_runtime(ops, int(values.get("PANEL_STATS_PORT", "18387")))
        print("已使用 sing-box，账号、节点及统计保留。核心版本更新使用 panelctl core update。")
        return
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    panel_owned(CONFIG_DIR)
    candidate, source = fetch_candidate(ops)
    staging = CONFIG_DIR / ".migration.json"
    try:
        content = compile_snapshot(ops, values, candidate)
        ops.atomic_write(staging, content)
        panel_owned(staging)
        check_candidate(candidate, staging)
        original_env = ops.PANEL_ENV.read_bytes()
        config = CONFIG_DIR / "config.json"
        previous_config = config.read_bytes() if config.exists() else None
        old_service = SERVICE if values.get("PANEL_CORE_ENGINE") == "sing-box" else "personal-xray.service"
        old_active = ops.service("is-active", "--quiet", old_service, check=False).returncode == 0
        old_path_active = ops.service("is-active", "--quiet", "personal-xray.path", check=False).returncode == 0
        ops.atomic_write(ops.PANEL_ENV.with_suffix(".env.before-singbox"), original_env, 0o600)
        try:
            ops.service("stop", "personal-xray.path", "personal-xray-reload.service", check=False)
            if old_active:
                ops.service("stop", old_service)
            os.replace(candidate, active_binary)
            ops.atomic_write(config, content)
            panel_owned(config)
            values.update(PANEL_CORE_ENGINE="sing-box", PANEL_CORE_BINARY=str(active_binary), PANEL_CONFIG_DIR=str(CONFIG_DIR))
            ops.atomic_write(ops.PANEL_ENV, "".join(f"{k}={v}\n" for k, v in values.items()), 0o600)
            ops.service("restart", SERVICE)
            wait_runtime(ops, int(values.get("PANEL_STATS_PORT", "18387")))
            ops.service("enable", "--now", SERVICE, "personal-core.path")
        except (OSError, PanelError, subprocess.SubprocessError):
            ops.service("disable", "--now", SERVICE, "personal-core.path", check=False)
            ops.atomic_write(ops.PANEL_ENV, original_env, 0o600)
            if previous_config is None:
                config.unlink(missing_ok=True)
            else:
                ops.atomic_write(config, previous_config)
                panel_owned(config)
            restored = ops.service("restart", old_service, check=False) if old_active else None
            if old_path_active:
                ops.service("start", "personal-xray.path", check=False)
            if restored is not None and restored.returncode:
                raise PanelError("切换失败，原配置已恢复，但原核心启动失败；请检查服务日志") from None
            raise PanelError("切换未完成，已恢复原核心和访问设置；账号、节点及原始核心文件保留") from None
        ops.service("disable", "personal-xray.service", "personal-xray.path", check=False)
        print(f"已切换到 sing-box {source['version']}（官方源码、REALITY 与逐用户统计模块、SHA-256 已验证）。")
        print("管理员、节点端口、密钥、累计流量和证书设置均保留，现有分享链接继续使用。")
    finally:
        candidate.unlink(missing_ok=True)
        staging.unlink(missing_ok=True)


def install(args, ops):
    ops.root_only()
    candidate, source = fetch_candidate(ops)
    active, previous = ops.INSTALL / "core/sing-box", ops.INSTALL / "core/sing-box.previous"
    config = Path(ops.env_values(ops.PANEL_ENV).get("PANEL_CONFIG_DIR", str(CONFIG_DIR))) / "config.json"
    try:
        check_candidate(candidate, config)
        if active.exists():
            ops.atomic_write(previous, active.read_bytes(), 0o755)
        os.replace(candidate, active)
        try:
            ops.service("restart", SERVICE)
            wait_runtime(ops, int(ops.env_values(ops.PANEL_ENV).get("PANEL_STATS_PORT", "18387")))
        except (OSError, PanelError, subprocess.SubprocessError):
            if previous.exists():
                ops.atomic_write(active, previous.read_bytes(), 0o755)
                ops.service("restart", SERVICE, check=False)
            raise PanelError("核心更新启动失败，已恢复前一二进制") from None
        print(f"sing-box {source['version']} 已更新，配置及统计 API 检查通过。")
    finally:
        candidate.unlink(missing_ok=True)


def rollback(ops):
    ops.root_only()
    active, previous = ops.INSTALL / "core/sing-box", ops.INSTALL / "core/sing-box.previous"
    if not previous.exists():
        raise PanelError("没有上一个 sing-box 核心版本")
    values = ops.env_values(ops.PANEL_ENV)
    check_candidate(previous, Path(values.get("PANEL_CONFIG_DIR", str(CONFIG_DIR))) / "config.json")
    old, replacement = active.read_bytes(), previous.read_bytes()
    ops.atomic_write(active, replacement, 0o755)
    try:
        ops.service("restart", SERVICE)
        wait_runtime(ops, int(values.get("PANEL_STATS_PORT", "18387")))
    except (OSError, PanelError, subprocess.SubprocessError):
        ops.atomic_write(active, old, 0o755)
        ops.service("restart", SERVICE, check=False)
        raise PanelError("旧 sing-box 核心启动失败，已撤销回滚") from None
    ops.atomic_write(previous, old, 0o755)
    print("已回滚到前一个 sing-box 核心")
