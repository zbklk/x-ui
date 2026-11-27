"""Authenticated management API. Run with Gunicorn, not Flask's dev server."""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import secrets
import time
from urllib.parse import urlsplit

from flask import Flask, g, jsonify, make_response, render_template, request
import qrcode
from qrcode.image.svg import SvgPathImage
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash

from access import AccessPolicy
from accounts import save_admin, validate_password, validate_username
from core import Core, PanelError, atomic_write, clean_node, owned_site, share_link, uid

COOKIE = "personal_panel_session"


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_app(core=None, testing=False):
    app = Flask(__name__)
    core = core or Core()
    policy = AccessPolicy.from_env()
    app.config.update(MAX_CONTENT_LENGTH=1024 * 1024, TESTING=testing)
    secure = policy.tls
    app.extensions["core"] = core
    app.extensions["access"] = policy

    @app.before_request
    def guard():
        if not policy.accepts_host(request.host):
            return jsonify(error="请使用 VPS 的 IP 地址或已配置的面板域名访问"), 400
        if not testing and not policy.accepts_client(request.remote_addr):
            return jsonify(error="该来源 IP 不在管理白名单中"), 403
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("Origin")
            if origin:
                parsed = urlsplit(origin)
                if parsed.netloc != request.host or parsed.scheme not in ("http", "https"):
                    return jsonify(error="来源校验失败"), 403
            if not request.is_json:
                return jsonify(error="需要 JSON 请求"), 415
        if not request.path.startswith("/api/") or request.path == "/api/login":
            return None
        token = request.cookies.get(COOKIE, "")
        with core.db() as db:
            row = db.execute("SELECT csrf,expires FROM sessions WHERE token_hash=?", (digest(token),)).fetchone()
        if not row or row["expires"] <= time.time():
            return jsonify(error="请先登录"), 401
        g.csrf = row["csrf"]
        if request.method not in ("GET", "HEAD", "OPTIONS") and not hmac.compare_digest(
                request.headers.get("X-CSRF-Token", ""), g.csrf):
            return jsonify(error="CSRF 校验失败，请刷新页面"), 403
        if request.path == "/api/restore":
            # A complete multi-inbound backup can exceed the per-edit limit.
            # Raise the budget only after authentication and CSRF validation.
            request.max_content_length = 32 * 1024 * 1024

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.errorhandler(PanelError)
    def invalid(error):
        return jsonify(error=str(error)), 400

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.name), error.code

    @app.errorhandler(Exception)
    def unexpected(error):
        # Exception text may include secrets from malformed configs; log only its class.
        app.logger.error("Request failed: %s", type(error).__name__)
        return jsonify(error="操作未完成，请查看服务状态后重试"), 500

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/healthz")
    def health():
        return jsonify(ok=True)

    def verify_admin(password, username=None):
        now, ip = time.time(), request.remote_addr or "unknown"
        with core.db() as db:
            db.execute("DELETE FROM attempts WHERE at < ?", (now - 900,))
            count = db.execute("SELECT count(*) FROM attempts WHERE ip=?", (ip,)).fetchone()[0]
            if count >= 8:
                response = jsonify(error="密码验证次数过多，请 15 分钟后重试")
                response.headers["Retry-After"] = "900"
                return None, (response, 429)
            admin = db.execute("SELECT username,password_hash FROM admin WHERE id=1").fetchone()
            # Count attempts before checking the expensive password hash.
            db.execute("INSERT INTO attempts VALUES(?,?)", (ip, now))
        if admin and check_password_hash(admin["password_hash"], password):
            if username is None or hmac.compare_digest(admin["username"].encode(), username.encode()):
                return admin, None
        if username is None:
            return None, (jsonify(error="当前密码不正确"), 403)
        return None, (jsonify(error="用户名或密码不正确"), 401)

    @app.post("/api/login")
    def login():
        body = request.get_json()
        if not isinstance(body, dict):
            raise PanelError("登录格式不正确")
        username, password = body.get("username", ""), body.get("password", "")
        if not isinstance(username, str) or not isinstance(password, str) or len(username) > 80 or len(password) > 128:
            raise PanelError("登录格式不正确")
        admin, error = verify_admin(password, username)
        if error:
            return error
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with core.db() as db:
            # An old password verified just before rotation must not open a new session.
            saved = db.execute("INSERT INTO sessions SELECT ?,?,? FROM admin WHERE id=1 AND password_hash=?",
                               (digest(token), csrf, time.time() + 12 * 3600, admin["password_hash"]))
            if not saved.rowcount:
                return jsonify(error="账户已更改，请重新登录"), 401
            db.execute("DELETE FROM attempts WHERE ip=?", (request.remote_addr or "unknown",))
        response = jsonify(ok=True, csrf=csrf, username=admin["username"])
        response.set_cookie(COOKIE, token, max_age=12 * 3600, httponly=True, secure=secure, samesite="Strict", path="/")
        core.audit("管理员登录")
        return response

    @app.get("/api/session")
    def session_info():
        with core.db() as db:
            row = db.execute("SELECT username FROM admin WHERE id=1").fetchone()
        return jsonify(csrf=g.csrf, username=row[0])

    def signed_out():
        response = jsonify(ok=True)
        response.delete_cookie(COOKIE, path="/", secure=secure, httponly=True, samesite="Strict")
        return response

    @app.post("/api/logout")
    def logout():
        with core.db() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (digest(request.cookies.get(COOKIE, "")),))
        return signed_out()

    @app.post("/api/account")
    def change_account():
        body = request.get_json()
        if not isinstance(body, dict):
            raise PanelError("账户设置格式不正确")
        username = body.get("username")
        validate_username(username)
        current = body.get("current_password")
        if not isinstance(current, str) or not 1 <= len(current) <= 128:
            raise PanelError("请输入当前密码")
        password = body.get("new_password", "")
        if password != "":
            validate_password(password)
        if password != body.get("confirm_password", ""):
            raise PanelError("两次新密码不一致")
        admin, error = verify_admin(current)
        if error:
            return error
        if not password and username == admin["username"]:
            raise PanelError("请修改用户名或输入新密码")
        with core.db() as db:
            save_admin(db, username, password or current, previous_hash=admin["password_hash"])
        core.audit("管理员修改账户")
        return signed_out()

    @app.get("/api/state")
    def state():
        return jsonify(state=core.state(), usage=core.usage(), status=core.status())

    @app.post("/api/nodes")
    def add_node():
        body = request.get_json()
        def transform(s):
            reserved = {policy.port, core.stats_port}
            site = owned_site()
            if site:
                reserved.add(site["port"])
            reserved.update(n["port"] for n in s["nodes"])
            s["nodes"].append(clean_node(body, reserved_ports=reserved))
            return s
        state = core.apply(transform, "新增入站")
        node = state["nodes"][-1]
        return jsonify(ok=True, id=node["id"], port=node["port"])

    @app.put("/api/nodes/<node_id>")
    def update_node(node_id):
        node_id = uid(node_id)
        body = request.get_json()
        if not isinstance(body, dict):
            raise PanelError("入站格式不正确")
        node = clean_node(dict(body, id=node_id))
        def transform(s):
            if not any(n["id"] == node_id for n in s["nodes"]):
                raise PanelError("入站不存在")
            s["nodes"] = [node if n["id"] == node_id else n for n in s["nodes"]]
            return s
        core.apply(transform, "修改入站或用户")
        return jsonify(ok=True)

    @app.delete("/api/nodes/<node_id>")
    def delete_node(node_id):
        node_id = uid(node_id)
        def transform(s):
            s["nodes"] = [n for n in s["nodes"] if n["id"] != node_id]
            return s
        core.apply(transform, "删除入站")
        return jsonify(ok=True)

    @app.post("/api/settings")
    def settings():
        body = request.get_json()
        if not isinstance(body, dict):
            raise PanelError("设置格式不正确")
        def transform(s):
            s["settings"].update(body)
            return s
        core.apply(transform, "修改全局设置")
        return jsonify(ok=True)

    @app.post("/api/keypair")
    def keypair():
        return jsonify(core.keypair())

    def find_link(node_id, client_id):
        s = core.state()
        for n in s["nodes"]:
            if n["id"] == node_id:
                for c in n["clients"]:
                    if c["id"] == client_id:
                        return share_link(n, c, s["settings"]["public_address"])
        raise PanelError("入站或用户不存在")

    @app.get("/api/share/<node_id>/<client_id>")
    def share(node_id, client_id):
        return jsonify(link=find_link(uid(node_id), uid(client_id)))

    @app.get("/api/qr/<node_id>/<client_id>")
    def qr(node_id, client_id):
        output = io.BytesIO()
        qrcode.make(find_link(uid(node_id), uid(client_id)), image_factory=SvgPathImage, border=3).save(output)
        return app.response_class(output.getvalue(), mimetype="image/svg+xml")

    @app.get("/api/backup")
    def backup():
        response = jsonify(core.backup())
        response.headers["Content-Disposition"] = f'attachment; filename="personal-panel-{time.strftime("%Y%m%d-%H%M%S", time.gmtime())}.json"'
        return response

    @app.post("/api/restore")
    def restore():
        core.restore(request.get_json())
        return jsonify(ok=True)

    @app.post("/api/rollback")
    def rollback():
        path = core.data / "previous.json"
        if not path.exists():
            raise PanelError("还没有可回退的配置")
        core.restore(json.loads(path.read_text()))
        return jsonify(ok=True)

    @app.post("/api/usage/<client_id>/reset")
    def reset_usage(client_id):
        client_id = uid(client_id)
        if not any(c["id"] == client_id for n in core.state()["nodes"] for c in n["clients"]):
            raise PanelError("用户不存在")
        with core.lock():
            core.collect_stats()
            with core.db() as db:
                db.execute("INSERT OR REPLACE INTO usage VALUES(?,0,0)", (client_id,))
            content = core.validate_config(core.compile(core.state(), core.usage()))
            core.write_config(content)
        core.audit("重置用户流量")
        return jsonify(ok=True)

    @app.post("/api/restart-core")
    def restart_core():
        with core.lock():
            core.collect_stats()
            content = core.validate_config(core.compile(core.state(), core.usage()))
            core.write_config(content)
            atomic_write(core.config_dir / "reload.trigger", str(time.time_ns()))
        core.audit("请求重启代理核心")
        return jsonify(ok=True)

    return app
