"""Administrator credentials shared by the interactive installer and the panel."""
import re

from werkzeug.security import generate_password_hash

from core import PanelError


def validate_username(username):
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", username):
        raise PanelError("用户名仅支持 1–80 位英文字母、数字、点、下划线和短横线")


def validate_password(password):
    if not isinstance(password, str) or not 7 <= len(password) <= 128:
        raise PanelError("密码需要 7–128 个字符")


def save_admin(db, username, password, *, previous_hash=None):
    password_hash = generate_password_hash(password, method="scrypt:32768:8:1")
    if previous_hash is None:
        db.execute("INSERT OR REPLACE INTO admin VALUES(1,?,?)", (username, password_hash))
    else:
        updated = db.execute("UPDATE admin SET username=?, password_hash=? WHERE id=1 AND password_hash=?",
                             (username, password_hash, previous_hash))
        if not updated.rowcount:
            raise PanelError("账户已更改，请重新登录")
    db.execute("DELETE FROM sessions")
    db.execute("DELETE FROM attempts")
