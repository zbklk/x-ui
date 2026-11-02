import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

import core_deploy
import manage
from core import Core, PanelError


class MigrationTests(unittest.TestCase):
    def test_existing_singbox_gains_quic_without_losing_nodes_and_failed_update_restores_binary(self):
        for capable, fail in ((True, False), (False, False), (False, True)):
            with self.subTest(capable=capable, fail=fail), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                core = Core(root / "data", root / "config", test_mode=True, engine="sing-box")
                from test_panel import node
                core.apply(lambda s: dict(s, nodes=[node("vless-reality", 22001), node("trojan-tls", 22002)]))
                before = core.backup()
                env = root / "panel.env"
                original = f"PANEL_CORE_ENGINE=sing-box\nPANEL_CONFIG_DIR={core.config_dir}\nPANEL_BIND=0.0.0.0:54322\n"
                env.write_text(original)
                (root / "core").mkdir()
                active = root / "core/sing-box"; active.write_bytes(b"existing-core")
                candidate = root / "candidate"; candidate.write_bytes(b"quic-core")
                version = "with_utls,with_v2ray_api" + (",with_quic" if capable else "")
                ops = types.SimpleNamespace(root_only=Mock(), PANEL_ENV=env, INSTALL=root, service=Mock(),
                    env_values=manage.env_values, atomic_write=manage.atomic_write)
                with patch.object(core_deploy, "permissions", return_value={}), \
                     patch.object(core_deploy.subprocess, "run", return_value=types.SimpleNamespace(stdout=version)), \
                     patch.object(core_deploy, "fetch_candidate", return_value=(candidate, {"version": "1.14.4"})) as fetch, \
                     patch.object(core_deploy, "check_candidate"), \
                     patch.object(core_deploy, "wait_runtime", side_effect=PanelError("failure") if fail else None):
                    if fail:
                        with self.assertRaisesRegex(PanelError, "恢复前一"):
                            core_deploy.migrate(ops)
                    else:
                        core_deploy.migrate(ops)
                    self.assertEqual(fetch.call_count, 0 if capable else 1)
                self.assertEqual(active.read_bytes(), b"existing-core" if capable or fail else b"quic-core")
                self.assertEqual(env.read_text(), original)
                self.assertEqual(core.backup()["state"], before["state"])
                self.assertEqual(core.backup()["usage"], before["usage"])

    def test_new_build_without_quic_is_rejected_before_configuration_check(self):
        with patch.object(core_deploy, "permissions", return_value={}), \
             patch.object(core_deploy.subprocess, "run", return_value=types.SimpleNamespace(stdout="with_utls,with_v2ray_api")) as run:
            with self.assertRaisesRegex(PanelError, "QUIC"):
                core_deploy.check_candidate(Path("candidate"), Path("config.json"), require_quic=True)
        self.assertEqual(run.call_count, 1)

    def test_failed_start_restores_xray_and_success_preserves_state_and_credentials(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                core = Core(root / "data", root / "old-config", test_mode=True)
                with core.db() as db:
                    db.execute("INSERT INTO admin VALUES(1,?,?)", ("owner", "existing-password-hash"))
                    db.execute("INSERT INTO usage VALUES(?,?,?)", ("old-user", 123, 456))
                before = core.backup()
                panel_env = root / "panel.env"
                original = f"PANEL_ACCESS=public\nPANEL_BIND=0.0.0.0:55444\nPANEL_TLS=on\nPANEL_PUBLIC_ADDRESS=example.com\nPANEL_SITE_DOMAIN=example.com\nPANEL_DATA_DIR={core.data}\n"
                panel_env.write_text(original)
                install = root / "install"
                (install / "core").mkdir(parents=True)
                (install / "core/xray").write_bytes(b"original-xray")
                candidate = install / "core/sing-box.candidate"
                candidate.write_bytes(b"new-singbox")
                def service(*args, **kwargs):
                    return types.SimpleNamespace(returncode=0)
                service = Mock(side_effect=service)
                ops = types.SimpleNamespace(root_only=Mock(), PANEL_ENV=panel_env, INSTALL=install,
                    env_values=manage.env_values, atomic_write=manage.atomic_write, service=service)
                with patch.object(core_deploy, "CONFIG_DIR", root / "new-config"), patch.object(core_deploy, "panel_owned"), \
                     patch.object(core_deploy, "fetch_candidate", return_value=(candidate, {"version": "1.14.4"})), \
                     patch.object(core_deploy, "compile_snapshot", return_value='{"inbounds": []}'), \
                     patch.object(core_deploy, "check_candidate") as validate, \
                     patch.object(core_deploy, "wait_runtime", side_effect=PanelError("failed") if fail else None):
                    if fail:
                        with self.assertRaisesRegex(PanelError, "已恢复原核心"):
                            core_deploy.migrate(ops)
                        self.assertEqual(panel_env.read_text(), original)
                        service.assert_any_call("restart", "personal-xray.service", check=False)
                        self.assertFalse((root / "new-config/config.json").exists())
                    else:
                        core_deploy.migrate(ops)
                        values = manage.env_values(panel_env)
                        self.assertEqual(values["PANEL_CORE_ENGINE"], "sing-box")
                        self.assertEqual(values["PANEL_BIND"], "0.0.0.0:55444")
                        self.assertEqual(values["PANEL_TLS"], "on")
                        self.assertEqual(values["PANEL_SITE_DOMAIN"], "example.com")
                        service.assert_any_call("disable", "personal-xray.service", "personal-xray.path", check=False)
                    validate.assert_called_once()
                after = core.backup()
                self.assertEqual(before["state"], after["state"])
                self.assertEqual(before["usage"], after["usage"])
                with core.db() as db:
                    self.assertEqual(db.execute("SELECT password_hash FROM admin").fetchone()[0], "existing-password-hash")
                self.assertEqual((install / "core/xray").read_bytes(), b"original-xray")
                self.assertEqual(panel_env.with_suffix(".env.before-singbox").read_text(), original)

    def test_binary_validation_failure_never_stops_old_core(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env = root / "panel.env"; env.write_text("PANEL_ACCESS=public\n")
            candidate = root / "candidate"; candidate.write_bytes(b"candidate")
            ops = types.SimpleNamespace(root_only=Mock(), PANEL_ENV=env, INSTALL=root, service=Mock(), env_values=manage.env_values, atomic_write=manage.atomic_write)
            with patch.object(core_deploy, "CONFIG_DIR", root / "config"), patch.object(core_deploy, "panel_owned"), \
                 patch.object(core_deploy, "fetch_candidate", return_value=(candidate, {"version": "test"})), \
                 patch.object(core_deploy, "compile_snapshot", return_value='{}'), \
                 patch.object(core_deploy, "check_candidate", side_effect=PanelError("invalid configuration")):
                with self.assertRaises(PanelError):
                    core_deploy.migrate(ops)
            ops.service.assert_not_called()

    def test_failed_update_restores_previous_singbox_binary(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / "core").mkdir()
            (root / "core/sing-box").write_bytes(b"working-core")
            candidate = root / "candidate"; candidate.write_bytes(b"bad-new-core")
            env = root / "panel.env"; env.write_text("PANEL_CORE_ENGINE=sing-box\n")
            ops = types.SimpleNamespace(root_only=Mock(), PANEL_ENV=env, INSTALL=root, service=Mock(), env_values=manage.env_values, atomic_write=manage.atomic_write)
            with patch.object(core_deploy, "fetch_candidate", return_value=(candidate, {"version": "test"})), \
                 patch.object(core_deploy, "check_candidate"), patch.object(core_deploy, "wait_runtime", side_effect=PanelError("failed")):
                with self.assertRaisesRegex(PanelError, "恢复前一"):
                    core_deploy.install(types.SimpleNamespace(action="update"), ops)
            self.assertEqual((root / "core/sing-box").read_bytes(), b"working-core")

    def test_deployment_hook_notifies_singbox_and_https_panel(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "config.json").write_text('{"certificate_path":"fullchain.pem"}')
            values = {"PANEL_CORE_ENGINE": "sing-box", "PANEL_CONFIG_DIR": str(root), "PANEL_TLS": "on"}
            with patch.object(manage, "root_only"), patch.object(manage.ssl, "SSLContext"), \
                 patch.object(manage, "env_values", return_value=values), patch.object(manage.os, "chown"), \
                 patch.object(manage.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=1, pw_gid=1)), \
                 patch.object(manage, "service") as service:
                manage.cert_deployed()
            self.assertTrue((root / "reload.trigger").exists())
            service.assert_any_call("reload", "personal-panel.service")


class PackageTests(unittest.TestCase):
    def test_checksum_and_source_provenance_are_required(self):
        for tampered, provenance in ((False, True), (True, True), (False, False)):
            with self.subTest(tampered=tampered, provenance=provenance), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                source = {"version": "1.14.4", "release_tag": "test-release", "commit": "a"*40}
                (root / "singbox-source.json").write_text(json.dumps(source))
                prefix = "personal-sing-box-1.14.4-linux-amd64"
                data = io.BytesIO()
                with tarfile.open(fileobj=data, mode="w:gz") as archive:
                    for name, payload in ((prefix + "/sing-box", b"binary"), (prefix + "/SOURCE.json", json.dumps(source if provenance else {}).encode())):
                        entry = tarfile.TarInfo(name); entry.size = len(payload); archive.addfile(entry, io.BytesIO(payload))
                blob = data.getvalue()
                (root / "upstream.json").write_text(json.dumps({"singbox": {"tag_name": "test-release", "assets": [{
                    "name": prefix + ".tar.gz", "digest": "sha256:" + hashlib.sha256(blob).hexdigest(), "browser_download_url": "https://github.com/test.tar.gz"}]}}))
                ops = types.SimpleNamespace(ROOT=root, INSTALL=root / "install", download=Mock(return_value=b"tampered" if tampered else blob), atomic_write=manage.atomic_write)
                with patch.object(core_deploy.platform, "machine", return_value="x86_64"):
                    if tampered or not provenance:
                        with self.assertRaises(PanelError):
                            core_deploy.fetch_candidate(ops)
                        self.assertFalse((root / "install/core/sing-box.candidate").exists())
                    else:
                        candidate, result = core_deploy.fetch_candidate(ops)
                        self.assertEqual(candidate.read_bytes(), b"binary")
                        self.assertEqual(result, source)
