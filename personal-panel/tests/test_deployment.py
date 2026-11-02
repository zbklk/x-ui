import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

import manage
from core import PanelError


class CLIEncodingTests(unittest.TestCase):
    def run_ascii_cli(self, script, stdin=""):
        # Minimal VPS images and SSH environments can disable UTF-8 mode or
        # explicitly set an ASCII PYTHONIOENCODING, even on Python 3.11+.
        env = dict(os.environ, LC_ALL="C", PYTHONCOERCECLOCALE="0",
                   PYTHONUTF8="0", PYTHONIOENCODING="ascii")
        return subprocess.run([sys.executable, "-c", script], env=env,
                              cwd=Path(__file__).resolve().parents[1],
                              input=stdin.encode("utf-8"), capture_output=True, timeout=15)

    def test_acme_install_success_message_does_not_fail_after_files_are_written(self):
        result = self.run_ascii_cli('''
import hashlib,json,sys,tempfile
from pathlib import Path
from unittest.mock import patch
import manage
payload=b"#!/bin/sh\\n"
with tempfile.TemporaryDirectory() as folder:
    root=Path(folder)
    metadata={"acme":{"commit":"test", "files":[{"path":"acme.sh", "sha256":hashlib.sha256(payload).hexdigest()}]}}
    (root/"upstream.json").write_text(json.dumps(metadata),encoding="utf-8")
    with patch.object(manage,"ROOT",root), patch.object(manage,"INSTALL",root), patch.object(manage,"root_only"), patch.object(manage,"download",return_value=payload), patch.object(sys,"argv",["manage.py","install-acme"]):
        status=manage.main()
    assert (root/"acme/acme.sh").read_bytes()==payload
    sys.exit(status)
''')
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertIn("acme.sh 已固定到已校验的上游提交", result.stdout.decode("utf-8"))

    def test_chinese_errors_are_readable_and_exception_secrets_stay_hidden(self):
        result = self.run_ascii_cli('''
import sys
from unittest.mock import patch
import manage
with patch.object(manage,"install_acme",side_effect=ValueError("mock-secret-never-print")), patch.object(sys,"argv",["manage.py","install-acme"]):
    sys.exit(manage.main())
''')
        self.assertEqual(result.returncode, 1)
        self.assertIn("操作失败（ValueError）", result.stderr.decode("utf-8"))
        self.assertNotIn(b"mock-secret-never-print", result.stdout + result.stderr)

    def test_help_is_readable_with_ascii_stdio(self):
        result = self.run_ascii_cli('''
import sys
import manage
sys.argv=["manage.py","--help"]
sys.exit(manage.main())
''')
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertIn("本机管理工具", result.stdout.decode("utf-8"))

    def test_utf8_input_status_and_child_interpreters(self):
        result = self.run_ascii_cli('''
import subprocess,sys
from unittest.mock import Mock,patch
import manage
def status():
    name=input()
    child=subprocess.run([sys.executable,"-c","import sys; print(sys.stdin.read())"], input=name.encode("utf-8"),capture_output=True,check=True)
    return {"name":name,"child":child.stdout.decode("utf-8").strip()}
with patch.object(manage,"unprivileged_cli"), patch.object(manage,"Core",return_value=Mock(status=status)), patch.object(sys,"argv",["manage.py","status"]):
    sys.exit(manage.main())
''', stdin="中文节点\n")
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(json.loads(result.stdout), {"name": "中文节点", "child": "中文节点"})

    def test_panelctl_overrides_inherited_ascii_for_interpreter_startup(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "venv/bin").mkdir(parents=True)
            (root / "venv/bin/python").symlink_to(sys.executable)
            (root / "manage.py").write_text(
                'import json,locale,sys\nprint(json.dumps({"utf8":sys.flags.utf8_mode,"stdio":sys.stdout.encoding,"files":locale.getpreferredencoding(False)}))\n',
                encoding="utf-8")
            source = (Path(__file__).resolve().parents[1] / "deploy/panelctl").read_text(encoding="utf-8")
            wrapper = root / "panelctl"
            wrapper.write_text(source.replace("/opt/personal-panel", str(root)), encoding="utf-8")
            env = dict(os.environ, LC_ALL="C", PYTHONCOERCECLOCALE="0",
                       PYTHONUTF8="0", PYTHONIOENCODING="ascii")
            result = subprocess.run(["bash", str(wrapper), "status"], env=env,
                                    capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            self.assertEqual(json.loads(result.stdout), {"utf8": 1, "stdio": "utf-8", "files": "utf-8"})


class CoreDownloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_checksum_mismatch_never_installs_core(self):
        with patch.object(manage, 'INSTALL', self.root), patch.object(manage, 'root_only'), patch.object(manage, 'download', return_value=b'tampered download'):
            with self.assertRaisesRegex(PanelError, 'SHA-256'):
                manage.core_install(types.SimpleNamespace(action='install'))
        self.assertFalse((self.root / 'core/xray').exists())

    def test_failed_upgrade_restores_previous_binary(self):
        folder = self.root / 'core'
        folder.mkdir()
        (folder / 'xray').write_bytes(b'old-tested-binary')
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as z:
            z.writestr('xray', b'new-binary')
            z.writestr('../../should-not-extract', b'do not extract this')
        payload = data.getvalue()
        asset = {'name': 'Xray-linux-64.zip', 'digest': 'sha256:' + hashlib.sha256(payload).hexdigest(), 'browser_download_url': 'https://github.com/XTLS/Xray-core/test.zip'}
        release = json.dumps({'tag_name': 'test', 'assets': [asset]}).encode()
        failed = subprocess.CalledProcessError(1, 'systemctl')
        with patch.object(manage, 'INSTALL', self.root), patch.object(manage, 'root_only'), patch.object(manage.platform, 'machine', return_value='x86_64'), patch.object(manage, 'check_core'), patch.object(manage, 'download', side_effect=[release, payload]), patch.object(manage, 'service', side_effect=[failed, None]):
            with self.assertRaisesRegex(PanelError, '恢复前一'):
                manage.core_install(types.SimpleNamespace(action='update'))
        self.assertEqual((folder / 'xray').read_bytes(), b'old-tested-binary')
        self.assertFalse((self.root / 'should-not-extract').exists())


class AcmeRenewalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        source = (Path(__file__).resolve().parents[1] / 'deploy/acme-renew.sh').read_text()
        source = source.replace('/opt/personal-panel/acme', str(self.root / 'acme')).replace('/var/lib/personal-acme', str(self.root / 'data')).replace('/var/lib/personal-panel-tls', str(self.root / 'tls'))
        (self.root / 'renew.sh').write_text(source)
        (self.root / 'data').mkdir()
        (self.root / 'acme').mkdir()
        fake = self.root / 'acme/acme.sh'
        fake.write_text('''#!/bin/bash
set -e
printf '%s\\n' "$*" >> "$FAKE_ROOT/calls"
if [[ "$*" == *" --issue "* ]]; then
  [[ "${FAKE_ISSUE_FAIL:-0}" == 0 ]] || exit 42
  mkdir -p "$FAKE_ROOT/data/certs/panel.example.com_ecc"
  touch "$FAKE_ROOT/data/certs/panel.example.com_ecc/panel.example.com.conf"
fi
if [[ "$*" == *" --renew "* ]]; then exit "${FAKE_RENEW_RESULT:-2}"; fi
''')
        fake.chmod(0o755)
        self.env = dict(os.environ, CF_Token='dummy-token-never-sent', CF_Zone_ID='0'*32, PANEL_DOMAIN='panel.example.com', FAKE_ROOT=str(self.root))

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, **extra):
        return subprocess.run(['bash', str(self.root / 'renew.sh')], env=dict(self.env, **extra), capture_output=True, text=True)

    def test_initial_issue_install_then_skipped_renewal(self):
        self.assertEqual(self.run_script().returncode, 0)
        calls = (self.root / 'calls').read_text()
        self.assertIn('--issue --dns dns_cf', calls)
        self.assertIn('--install-cert', calls)
        self.assertNotIn('dummy-token', calls)
        self.assertEqual(self.run_script().returncode, 0)
        calls = (self.root / 'calls').read_text()
        self.assertEqual(calls.count('--install-cert'), 1)
        self.assertIn('--renew', calls)

    def test_failed_renewal_is_not_hidden(self):
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.run_script(FAKE_RENEW_RESULT='1').returncode, 1)

    def test_failed_initial_issue_does_not_mark_certificate_installed(self):
        self.assertEqual(self.run_script(FAKE_ISSUE_FAIL='1').returncode, 42)
        self.assertFalse((self.root / 'data/panel.example.com.installed').exists())


if __name__ == '__main__':
    unittest.main()
