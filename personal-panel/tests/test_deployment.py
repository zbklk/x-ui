import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

import manage
from core import PanelError


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
