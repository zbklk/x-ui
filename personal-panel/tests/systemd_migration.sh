#!/bin/bash
# Ephemeral GitHub runner only. Never run against an existing panel installation.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && $EUID == 0 ]] || { echo '仅允许临时 GitHub Actions runner 执行'; exit 1; }
[[ ! -e /etc/personal-panel/panel.env && ! -e /var/lib/personal-panel/panel.sqlite3 ]] || { echo '拒绝覆盖已有安装'; exit 1; }
source_dir=$(cd "$(dirname "$0")/.." && pwd)
xray_test=$1
python_test=$2
cleanup() {
  systemctl disable --now personal-panel.service personal-core.service personal-core.path personal-xray.service personal-xray.path personal-site.service 2>/dev/null || true
}
trap cleanup EXIT
groupadd --system personal-panel
useradd --system --gid personal-panel --home-dir /nonexistent --shell /usr/sbin/nologin personal-panel
useradd --system --gid personal-panel --home-dir /nonexistent --shell /usr/sbin/nologin personal-site
install -d -m 755 /opt/personal-panel /opt/personal-panel/core
install -d -m 700 /etc/personal-panel
install -d -m 700 -o personal-panel -g personal-panel /var/lib/personal-panel /var/lib/personal-core /var/lib/personal-xray
install -d -m 750 -o root -g personal-panel /var/lib/personal-panel-tls
cp "$source_dir/"*.py "$source_dir/"*.json /opt/personal-panel/
cp -a "$source_dir/templates" "$source_dir/static" "$source_dir/site" /opt/personal-panel/
"$python_test" -m venv --system-site-packages /opt/personal-panel/venv
cat > /opt/personal-panel/venv/bin/gunicorn <<'SH'
#!/bin/bash
exec /opt/personal-panel/venv/bin/python -m gunicorn "$@"
SH
chmod 755 /opt/personal-panel/venv/bin/gunicorn
install -m 755 "$xray_test" /opt/personal-panel/core/xray
install -m 644 "$source_dir/deploy/personal-"*.service "$source_dir/deploy/personal-"*.path /etc/systemd/system/
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=example.com -addext subjectAltName=DNS:example.com \
  -keyout /var/lib/personal-panel-tls/key.pem -out /var/lib/personal-panel-tls/fullchain.pem 2>/dev/null
chown root:personal-panel /var/lib/personal-panel-tls/*.pem
chmod 640 /var/lib/personal-panel-tls/*.pem
cat > /etc/personal-panel/panel.env <<'ENV'
PANEL_ACCESS=public
PANEL_BIND=127.0.0.1:55444
PANEL_ALLOWED_HOSTS=localhost,127.0.0.1,[::1],example.com
PANEL_ALLOWED_CLIENTS=127.0.0.0/8,::1/128
PANEL_TLS=on
PANEL_PUBLIC_ADDRESS=example.com
PANEL_SITE_DOMAIN=example.com
PANEL_SITE_PORT=25443
PANEL_STATS_PORT=18387
ENV
chmod 600 /etc/personal-panel/panel.env
cat > /etc/personal-panel/site.env <<'ENV'
PANEL_SITE_DOMAIN=example.com
PANEL_SITE_PORT=25443
ENV
chmod 600 /etc/personal-panel/site.env
runuser -u personal-panel -- bash -c 'cd /opt/personal-panel && venv/bin/python -' <<'PY'
import json,uuid
from core import Core
from werkzeug.security import generate_password_hash
c=Core()
user={'id':str(uuid.uuid4()),'name':'existing user','secret':'existing-long-trojan-password','enabled':True,'expires_at':0,'quota_bytes':1073741824}
n={'id':str(uuid.uuid4()),'name':'existing TLS node','protocol':'trojan-tls','listen':'127.0.0.1','port':25431,'address':'example.com','sni':'example.com','enabled':True,'clients':[user]}
c.apply(lambda s:dict(s,nodes=[n]))
with c.db() as db:
 db.execute('INSERT INTO admin VALUES(1,?,?)',('existing-admin',generate_password_hash('existing-admin-password')))
 db.execute('INSERT INTO usage VALUES(?,?,?)',(user['id'],123,456))
with open('/var/lib/personal-panel/before-migration.json','w') as f:
 json.dump(c.backup(),f)
PY
systemctl daemon-reload
systemctl enable --now personal-xray.service personal-xray.path personal-site.service
sleep 1
systemctl is-active --quiet personal-xray.service personal-site.service
# Force a real runtime start failure after candidate validation. Old service and
# root-only environment must be restored, not merely left as backup files.
install -d -m 755 /etc/systemd/system/personal-core.service.d
cat > /etc/systemd/system/personal-core.service.d/test-failure.conf <<'UNIT'
[Service]
ExecStart=
ExecStart=/bin/false
Restart=no
UNIT
systemctl daemon-reload
if /opt/personal-panel/venv/bin/python /opt/personal-panel/manage.py core migrate; then
  echo '迁移本应失败'; exit 1
fi
systemctl is-active --quiet personal-xray.service
if rg -q '^PANEL_CORE_ENGINE=sing-box$' /etc/personal-panel/panel.env; then
  echo '迁移失败后未恢复原访问文件'; exit 1
fi
rm /etc/systemd/system/personal-core.service.d/test-failure.conf
systemctl daemon-reload
systemctl reset-failed personal-core.service
/opt/personal-panel/venv/bin/python /opt/personal-panel/manage.py core migrate
/opt/personal-panel/venv/bin/python /opt/personal-panel/manage.py maintain
systemctl start personal-panel.service
systemctl is-active --quiet personal-core.service personal-core.path personal-panel.service
if systemctl is-active --quiet personal-xray.service; then
  echo '原 Xray 核心仍在运行'; exit 1
fi
cd /opt/personal-panel
venv/bin/python - <<'PY'
import http.client,json,socket,ssl,time
from manage import env_values
from pathlib import Path
from ownsite import health
from stats_rpc import query_stats
env=env_values(Path('/etc/personal-panel/panel.env'))
assert env['PANEL_CORE_ENGINE']=='sing-box'
assert env['PANEL_TLS']=='on' and env['PANEL_BIND']=='127.0.0.1:55444'
query_stats(18387)
health('example.com',25443,cafile='/var/lib/personal-panel-tls/fullchain.pem')
context=ssl.create_default_context(cafile='/var/lib/personal-panel-tls/fullchain.pem')
for attempt in range(30):
 try:
  conn=http.client.HTTPSConnection('example.com',55444,context=context,timeout=2)
  conn._create_connection=lambda address,timeout,source_address=None:socket.create_connection(('127.0.0.1',55444),timeout)
  conn.request('POST','/api/login',json.dumps({'username':'existing-admin','password':'existing-admin-password'}),headers={'Content-Type':'application/json'})
  r=conn.getresponse();body=r.read();assert r.status==200,body
  cookie=r.getheader('Set-Cookie');assert '; Secure' in cookie
  conn.request('GET','/api/state',headers={'Cookie':cookie.split(';')[0]})
  r=conn.getresponse();assert r.status==200
  current=json.loads(r.read());conn.close()
  break
 except OSError:
  time.sleep(.2)
else:
 raise AssertionError('HTTPS panel failed to start')
before=json.loads(Path('/var/lib/personal-panel/before-migration.json').read_text())
assert current['state']==before['state']
assert current['usage']==before['usage']
assert current['status']['core_engine']=='sing-box'
assert current['status']['core_status']=='active'
assert 'stats_error' not in current['status']['stats']
print('Real systemd rollback, migration, user statistics, owned website and existing-admin HTTPS login passed')
PY
