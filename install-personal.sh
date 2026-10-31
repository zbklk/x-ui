#!/bin/bash
# Separate installation entry. Does not stop, remove or migrate legacy x-ui.
set -euo pipefail
umask 022
[[ $EUID == 0 ]] || { echo '请使用 sudo bash install-personal.sh'; exit 1; }
[[ -d /run/systemd/system ]] || { echo '需要运行 systemd 的 Debian / Ubuntu 服务器'; exit 1; }
command -v apt-get >/dev/null || { echo '目前仅支持 Debian / Ubuntu'; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl python3 python3-venv openssl
python3 -c 'import sys; assert sys.version_info >= (3, 10), "需要 Python 3.10+，建议 Ubuntu 22.04+ / Debian 12+"'

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Never auto-trust a sibling directory beside an installer downloaded into /tmp.
# Always resolve the requested GitHub ref once and fetch that immutable snapshot.
ref=${PANEL_SOURCE_REF:-main}
[[ "$ref" == main || "$ref" =~ ^[a-f0-9]{40}$ ]] || { echo 'PANEL_SOURCE_REF 仅接受 main 或完整提交 SHA'; exit 1; }
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  "https://api.github.com/repos/zbklk/x-ui/commits/$ref" -o "$work/commit.json"
source_commit=$(python3 -c 'import json,sys,re; s=json.load(open(sys.argv[1]))["sha"]; assert re.fullmatch("[a-f0-9]{40}",s); print(s)' "$work/commit.json")
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  "https://github.com/zbklk/x-ui/archive/$source_commit.tar.gz" -o "$work/source.tar.gz"
mkdir "$work/source"
tar --extract --gzip --file "$work/source.tar.gz" --directory "$work/source" --strip-components=1
source_dir="$work/source/personal-panel"

# Old 0.1.x configs have no access-mode marker and migrate to public. Preserve
# private mode only when an operator explicitly selected it in 0.2.x or later.
install_access=${PANEL_ACCESS:-$(python3 - <<'PY'
from pathlib import Path
p=Path('/etc/personal-panel/panel.env')
values=dict(line.split('=',1) for line in p.read_text().splitlines() if '=' in line and not line.startswith('#')) if p.exists() else {}
print(values.get('PANEL_ACCESS','public'))
PY
)}
[[ "$install_access" == public || "$install_access" == private ]] || { echo '访问模式只能为 public 或 private'; exit 1; }

default_port=$(python3 - <<'PY'
from pathlib import Path
from urllib.parse import urlsplit
p=Path('/etc/personal-panel/panel.env')
values=dict(line.split('=',1) for line in p.read_text().splitlines() if '=' in line and not line.startswith('#')) if p.exists() else {}
print(urlsplit('//'+values.get('PANEL_BIND','127.0.0.1:54322')).port or 54322)
PY
)
selected_port=${PANEL_PORT:-$default_port}
if [[ -t 0 && -z ${PANEL_PORT:-} ]]; then
  read -r -p "面板管理端口 [默认 $default_port]：" input_port
  selected_port=${input_port:-$default_port}
fi
selected_port=$(python3 - "$selected_port" <<'PY'
import sys
from pathlib import Path
try:
    port=int(sys.argv[1])
    assert 1024 <= port <= 65535
    p=Path('/etc/personal-panel/panel.env')
    values=dict(line.split('=',1) for line in p.read_text().splitlines() if '=' in line and not line.startswith('#')) if p.exists() else {}
    assert port != int(values.get('PANEL_STATS_PORT','18387'))
    assert port != int(values.get('PANEL_SITE_PORT','0'))
except (ValueError,AssertionError):
    sys.exit('管理端口需在 1024–65535 之间，且不能与统计或自有小站端口相同')
print(port)
PY
)

getent group personal-panel >/dev/null || groupadd --system personal-panel
getent group personal-acme >/dev/null || groupadd --system personal-acme
id personal-panel >/dev/null 2>&1 || useradd --system --gid personal-panel --home-dir /nonexistent --shell /usr/sbin/nologin personal-panel
id personal-acme >/dev/null 2>&1 || useradd --system --gid personal-acme --home-dir /var/lib/personal-acme --shell /usr/sbin/nologin personal-acme
id personal-site >/dev/null 2>&1 || useradd --system --gid personal-panel --home-dir /nonexistent --shell /usr/sbin/nologin personal-site
install -d -m 755 /opt/personal-panel
install -d -m 700 /etc/personal-panel
install -d -m 700 -o personal-panel -g personal-panel /var/lib/personal-panel /var/lib/personal-xray
install -d -m 700 -o personal-acme -g personal-acme /var/lib/personal-acme
install -d -m 2750 -o personal-acme -g personal-panel /var/lib/personal-panel-tls

systemctl stop personal-panel.service personal-panel-maintain.timer personal-panel-maintain.service 2>/dev/null || true
if [[ -f /var/lib/personal-panel/panel.sqlite3 ]]; then
  install -d -m 700 /var/backups/personal-panel
  python3 - <<'PY'
import sqlite3,time
from pathlib import Path
folder=Path('/var/backups/personal-panel')
target=folder/('before-install-'+time.strftime('%Y%m%d-%H%M%S')+'.sqlite3')
with sqlite3.connect('/var/lib/personal-panel/panel.sqlite3') as src, sqlite3.connect(target) as dst:
    src.backup(dst)
target.chmod(0o600)
for old in sorted(folder.glob('before-install-*.sqlite3'))[:-7]:
    old.unlink()
PY
fi
for file in app.py core.py access.py ownsite.py site_server.py manage.py wsgi.py gunicorn.conf.py requirements.txt upstream.json; do
  install -m 644 "$source_dir/$file" "/opt/personal-panel/$file"
done
for directory in templates static deploy site; do
  install -d -m 755 "/opt/personal-panel/$directory"
  cp -a "$source_dir/$directory/." "/opt/personal-panel/$directory/"
done
chown -R root:root /opt/personal-panel
chmod 755 /opt/personal-panel /opt/personal-panel/deploy/*.sh /opt/personal-panel/deploy/panelctl
printf '%s\n' "$source_commit" > /opt/personal-panel/SOURCE_COMMIT
python3 -m venv /opt/personal-panel/venv
/opt/personal-panel/venv/bin/python -m pip install --disable-pip-version-check --only-binary=:all: -r /opt/personal-panel/requirements.txt
/opt/personal-panel/venv/bin/python -m pip check
if [[ ! -f /etc/personal-panel/panel.env ]]; then
  cat > /etc/personal-panel/panel.env <<'ENV'
PANEL_ACCESS=public
PANEL_BIND=0.0.0.0:54322
PANEL_ALLOWED_HOSTS=localhost,127.0.0.1,[::1]
PANEL_ALLOWED_CLIENTS=0.0.0.0/0,::/0
PANEL_TLS=off
PANEL_STATS_PORT=18387
ENV
  chmod 600 /etc/personal-panel/panel.env
fi

# Keep an existing tested core on application upgrades; core updates are explicit.
if [[ ! -x /opt/personal-panel/core/xray ]]; then
  /opt/personal-panel/venv/bin/python /opt/personal-panel/manage.py core install
fi
/opt/personal-panel/venv/bin/python /opt/personal-panel/manage.py install-acme
install -m 755 /opt/personal-panel/deploy/panelctl /usr/local/bin/panelctl
install -m 644 /opt/personal-panel/deploy/personal-*.service /opt/personal-panel/deploy/personal-*.timer /opt/personal-panel/deploy/personal-*.path /etc/systemd/system/
systemctl daemon-reload
# The manager reads the root-only env file and passes it to the unprivileged job.
systemctl start personal-panel-maintain.service
systemctl enable --now personal-xray.service personal-xray.path personal-cert.path personal-panel-maintain.timer
if [[ -t 0 ]]; then
  has_admin=$(python3 -c 'import sqlite3; d=sqlite3.connect("/var/lib/personal-panel/panel.sqlite3");print(d.execute("SELECT count(*) FROM admin").fetchone()[0])')
  if [[ "$has_admin" == 0 ]]; then
    panelctl admin
  fi
fi
# Apply to upgrades as well: legacy localhost-only installations become public.
# Existing administrator, nodes, accounting and TLS settings remain in place.
panelctl access "$install_access" --port "$selected_port" --no-restart
systemctl enable --now personal-panel.service
systemctl is-active --quiet personal-panel.service personal-xray.service
panelctl access check
# An existing owned site keeps its domain and certificate during upgrades.
site_domain=${PANEL_SITE_DOMAIN:-$(python3 - <<'PY'
from pathlib import Path
p=Path('/etc/personal-panel/site.env')
values=dict(line.split('=',1) for line in p.read_text().splitlines() if '=' in line and not line.startswith('#')) if p.exists() else {}
print(values.get('PANEL_SITE_DOMAIN',''))
PY
)}
if [[ -t 0 && -z "$site_domain" ]]; then
  printf '%s\n' '可选：创建 HTTPS 小站，启用域名 HTTPS 面板登录，并预设 REALITY 目标。域名 A/AAAA 应指向本机，Cloudflare 使用 DNS only（灰云）。'
  printf '%s\n' '证书使用本域名的 DNS 编辑 API Token（无需 Global API Key）；输入留在 VPS 上，定时自动续签。'
  read -r -p '自有域名（留空跳过）：' site_domain
fi
if [[ -n "$site_domain" ]]; then
  site_options=(--panel-https)
  [[ -z ${PANEL_SITE_PORT:-} ]] || site_options+=(--port "$PANEL_SITE_PORT")
  if ! panelctl site "$site_domain" "${site_options[@]}"; then
    printf '%s\n' '面板已完成升级，但域名 HTTPS 设置未完成。请检查 DNS、Token 和服务日志，再运行 sudo panelctl site 你的域名 --panel-https。'
    exit 1
  fi
fi
cat <<'MSG'

Personal Panel 0.3.1 已安装。填入域名且证书配置成功时，请使用上方输出的 HTTPS 域名 + 管理端口登录。
如启用了云平台安全组或云防火墙，请放行所选管理端口的 TCP。
旧 x-ui 未被修改；原有 Personal Panel 管理员、节点及数据已保留。
如尚未设置账号，在服务器运行：sudo panelctl admin

查看访问地址：sudo panelctl access show
修改管理端口：sudo panelctl access public --port 54323
改回 SSH 隧道模式：sudo panelctl access private
证书与自动续签：sudo panelctl cert panel.example.com
自有小站、HTTPS 面板与 REALITY 预设：sudo panelctl site www.example.com --panel-https
面板也使用 HTTPS：sudo panelctl cert panel.example.com --panel-https
查看状态：sudo panelctl status
MSG
if [[ "$install_access" == private ]]; then
  printf '%s\n' '当前保留私有模式，请先在自己的电脑建立 SSH 隧道：'
  printf 'ssh -N -L %s:127.0.0.1:%s root@SERVER_IP\n' "$selected_port" "$selected_port"
fi
