# Personal Panel · 自用 Xray 面板

独立实现的私人节点管理面板，当前版本 **0.1.0**。

默认只监听本机，通过 SSH 隧道管理；Cloudflare API Token 与网页进程隔离；提供自动续签、配置校验、流量额度和备份恢复。采用 Python / Flask / Gunicorn / SQLite 与官方 Xray 核心，前端无需外部 CDN。

**这不是旧 x-ui 的完整升级版，不使用闭源发布包。** 原有 Go 代码与 `install.sh` 保留，旧说明见 [README.legacy.md](README.legacy.md)。新代码位于 [personal-panel/](personal-panel/)。

## 安装与访问

支持运行 systemd 的 **Ubuntu 22.04+ / Debian 12+**，Python 3.10+，amd64 / arm64。暂不支持 Alpine / OpenRC。

以 **root 用户登录 VPS** 后，复制下面这一整行执行：

```bash
bash <(curl -fsSL --proto '=https' --proto-redir '=https' https://raw.githubusercontent.com/zbklk/x-ui/main/install-personal.sh)
```

如果当前使用普通用户，先执行 `sudo -i` 切换到 root，再运行上面的安装命令。

首次交互安装会提示设置管理员账号和密码。无人值守安装不会创建默认账号，之后在 VPS 执行 `panelctl admin` 创建。密码至少 14 字符，输入不显示；重设账号会撤销已有会话。

安装后，在**自己的电脑**（不是 VPS）打开终端，替换服务器 IP 和 SSH 用户，运行：

```bash
ssh -N -L 54322:127.0.0.1:54322 root@SERVER_IP
```

SSH 端口不是 22 时，在 `ssh` 后添加 `-p 你的SSH端口`。保持这个终端窗口和 SSH 连接，然后在自己电脑的浏览器访问 **http://127.0.0.1:54322**。

面板默认只监听 VPS 本机地址，不需要向公网开放管理端口 54322。

安装不会停止旧 x-ui，不会修改旧数据库、旧证书、防火墙或 SSH 配置。新旧节点不能占用相同端口。GitHub 保存源码和脚本，面板运行在 VPS，不能部署到 GitHub Pages。

## 功能范围

| 功能 | 当前实现 |
| --- | --- |
| 协议 | VLESS REALITY Vision、VLESS WS TLS、VMess WS TLS、Trojan TCP TLS、SS2022 AES-128-GCM |
| 用户 | 单端口多用户、启停、UUID / 密码、到期时间、累计流量额度 |
| 分享 | 分享链接、本地二维码、IPv4 / IPv6 分享地址 |
| 出站 | 默认仅 IPv4；可切换双栈；默认阻止访问本机及内网 |
| 配置 | 校验 REALITY 密钥对、TLS SNI、新端口和 Xray 配置后写入；独立服务加载 |
| 证书 | 单个域名、Cloudflare 指定 Zone 的 Token、DNS-01、自动续签与加载钩子 |
| 恢复 | JSON 导出 / 恢复、上次配置回退、每日备份保留最近 7 份 |
| 核心 | 固定初装版本、官方发布包 SHA-256 校验、更新前校验配置、失败恢复及二进制回滚 |

REALITY 需自行选择并验证可达的 TLS 目标，不预设一个声称适合所有网络的 SNI。REALITY 和 SS2022 无需证书。TLS 协议需先配置证书。

如有防火墙，只放行实际使用的节点 TCP 端口；SS2022 需要时同时放行该节点 UDP 端口。默认无需向公网放行管理端口 54322 或统计端口 18387，原 SSH 放行规则照常保留。

## Cloudflare 证书与自动续签

创建 API Token，权限为 `Zone → DNS → Edit`，资源只包含所属 Zone，例如 `example.com`。复制该 Zone 的 Zone ID。在服务器执行：

```bash
sudo panelctl cert panel.example.com
```

按提示输入 Token（不回显）与 Zone ID。无需 Global API Key。Token 授权的是整个 Zone 的 DNS 编辑能力，证书只签 `panel.example.com`；不是限制到单条记录。可限制 Token 到固定的 API 出口 IP，注意 IPv4 / IPv6；设置有效期后需提前替换。

当前管理一个证书域名，不申请通配符；DNS 验证不要求面板服务器开放入站 80/443，也不要求先把 A/AAAA 指向该服务器。TLS 入站的 SNI 需被证书覆盖。

专用 `personal-acme` 用户运行固定上游提交的 acme.sh，每日 timer 检查是否续签。完整证书及私钥安装后，校验配对，再通知服务加载。凭据不会经过网页，网页用户不能读取 Token；不自动升级执行 ACME 上游代码。

```bash
systemctl list-timers personal-acme.timer
sudo journalctl -u personal-acme.service -n 60 --no-pager
sudo systemctl start personal-acme.service
```

最后一条执行正常续签检查，不强制重新签发。不要公开环境文件、签发配置或调试日志中的凭据。

如果旧面板曾使用 Global API Key，本安装不改动它的任务。新配置验证后，应在 Cloudflare 轮换旧全局密钥，并同步处理其他使用旧密钥的服务。

## 面板 HTTPS 与公网访问

SSH 隧道默认不依赖域名证书。面板也要 HTTPS 时执行：

```bash
sudo panelctl cert panel.example.com --panel-https
```

仍只监听本机。隧道访问时，在自己电脑 hosts 中将 `panel.example.com` 指向 `127.0.0.1`，访问 `https://panel.example.com:54322`，使名称匹配证书。

如需公网管理，先签好证书，使用 `sudoedit /etc/personal-panel/panel.env` 配置：

```ini
PANEL_BIND=0.0.0.0:54322
PANEL_ALLOWED_HOSTS=panel.example.com
PANEL_ALLOWED_CLIENTS=203.0.113.10/32
PANEL_TLS=on
PANEL_STATS_PORT=18387
```

将示例 IP 换成自己的管理出口 IP，重启 `personal-panel.service`，同时在云 / 本机防火墙限制该来源。程序拒绝无 TLS 的公网监听及全网 CIDR 白名单。不信任 `X-Forwarded-For`，默认不适合直接通过反向代理判断访客来源。

## 维护与恢复

```bash
sudo panelctl status
sudo panelctl admin
sudo panelctl core update
sudo panelctl core rollback
sudo systemctl restart personal-panel.service
sudo journalctl -u personal-xray.service -n 60 --no-pager
sudo journalctl -u personal-panel-maintain.service -n 40 --no-pager
```

核心更新是手动操作：下载官方 Latest 并校验 SHA-256，以普通用户测试现有配置，再替换核心；服务启动失败会恢复前一二进制。配置更改或核心重启会短暂中断节点连接，仅重启面板不主动重启核心。

再次运行新安装脚本可更新面板，短暂停止面板及统计任务，保留现有核心。更新前 SQLite 备份至 `/var/backups/personal-panel/`，保留最近 7 份。

网页支持下载、恢复 JSON 备份及回退上次状态。备份包含节点私钥、用户凭据与流量，不含管理员密码、Cloudflare Token 或证书私钥。自动备份位于 `/var/lib/personal-panel/auto-backups/`，每天 UTC 日期一份、保留最近 7 份；离机保存请自行加密。

旧 x-ui 数据库不能直接导入：用不同端口并行测试，手动迁移需要的节点，再自行停用旧服务。不要把旧 `x-ui.db` 覆盖到新数据库。

## 服务与权限

| 服务 / 路径 | 用途 |
| --- | --- |
| `personal-panel.service` | 普通用户网页进程，无 sudo、root 或 Linux capabilities |
| `personal-xray.service` | 独立普通用户核心，仅授予绑定低端口的能力 |
| `personal-panel-maintain.timer` | 约每 15 秒采集流量、检查额度及到期 |
| `personal-xray.path` | 固定服务处理配置加载请求，不提供任意命令接口 |
| `personal-acme.timer` / `personal-cert.path` | 独立续签；完整部署后通知服务加载 |
| `/opt/personal-panel` | root 拥有的代码、虚拟环境和核心 |
| `/var/lib/personal-panel` | 普通用户独占的数据库、备份及审计 |
| `/var/lib/personal-xray` | 配置与上次配置，目录权限 0700 |
| `/etc/personal-panel/cloudflare.env` | root:root 0600；systemd 只传给证书服务 |
| `/var/lib/personal-acme` | ACME 用户独占的账户、Token 缓存和签发状态 |
| `/var/lib/personal-panel-tls` | 证书用户可写、面板用户只读；私钥 0640 |

密码使用 scrypt 哈希；随机会话 Token 只存摘要；Cookie 为 HttpOnly / SameSite=Strict，HTTPS 时启用 Secure；写请求检查 CSRF / Origin；持久化登录失败限速。拥有服务器 root 权限的人仍能读取节点密钥与证书。

## 限制与验证范围

- 自用初版，没有旧 x-ui 的全部 Telegram、订阅、设备数限制、自定义完整 JSON 和传输方式，也没有旧数据库迁移器。
- 额度不是实时计费边界，约 15 秒检查一次，可能超额；异常重启前尚未采集的尾部流量可能丢失，不用于对外计费。
- `::` 在部分系统上接受双栈；严格仅 IPv6 入站需配合防火墙。网页进程不能完整试绑低于 1024 的端口；端口检查与实际绑定间也存在竞争窗口，请确认核心状态。
- 未来核心可能移除协议，更新前保留备份。初装固定版本见 `personal-panel/upstream.json`。
- 已验证认证、CSRF、IP 白名单、恢复、额度、续签流程模拟与更新失败恢复；固定官方核心通过五种协议配置及四种协议本机真实传输 / 统计测试。REALITY 尚未在真实公网目标上做客户端握手验收。
- 仍需在实际 VPS 验收 systemd 生命周期，并用自己的域名 / Token 完成真实 ACME 签发。本地测试不等于第三方安全审计。

## 本地测试

```bash
cd personal-panel
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
# 对 upstream.json 指定的核心下载并校验后，开启集成测试：
XRAY_TEST_BINARY=/absolute/path/to/xray .venv/bin/python -m unittest discover -s tests -v
```

原项目与本仓库代码遵循根目录 [GPL-3.0 LICENSE](LICENSE)。
