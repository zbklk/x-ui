# Personal Panel · 自用 Xray 面板

独立实现的私人节点管理面板，当前版本 **0.2.0**。

默认支持 **VPS 公网 IP + 端口直接登录**，出门使用电脑或手机浏览器即可管理节点，无需保持 SSH 隧道。域名和 HTTPS 可选；Cloudflare API Token 与网页进程隔离，并提供自动续签、配置校验、流量额度和备份恢复。采用 Python / Flask / Gunicorn / SQLite 与官方 Xray 核心，前端无需外部 CDN。

**这不是旧 x-ui 的完整升级版，不使用闭源发布包。** 原有 Go 代码与 `install.sh` 保留，旧说明见 [README.legacy.md](README.legacy.md)。新代码位于 [personal-panel/](personal-panel/)。

## 安装与访问

支持运行 systemd 的 **Ubuntu 22.04+ / Debian 12+**，Python 3.10+，amd64 / arm64。暂不支持 Alpine / OpenRC。

以 **root 用户登录 VPS**，执行一行安装命令：

```bash
bash <(curl -fsSL --proto '=https' --proto-redir '=https' https://raw.githubusercontent.com/zbklk/x-ui/main/install-personal.sh)
```

普通用户先执行 `sudo -i`。安装时可设置管理端口，直接回车使用默认 **54322**；首次安装还会提示创建管理员账号与密码，密码至少 14 字符、输入不回显。

安装完成后，直接在任何电脑或手机的浏览器打开安装输出的地址：

```text
http://你的VPS公网IP:54322/
```

使用刚才设置的管理员账号和密码登录即可；**不需要 SSH 隧道，也不强制使用域名或固定来源 IP**。IPv6 地址需加方括号，例如 `http://[你的IPv6]:54322/`。无人值守安装不会创建默认账号，可在 VPS 执行 `panelctl admin` 创建。

默认 HTTP 会明文传输登录信息；需要加密时，可按下文启用域名 HTTPS。已经配置好的 HTTPS 在升级时保留。

安装会尝试放行已启用的 UFW 中对应的管理 TCP 端口，不启用 UFW，也不改动 SSH 放行规则。**如启用了云平台安全组、云防火墙或其他主机防火墙，还需放行所选管理端口的 TCP。**统计端口 18387 始终只供本机使用，无需开放。

### 已有 0.1.0 面板升级

再次执行上方同一条安装命令即可。原来的管理员、密码、节点、流量与证书保留；旧版仅本机访问的配置会自动切换为公网直连。若希望继续使用默认端口，端口提示直接回车即可，无需卸载重装。

0.2.0 以后通过 `panelctl access private` 明确选择的私有模式，会在下次升级中保留。

### 查看地址或修改端口

在 VPS 执行：

```bash
panelctl access show
panelctl access public --port 55443
```

修改后使用输出的新地址登录。也可用 `--address 你的公网IP` 指定输出地址（适合 NAT 等无法自动识别公网 IP 的环境），或通过 `--listen ::` 监听 IPv6。命令仅重启面板，保留节点和账号；启动失败自动恢复原访问配置。

安装不会卸载旧 x-ui，不会修改其数据库和证书。新旧节点不能占用同一端口。GitHub 保存代码和安装脚本，面板实际运行在 VPS，不能部署到 GitHub Pages。

## 功能范围

| 功能 | 当前实现 |
| --- | --- |
| 协议 | VLESS REALITY Vision、VLESS WS TLS、VMess WS TLS、Trojan TCP TLS、SS2022 AES-128-GCM |
| 用户 | 单端口多用户、启停、UUID / 密码、到期时间、累计流量额度 |
| 分享 | 分享链接、本地二维码、IPv4 / IPv6 分享地址；支持公网 HTTP 下生成 UUID 及复制链接 |
| 管理访问 | 默认公网 IP + 端口；可改端口、配置 HTTPS、限制来源或切换私有模式 |
| 出站 | 默认仅 IPv4；可切换双栈；默认阻止访问本机及内网 |
| 配置 | 校验 REALITY 密钥对、TLS SNI、新端口和 Xray 配置后写入；独立服务加载 |
| 证书 | 单个域名、Cloudflare 指定 Zone 的 Token、DNS-01、自动续签与加载钩子 |
| 恢复 | JSON 导出 / 恢复、上次配置回退、每日备份保留最近 7 份 |
| 核心 | 固定初装版本、官方发布包 SHA-256 校验、更新前校验配置、失败恢复及二进制回滚 |

REALITY 需自行选择并验证可达的 TLS 目标，不预设一个声称适合所有网络的 SNI。REALITY 和 SS2022 无需证书。TLS 协议需先配置证书。

防火墙需放行面板管理 TCP 端口及实际使用的节点 TCP 端口；SS2022 需要时同时放行该节点 UDP 端口。统计端口 18387 不对公网开放，原 SSH 放行规则照常保留。

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

## 可选 HTTPS 与私有访问

默认公网 IP 访问不需要域名。希望加密面板登录时，将自己的域名解析到 VPS，再执行：

```bash
sudo panelctl cert panel.example.com --panel-https
```

完成后使用 `https://panel.example.com:管理端口/` 登录；面板继续使用当前监听范围，证书自动续签。请用证书覆盖的域名访问，以避免 IP 与域名证书不匹配。凭据仍由独立证书服务管理。

如需限制到指定来源 IP，可显式配置（默认不限制）：

```bash
sudo panelctl access public --allow-client 203.0.113.10/32
```

该设置会同时保留本机健康检查访问。不读取浏览器提供的 `X-Forwarded-For`。使用域名时，需已通过证书命令添加该域名，或在 `/etc/personal-panel/panel.env` 的 `PANEL_ALLOWED_HOSTS` 中明确配置；任意未配置的域名会被拒绝，以防 DNS 重绑定。

如果以后要恢复仅本机访问：

```bash
sudo panelctl access private
```

然后在自己的电脑建立 SSH 隧道，再打开本机地址：

```bash
ssh -N -L 54322:127.0.0.1:54322 root@SERVER_IP
```

私有模式是可选项。管理端口不是 54322 时同步替换隧道端口；SSH 端口不是 22 时在 `ssh` 后加 `-p 实际SSH端口`。已经启用 HTTPS 时需使用证书域名访问。

## 维护与恢复

```bash
sudo panelctl status
sudo panelctl admin
sudo panelctl access show
sudo panelctl access public --port 54322
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

密码使用 scrypt 哈希；随机会话 Token 只存摘要；Cookie 为 HttpOnly / SameSite=Strict，HTTPS 时启用 Secure；写请求检查 CSRF / Origin；按来源 IP 持久化限制登录失败次数，其他来源的失败不会锁住所有用户。拥有服务器 root 权限的人仍能读取节点密钥与证书。

## 限制与验证范围

- 当前版本没有旧 x-ui 的全部 Telegram、订阅、设备数限制、自定义完整 JSON 和传输方式，也没有旧数据库迁移器。
- 额度不是实时计费边界，约 15 秒检查一次，可能超额；异常重启前尚未采集的尾部流量可能丢失，不用于对外计费。
- `::` 在部分系统上接受双栈；严格仅 IPv6 入站需配合防火墙。网页进程不能完整试绑低于 1024 的端口；端口检查与实际绑定间也存在竞争窗口，请确认核心状态。
- 未来核心可能移除协议，更新前保留备份。初装固定版本见 `personal-panel/upstream.json`。
- 已验证认证、CSRF、IP 白名单、恢复、额度、续签流程模拟与更新失败恢复；固定官方核心通过五种协议配置及四种协议本机真实传输 / 统计测试。REALITY 尚未在真实公网目标上做客户端握手验收。
- 新版本还应在实际 VPS 验收公网访问及 systemd 生命周期，并用自己的域名 / Token 完成真实 ACME 签发。本地测试不等于第三方安全审计。

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
