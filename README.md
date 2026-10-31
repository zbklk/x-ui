# Personal Panel · 自用 sing-box 面板

独立实现的私人节点管理面板，当前版本 **0.4.0**，默认核心为 **sing-box 1.14.4**（含逐用户统计模块）。

默认支持 **VPS 公网 IP + 端口直接登录**，出门使用电脑或手机浏览器即可管理节点，无需保持 SSH 隧道。域名和 HTTPS 可选；Cloudflare API Token 与网页进程隔离，并提供自动续签、配置校验、流量额度和备份恢复。采用 Python / Flask / Gunicorn / SQLite 与 sing-box 官方源码统计构建，前端无需外部 CDN。

**这不是旧 x-ui 的完整升级版，不使用闭源发布包。** 原有 Go 代码与 `install.sh` 保留，旧说明见 [README.legacy.md](README.legacy.md)。新代码位于 [personal-panel/](personal-panel/)。

## 安装与访问

支持运行 systemd 的 **Ubuntu 22.04+ / Debian 12+**，Python 3.10+，amd64 / arm64。暂不支持 Alpine / OpenRC。

以 **root 用户登录 VPS**，执行一行安装命令：

```bash
bash <(curl -fsSL --proto '=https' --proto-redir '=https' https://raw.githubusercontent.com/zbklk/x-ui/main/install-personal.sh)
```

普通用户先执行 `sudo -i`。安装时可设置管理端口，直接回车使用默认 **54322**；首次安装还会提示创建管理员账号与密码，密码至少 14 字符、输入不回显。

安装后半段可输入已解析到 VPS 的域名，自动创建简单 HTTPS 网站、申请证书、启用自动续签，并让面板共用证书，输出 **HTTPS 域名 + 管理端口** 登录地址。登录后新建 REALITY 会预填 SNI、目标域名和目标端口。没有域名可直接回车跳过，之后随时运行 `panelctl site 你的域名 --panel-https`。

安装完成后，直接在任何电脑或手机的浏览器打开安装输出的地址：

```text
填写域名并成功配置证书：https://你的域名:54322/
跳过域名设置：http://你的VPS公网IP:54322/
```

使用刚才设置的管理员账号和密码登录即可；**不需要 SSH 隧道，也不强制使用域名或固定来源 IP**。IPv6 地址需加方括号，例如 `http://[你的IPv6]:54322/`。无人值守安装不会创建默认账号，可在 VPS 执行 `panelctl admin` 创建。

填写域名时会自动启用 HTTPS；跳过域名时保留 IP + 端口的 HTTP 访问。HTTP 会明文传输登录信息；之后可按下文启用域名 HTTPS。已经配置好的 HTTPS 在升级时保留。

安装会尝试放行已启用的 UFW 中对应的管理 TCP 端口，不启用 UFW，也不改动 SSH 放行规则。**如启用了云平台安全组、云防火墙或其他主机防火墙，还需放行所选管理端口的 TCP。**统计端口 18387 始终只供本机使用，无需开放。

### 已有面板升级

再次执行上方同一条安装命令即可。原来的管理员、密码、节点、流量与证书保留；旧版仅本机访问的配置会自动切换为公网直连。若希望继续使用默认端口，端口提示直接回车即可，无需卸载重装。

0.2.0 以后通过 `panelctl access private` 明确选择的私有模式，会在下次升级中保留。

### 0.3.x 升级到 sing-box

再次运行同一条安装命令即可：自动安装 **sing-box 1.14.4**，读取现有节点生成新核心配置，校验成功后才停止本面板的 Xray 服务并切换。管理员、节点、UUID / 密钥、端口、累计流量、备份、HTTPS 面板与证书续签设置保留，原分享链接可继续使用。

切换时节点连接会短暂中断。新核心或逐用户统计 API 启动检查失败时，自动恢复原核心及访问设置。原 Xray 二进制和配置留作恢复依据，不卸载原来的独立旧 x-ui。

切换用于避开新版 Xray 的部分 REALITY ClientHello 兼容限制。自动化测试已验证不包含 ML-KEM 的客户端指纹可进行 REALITY Vision HTTPS 传输，也覆盖 sing-box 客户端连接；客户端仍需支持 VLESS / REALITY / Vision。已有节点可先保留原分享链接测试，无需重新生成密钥。

升级后可按下方“维护与恢复”检查 `core_engine`、版本及 `personal-core.service` 日志，确认实际运行的核心。

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
| 管理访问 | 安装填写域名后自动 HTTPS 域名 + 端口；跳过域名可用公网 IP + 端口；支持来源限制及私有模式 |
| 出站 | 默认仅 IPv4；可切换双栈；默认阻止访问本机及内网 |
| 配置 | 校验 REALITY 密钥对、TLS SNI、新端口和核心配置后写入；独立服务加载 |
| 证书 | 单个域名、Cloudflare 指定 Zone 的 Token、DNS-01、自动续签与加载钩子 |
| 自有网站 | 可选独立静态 HTTPS 小站、TLS 1.3 / HTTP/2、自有域名 REALITY 默认值、端口冲突与循环检查 |
| 恢复 | JSON 导出 / 恢复、上次配置回退、每日备份保留最近 7 份 |
| 核心 | 固定官方源码版本、统计构建 SHA-256 校验、更新前校验配置、失败恢复及二进制回滚 |

REALITY 可使用安装器创建的自有小站，或自行选择并验证其他 TLS 目标。REALITY 入站本身和 SS2022 无需证书；自有 HTTPS 目标网站及 TLS 协议需要证书。自有目标更便于维护，但不保证在所有网络下比第三方目标更合适。

防火墙需放行面板管理 TCP 端口及实际使用的节点 TCP 端口；SS2022 需要时同时放行该节点 UDP 端口。统计端口 18387 不对公网开放，原 SSH 放行规则照常保留。

## 可选：自有 HTTPS 网站与 REALITY 目标

域名的 A 记录指向本机 IPv4；如果添加 AAAA，也需指向本机可用 IPv6。**Cloudflare 记录使用 DNS only（灰云）**，让节点直接连接 VPS。按下一节创建只授权该 Zone 的 API Token，准备好 Zone ID。

新装或升级时输入该域名即可。也可以在升级到当前版本后单独执行：

```bash
sudo panelctl site www.example.com --panel-https
# 如需指定网站端口：
sudo panelctl site www.example.com --port 8443 --panel-https
```

脚本在 VPS 提示输入 Token（隐藏输入）及 Zone ID。已有同域名的凭据会复用。自动创建的网页文件位于 `/opt/personal-panel/site/`，独立 `personal-site.service` 运行；后续安装升级会覆盖内置网页。网站监听 IPv4 及系统支持的 IPv6。启动时验证证书链、域名、TLS 1.3 和 HTTP/2 首页；设置失败恢复原面板及小站配置。请另用浏览器确认公网网址能打开，云防火墙仍需手动放行。

默认优先选 **443**；被其他服务或节点占用时选 **8443 / 9443**。不会停止占用端口的服务。显式指定的端口不可用时直接报错。新建入站自动填入：

| 字段 | 示例：网站使用 443 | 网站使用 8443 时 |
| --- | --- | --- |
| SNI 域名 | `www.example.com` | `www.example.com` |
| REALITY 目标域名 | `www.example.com` | `www.example.com` |
| 目标端口 | `443` | `8443` |
| 入站端口 | 另选，例如 `20000` | 另选，例如 `20000` |

网站地址分别为 `https://www.example.com/` 或 `https://www.example.com:8443/`。域名字段不填写协议、路径或端口。**安装器会自动让管理面板共用证书**，面板地址为 `https://www.example.com:管理端口/`，例如 `https://www.example.com:54322/`；用安装时设置的管理员账号登录后即可创建节点。管理端口、节点、账号与来源限制保留；续签后网站及面板自动加载证书。原来的 `http://IP:管理端口/` 需改用 HTTPS 域名地址，HTTP 与 HTTPS 不在该端口并行提供。

单独执行 `panelctl site` 时，`--panel-https` 表示同时切换面板 HTTPS；省略此参数只创建网站并保留当前面板协议。切换失败会恢复原面板配置。明确选择过 `private` 的实例仍保留私有监听，需通过原有 SSH 隧道访问，不自动扩大来源范围。

**入站与网站不能占同一个监听端口。** 生成核心配置时，自有目标被转换为 `127.0.0.1:网站端口`，SNI 仍是你的域名，避免绕公网 DNS 或回到自身入站。新建节点使用默认值；已有节点不会被批量更改。若现有启用节点与新的小站配置冲突，需先调整或停用该节点再重试。

当前网站与节点 TLS 共用一个证书域名。如果已配置 `panel.example.com` 的证书，建站也应使用这个域名。域名切换与多个证书不在当前自动化范围。

```bash
sudo systemctl status personal-site.service
sudo journalctl -u personal-site.service -n 60 --no-pager
```

## Cloudflare 证书与自动续签

创建 API Token，权限为 `Zone → DNS → Edit`，资源只包含所属 Zone，例如 `example.com`。复制该 Zone 的 Zone ID。在服务器执行：

```bash
sudo panelctl cert panel.example.com
```

按提示输入 Token（不回显）与 Zone ID。无需 Global API Key。Token 授权的是整个 Zone 的 DNS 编辑能力，证书只签 `panel.example.com`；不是限制到单条记录。可限制 Token 到固定的 API 出口 IP，注意 IPv4 / IPv6；设置有效期后需提前替换。

当前管理一个证书域名，不申请通配符；DNS 验证不要求面板服务器开放入站 80/443，也不要求先把 A/AAAA 指向该服务器。TLS 入站的 SNI 需被证书覆盖。

专用 `personal-acme` 用户运行固定上游提交的 acme.sh，`personal-acme.timer` 每日自动检查是否需要续签，达到续签条件才申请新证书，无需手动操作；服务器重启后也会继续运行。完整证书及私钥安装后，校验配对，再通知服务加载。凭据不会经过网页，网页用户不能读取 Token；不自动升级执行 ACME 上游代码。

续签后，已启用的小站自动重启加载新证书；面板 HTTPS 和使用证书的 sing-box 入站也收到加载通知。同域名重复运行 `cert` / `site` 会复用凭据；更换 Token 使用 `sudo panelctl cert 你的域名 --replace-token`，按提示重新输入，不放入命令参数。

```bash
sudo systemctl status personal-acme.timer --no-pager
systemctl list-timers personal-acme.timer
sudo journalctl -u personal-acme.service -n 60 --no-pager
sudo systemctl start personal-acme.service
```

正常情况下 timer 为 `active (waiting)`，列表显示下一次检查时间。最后一条执行正常续签检查，不强制重新签发。自动续签需要 Cloudflare Token 持续有效；有有效期的 Token 请提前替换。不要公开环境文件、签发配置或调试日志中的凭据。

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
sudo /opt/personal-panel/core/sing-box version
sudo systemctl status personal-core.service --no-pager
sudo panelctl admin
sudo panelctl access show
sudo panelctl access public --port 54322
sudo panelctl core update
sudo panelctl core rollback
sudo systemctl restart personal-panel.service
sudo journalctl -u personal-core.service -n 60 --no-pager
sudo journalctl -u personal-panel-maintain.service -n 40 --no-pager
```

`panelctl status` 正常应显示 `"core_engine": "sing-box"`、`"core_status": "active"`，`core` 字段显示 sing-box 版本。当前核心日志使用 `personal-core.service`；`personal-xray.service` 属于迁移前的服务。核心可执行文件安装在上面的完整路径，无需系统全局的 `sing-box` 命令。

核心更新是手动操作：`panelctl core update` 安装当前面板清单固定的 sing-box 统计构建，校验 SHA-256、源码清单及现有配置，再替换核心；服务启动或统计 API 检查失败会恢复前一二进制。要获取更新的固定版本，先重新运行面板安装命令，再执行核心更新；不会直接换成缺少统计模块的上游默认包。配置更改或核心重启会短暂中断节点连接，仅重启面板不主动重启核心。

`panelctl core rollback` 需要此前核心更新留下的备份，只回滚到上一个 sing-box 二进制，不切换回 Xray。网页中的“回退上次配置”恢复节点配置，与核心二进制回滚分别使用。

再次运行新安装脚本可更新面板，短暂停止面板及统计任务。0.3.x 的 Xray 实例自动迁移到 sing-box；已经使用 sing-box 的实例保留现有核心，升级核心需显式运行更新命令。更新前 SQLite 备份至 `/var/backups/personal-panel/`，保留最近 7 份。

网页支持下载、恢复 JSON 备份及回退上次状态。备份包含节点私钥、用户凭据与流量，不含管理员密码、Cloudflare Token 或证书私钥。自动备份位于 `/var/lib/personal-panel/auto-backups/`，每天 UTC 日期一份、保留最近 7 份；离机保存请自行加密。

旧 x-ui 数据库不能直接导入：用不同端口并行测试，手动迁移需要的节点，再自行停用旧服务。不要把旧 `x-ui.db` 覆盖到新数据库。

## 内核来源与逐用户统计

默认使用 **sing-box 1.14.4**。为了保留流量统计及用户额度，内核由本仓库公开的 [GitHub Actions](.github/workflows/sing-box-core.yml) 从 **未修改的 SagerNet/sing-box 官方源码**构建，开启官方 `with_utls,with_v2ray_api` 编译标签；这不是上游的默认发布包，也没有修改协议或加入第三方补丁。

- 源码提交、Go 版本及编译标签：[singbox-source.json](personal-panel/singbox-source.json)。
- amd64 / arm64 构建、源码描述与许可证：[发布包](https://github.com/zbklk/x-ui/releases/tag/personal-sing-box-v1.14.4-1)。VPS 下载预先构建好的包，不在 VPS 编译。
- 下载地址与 SHA-256 固定在 [upstream.json](personal-panel/upstream.json)。安装还检查包内源码清单和统计模块，拒绝缺少逐用户统计的内核。
- 统计 API 只监听 `127.0.0.1:18387`。面板直接读取累计计数，不依赖 Xray 程序，也不开放到公网。重启代次及累计流量继续保存在原 SQLite 数据库。

## 服务与权限

| 服务 / 路径 | 用途 |
| --- | --- |
| `personal-panel.service` | 普通用户网页进程，无 sudo、root 或 Linux capabilities |
| `personal-core.service` | 独立普通用户 sing-box 核心，仅授予绑定低端口的能力 |
| `personal-site.service` | 独立 personal-site 用户，只读静态网站，仅授予绑定低端口的能力；不能读取面板数据库或 DNS Token |
| `personal-panel-maintain.timer` | 约每 15 秒采集流量、检查额度及到期 |
| `personal-core.path` | 固定服务处理配置加载请求，不提供任意命令接口 |
| `personal-acme.timer` / `personal-cert.path` | 独立续签；完整部署后通知服务加载 |
| `/opt/personal-panel` | root 拥有的代码、虚拟环境和核心 |
| `/opt/personal-panel/core/sing-box` | 当前 sing-box 可执行文件 |
| `/etc/personal-panel/panel.env` | root 管理的面板访问及核心设置 |
| `/var/lib/personal-panel` | 普通用户独占的数据库、备份及审计 |
| `/var/lib/personal-core` | sing-box 配置与上次配置，目录权限 0700 |
| `/etc/personal-panel/cloudflare.env` | root:root 0600；systemd 只传给证书服务 |
| `/var/lib/personal-acme` | ACME 用户独占的账户、Token 缓存和签发状态 |
| `/var/lib/personal-panel-tls` | 证书用户可写、面板用户只读；私钥 0640 |

密码使用 scrypt 哈希；随机会话 Token 只存摘要；Cookie 为 HttpOnly / SameSite=Strict，HTTPS 时启用 Secure；写请求检查 CSRF / Origin；按来源 IP 持久化限制登录失败次数，其他来源的失败不会锁住所有用户。拥有服务器 root 权限的人仍能读取节点密钥与证书。

## 限制与验证范围

- 当前版本没有旧 x-ui 的全部 Telegram、订阅、设备数限制、自定义完整 JSON 和传输方式，也没有旧数据库迁移器。
- 额度不是实时计费边界，约 15 秒检查一次，可能超额；异常重启前尚未采集的尾部流量可能丢失，不用于对外计费。
- `::` 在部分系统上接受双栈；严格仅 IPv6 入站需配合防火墙。网页进程不能完整试绑低于 1024 的端口；端口检查与实际绑定间也存在竞争窗口，请确认核心状态。
- 未来核心可能移除协议，更新前保留备份。初装固定版本见 `personal-panel/upstream.json`。
- 已验证认证、CSRF、IP 白名单、备份恢复、额度、续签流程模拟、迁移及更新失败恢复；sing-box 通过五种协议多用户真实传输 / 统计测试，包含 REALITY Vision 的真实 HTTPS、非 ML-KEM 指纹和 sing-box 客户端连接，以及域名解析到内网地址后的访问阻断。小站验证 TLS 1.3、HTTP/2 与证书域名。
- [GitHub Actions 验证记录](https://github.com/zbklk/x-ui/actions/runs/41181250619)：Python 3.10 / 3.12 测试通过；真实 systemd 环境覆盖旧核心迁移、启动失败恢复、原账号 HTTPS 登录、统计读取、配置加载及证书部署后的服务加载。
- 首次安装仍需在自己的 VPS 确认公网访问，并用自己的域名 / Token 完成真实 ACME 签发。自动化测试中的续签流程模拟不等于真实 CA 签发，也不构成第三方安全审计。

## 本地测试

```bash
cd personal-panel
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
# 下载并校验 upstream.json 指定的统计版 sing-box 和测试用 Xray 后：
SINGBOX_TEST_BINARY=/absolute/path/to/sing-box XRAY_TEST_BINARY=/absolute/path/to/xray .venv/bin/python -m unittest discover -s tests -v
```

`XRAY_TEST_BINARY` 仅用于跨核心兼容及旧版 Xray 相关测试，线上 sing-box 服务和逐用户统计不依赖 Xray。未设置测试二进制时，相应真实传输集成测试会跳过；完整验证方式见 [测试工作流](.github/workflows/personal-panel.yml)。

原项目与本仓库代码遵循根目录 [GPL-3.0 LICENSE](LICENSE)。
