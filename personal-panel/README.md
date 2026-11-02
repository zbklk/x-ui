# Personal Panel 0.5.0

新实现的自用面板，默认代理核心为 **sing-box 1.14.4**，支持 VLESS、Trojan、VMess、Shadowsocks 2022 和 Hysteria2，不依赖旧 Go 面板或闭源发布包。

从 0.3.x 升级时自动把本面板的 Xray 节点配置迁移到 sing-box；0.4.x 的 sing-box 若缺少 QUIC，安装器自动升级核心以启用 Hysteria2。保留账号、原节点、密钥、累计流量与证书，原分享链接可继续使用；启动检查失败恢复原核心。内核由 [公开工作流](../.github/workflows/sing-box-core.yml) 从未修改的官方源码构建，开启官方 `with_quic,with_utls,with_v2ray_api` 标签，支持 Hysteria2、REALITY 和逐用户流量统计。版本、源码提交及构建信息见 [singbox-source.json](singbox-source.json)。VPS 下载已构建并校验 SHA-256 的发布包。

安装时填写已解析域名后，自动使用 HTTPS 域名 + 管理端口登录，再创建节点；跳过域名时可通过 VPS 公网 IP + 管理端口登录。已有 0.1.0 实例重新运行安装命令会保留账号与节点，并切换为公网访问。明确选择的私有模式在升级时保留。

安装、访问、Cloudflare Token 自动续签、权限、备份及验证范围见 [根目录 README](../README.md)。安装入口为 [install-personal.sh](../install-personal.sh)。

安装时选择配置域名并提供 Cloudflare API Token 后，会自动创建独立 HTTPS 小站、签发与自动续签证书，让面板共用证书，并为新建 REALITY 入站预填域名与目标端口。已安装实例也可运行 `sudo panelctl site www.example.com --panel-https`；管理端口、已有节点与账号保留。续签 timer 每日检查，证书更新后通知网站、HTTPS 面板及使用证书的核心加载。

在 VPS 检查当前核心：

```bash
sudo panelctl status
sudo /opt/personal-panel/core/sing-box version
sudo journalctl -u personal-core.service -n 60 --no-pager
```

`core_engine` 应为 `sing-box`，`core_status` 应为 `active`。已迁移实例使用 `personal-core.service`，配置位于 `/var/lib/personal-core/config.json`，数据库仍位于 `/var/lib/personal-panel/panel.sqlite3`。

新建入站选择 **Hysteria2 · QUIC · TLS**，SNI 使用当前证书域名；支持多用户、额度、到期、分享二维码及可选 Salamander。请放行该节点端口 **UDP**，并使用支持 HY2 的客户端。证书及自动续签与原 TLS 节点共用。

重新执行安装脚本更新面板并按需启用 QUIC；已有 QUIC 核心保持原版本，其他升级可另执行 `sudo panelctl core update`，安装当前清单固定的统计构建。`sudo panelctl core rollback` 只恢复此前更新备份的 sing-box 二进制，不切换回 Xray；旧核心无法接受当前 HY2 配置时会拒绝回滚。详细步骤见根目录 README 的“维护与恢复”。

开发测试先进入本目录：

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
# 下载并校验 upstream.json 固定的统计版 sing-box 和测试工作流固定的 Xray 后：
SINGBOX_TEST_BINARY=/absolute/path/to/sing-box XRAY_TEST_BINARY=/absolute/path/to/xray .venv/bin/python -m unittest discover -s tests -v
```

`XRAY_TEST_BINARY` 仅用于跨核心兼容及旧版 Xray 相关测试，线上运行不依赖 Xray。未设置测试二进制时，相应集成测试会跳过。完整 CI 及真实 systemd 迁移验证见 [测试工作流](../.github/workflows/personal-panel.yml)。
