# Personal Panel 0.4.0

新实现的自用面板，默认代理核心为 sing-box，不依赖旧 Go 面板或闭源发布包。

从 0.3.x 升级时自动把本面板的 Xray 节点配置迁移到 sing-box，保留账号、节点、密钥、累计流量与证书。统计内核由公开工作流从固定官方源码构建，只开启官方统计模块，不修改协议代码；启动检查失败恢复原核心。

安装时填写已解析域名后，自动使用 HTTPS 域名 + 管理端口登录，再创建节点；跳过域名时可通过 VPS 公网 IP + 管理端口登录。已有 0.1.0 实例重新运行安装命令会保留账号与节点，并切换为公网访问。明确选择的私有模式在升级时保留。

安装、访问、Cloudflare Token 自动续签、权限、备份及验证范围见 [根目录 README](../README.md)。安装入口为 [install-personal.sh](../install-personal.sh)。

安装会自动创建独立 HTTPS 小站、签发与自动续签证书，让面板共用证书，并为新建 REALITY 入站预填域名与目标端口。已安装实例也可运行 `sudo panelctl site www.example.com --panel-https`；管理端口、已有节点与账号保留。

开发测试先进入本目录：

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```
