# Personal Panel 0.3.0

新实现的自用面板，不依赖旧 Go 面板或闭源发布包。

安装后默认通过 VPS 公网 IP + 管理端口直接登录，无需 SSH 隧道。已有 0.1.0 实例重新运行安装命令会保留账号与节点，并切换为公网访问。HTTPS 和私有模式均可选。

安装、访问、Cloudflare Token 自动续签、权限、备份及验证范围见 [根目录 README](../README.md)。安装入口为 [install-personal.sh](../install-personal.sh)。

0.3.0 可在安装时输入已解析域名，自动创建独立 HTTPS 小站、签发与自动续签证书，并为新建 REALITY 入站预填域名与目标端口。已安装实例也可运行 `sudo panelctl site www.example.com`；已有节点与面板访问方式保留。

开发测试先进入本目录：

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```
