# Personal Panel 0.2.0

新实现的自用面板，不依赖旧 Go 面板或闭源发布包。

安装后默认通过 VPS 公网 IP + 管理端口直接登录，无需 SSH 隧道。已有 0.1.0 实例重新运行安装命令会保留账号与节点，并切换为公网访问。HTTPS 和私有模式均可选。

安装、访问、Cloudflare Token 自动续签、权限、备份及验证范围见 [根目录 README](../README.md)。安装入口为 [install-personal.sh](../install-personal.sh)。

开发测试先进入本目录：

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```
