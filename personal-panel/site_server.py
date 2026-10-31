"""A separate, read-only HTTPS site with TLS 1.3 and HTTP/2 support."""
import asyncio
import errno
import os
from pathlib import Path
import socket
import ssl

from hypercorn.asyncio import serve
from hypercorn.config import Config

ROOT = Path(__file__).resolve().parent / "site"
PAGES = {"/": ("index.html", b"text/html; charset=utf-8"),
         "/style.css": ("style.css", b"text/css; charset=utf-8")}


class SiteConfig(Config):
    def create_ssl_context(self):
        context = super().create_ssl_context()
        # REALITY requires X25519 (or a supported hybrid group). Use the stable
        # shared baseline across Debian/Ubuntu OpenSSL and Xray versions.
        context.set_ecdh_curve("X25519")
        # Hypercorn replaces OpenSSL's default options. REALITY expects the TLS
        # 1.3 compatibility ChangeCipherSpec record sent by ordinary web servers.
        context.options |= ssl.OP_ENABLE_MIDDLEBOX_COMPAT
        return context


async def app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            event = await receive()
            if event["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif event["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    elif scope["type"] == "http":
        path, method = scope.get("path", ""), scope["method"]
        headers = [(b"x-content-type-options", b"nosniff"),
                   (b"content-security-policy", b"default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'"),
                   (b"referrer-policy", b"no-referrer")]
        if method not in ("GET", "HEAD"):
            status, body, mime = 405, b"Method not allowed\n", b"text/plain; charset=utf-8"
            headers.append((b"allow", b"GET, HEAD"))
        elif path in PAGES:
            filename, mime = PAGES[path]
            status, body = 200, (ROOT / filename).read_bytes()
            headers.append((b"cache-control", b"public, max-age=300"))
        else:
            status, body, mime = 404, b"Page not found\n", b"text/plain; charset=utf-8"
        headers.extend([(b"content-type", mime), (b"content-length", str(len(body)).encode())])
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": b"" if method == "HEAD" else body})


def listeners(port):
    """Give Hypercorn explicit v4/v6 sockets; never depend on OS dual-stack defaults."""
    sockets = []
    try:
        for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            listener = None
            try:
                listener = socket.socket(family, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind((address, port))
                listener.set_inheritable(True)
                sockets.append(listener)
            except OSError as error:
                if listener:
                    listener.close()
                if family == socket.AF_INET6 and error.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL, errno.ENETUNREACH):
                    continue
                raise
        return sockets
    except BaseException:
        for listener in sockets:
            listener.close()
        raise


def main():
    port = int(os.environ.get("PANEL_SITE_PORT", "443"))
    if not 1 <= port <= 65535:
        raise ValueError("Invalid site port")
    folder = Path(os.environ.get("PANEL_TLS_DIR", "/var/lib/personal-panel-tls"))
    config = SiteConfig()
    config.certfile = str(folder / "fullchain.pem")
    config.keyfile = str(folder / "key.pem")
    config.alpn_protocols = ["h2", "http/1.1"]
    config.include_server_header = False
    config.accesslog = None
    config.read_timeout = 10
    config.ssl_handshake_timeout = 10
    config.keep_alive_timeout = 5
    config.graceful_timeout = 2
    config.shutdown_timeout = 3
    config.h2_max_concurrent_streams = 32
    config.h2_max_header_list_size = 16384
    bound = listeners(port)
    # fd:// transfers ownership to Hypercorn. detach avoids double-closing the fd.
    config.bind = ["fd://" + str(listener.detach()) for listener in bound]
    asyncio.run(serve(app, config))


if __name__ == "__main__":
    main()
