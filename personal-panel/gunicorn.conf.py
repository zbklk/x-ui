"""Do not expose plaintext management listeners outside loopback."""
import ipaddress
import os
from pathlib import Path
from urllib.parse import urlsplit

bind = os.environ.get("PANEL_BIND", "127.0.0.1:54322")
address = ipaddress.ip_address(urlsplit("//" + bind).hostname)
tls = os.environ.get("PANEL_TLS", "off") == "on"
if not address.is_loopback:
    if not tls:
        raise RuntimeError("Public management listener requires PANEL_TLS=on")
    nets = [ipaddress.ip_network(n.strip()) for n in os.environ.get("PANEL_ALLOWED_CLIENTS", "").split(",") if n.strip()]
    if not nets or any(n.prefixlen == 0 for n in nets):
        raise RuntimeError("Public management listener requires a non-global client IP allowlist")
workers = 1
worker_class = "gthread"
threads = 4
timeout = 60
graceful_timeout = 20
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 4094
forwarded_allow_ips = ""  # Never trust browser-supplied X-Forwarded-* headers.
accesslog = None
errorlog = "-"
control_socket_disable = True
umask = 0o077
if tls:
    certfile = str(Path(os.environ.get("PANEL_TLS_DIR", "/var/lib/personal-panel-tls")) / "fullchain.pem")
    keyfile = str(Path(os.environ.get("PANEL_TLS_DIR", "/var/lib/personal-panel-tls")) / "key.pem")


def ssl_context(conf, default_ssl_context_factory):
    import ssl
    context = default_ssl_context_factory()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context
