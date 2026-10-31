"""Explicit public/private management modes; optional TLS in either mode."""
import os
from pathlib import Path
from access import AccessPolicy

policy = AccessPolicy.from_env()
bind = policy.bind
tls = policy.tls
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
