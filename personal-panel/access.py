"""Management access policy shared by Gunicorn, Flask and the root CLI."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from urllib.parse import urlsplit

DEFAULT_HOSTS = ("localhost", "127.0.0.1", "[::1]")


@dataclass(frozen=True)
class AccessPolicy:
    mode: str
    bind: str
    address: object
    port: int
    tls: bool
    hosts: tuple
    networks: tuple

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        mode = env.get("PANEL_ACCESS", "private")
        if mode not in ("public", "private"):
            raise ValueError("PANEL_ACCESS must be public or private")
        bind = env.get("PANEL_BIND", "127.0.0.1:54322")
        try:
            parsed = urlsplit("//" + bind)
            address, port = ipaddress.ip_address(parsed.hostname), parsed.port
            if parsed.username or parsed.password or parsed.path or not port or not 1024 <= port <= 65535:
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError("PANEL_BIND requires an IP address and port 1024–65535") from None
        if mode == "private" and not address.is_loopback:
            raise ValueError("Use panelctl access public to enable a public listener")
        tls = env.get("PANEL_TLS", "off")
        if tls not in ("on", "off"):
            raise ValueError("PANEL_TLS must be on or off")
        clients = env.get("PANEL_ALLOWED_CLIENTS", "0.0.0.0/0,::/0" if mode == "public" else "127.0.0.0/8,::1/128")
        networks = tuple(ipaddress.ip_network(n.strip()) for n in clients.split(",") if n.strip())
        if not networks:
            raise ValueError("PANEL_ALLOWED_CLIENTS cannot be empty")
        hosts = tuple(h.strip().lower().strip("[]") for h in env.get("PANEL_ALLOWED_HOSTS", ",".join(DEFAULT_HOSTS)).split(",") if h.strip())
        return cls(mode, bind, address, port, tls == "on", hosts, networks)

    def accepts_host(self, raw_host):
        try:
            parsed = urlsplit("//" + raw_host)
            hostname = parsed.hostname
            # Reject userinfo, unbracketed IPv6, invalid ports and authority tricks.
            if not hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
                return False
            _ = parsed.port
            hostname = hostname.lower()
            if hostname in self.hosts:
                return True
            if self.mode == "public":
                # Literal IP access works without discovering the machine's public
                # address. Arbitrary DNS names remain blocked against rebinding.
                ipaddress.ip_address(hostname)
                return True
        except (TypeError, ValueError):
            pass
        return False

    def accepts_client(self, raw_address):
        try:
            address = ipaddress.ip_address(raw_address)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            return any(address in network for network in self.networks)
        except (ValueError, TypeError):
            return False


def make_bind(address, port):
    address = ipaddress.ip_address(address)
    return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"


def access_url(policy, public_address=""):
    address = public_address if policy.mode == "public" else str(policy.address)
    address = address or "VPS_IP"
    if ":" in address and not address.startswith("["):
        address = "[" + address + "]"
    return f"{'https' if policy.tls else 'http'}://{address}:{policy.port}/"
