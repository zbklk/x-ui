"""Compile the existing panel state for unmodified sing-box 1.14+."""
import base64
import time

from core import PRIVATE_IPS, PanelError, active_client, owned_site


def singbox_config(state, usage=None, now=None, stats_port=18387, tls_dir="/var/lib/personal-panel-tls"):
    usage, now = usage or {}, time.time() if now is None else now
    settings, site = state["settings"], owned_site()
    strategy = "ipv4_only" if settings["ipv4_only"] else "prefer_ipv4"
    config = {
        "log": {"level": "warn" if settings["loglevel"] == "warning" else settings["loglevel"], "timestamp": True},
        "dns": {"servers": [{"type": "udp", "tag": "dns-primary", "server": "1.1.1.1"},
                            {"type": "udp", "tag": "dns-secondary", "server": "8.8.8.8"}]},
        "inbounds": [], "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct", "default_domain_resolver": {"server": "dns-primary", "strategy": strategy},
                  "rules": [{"action": "resolve", "strategy": strategy}]},
        "experimental": {"v2ray_api": {"listen": f"127.0.0.1:{stats_port}", "stats": {"enabled": True, "users": []}}}}
    if settings["ipv4_only"]:
        config["outbounds"][0]["inet4_bind_address"] = "0.0.0.0"
        config["route"]["rules"].append({"ip_cidr": ["::/0"], "action": "reject"})
    if settings["block_private"]:
        # Resolve before testing addresses, so domain requests cannot bypass the
        # private-address policy. Direct dials use those resolved addresses.
        config["route"]["rules"].append({"ip_cidr": PRIVATE_IPS, "action": "reject"})
    for node in state["nodes"]:
        clients = [c for c in node["clients"] if active_client(c, usage, now)]
        if not node["enabled"] or not clients:
            continue
        if site and node["port"] == site["port"]:
            raise PanelError(f"入站端口不能与自有 HTTPS 小站端口 {site['port']} 相同，请选择其他入站端口")
        protocol = node["protocol"].split("-")[0]
        inbound = {"type": "shadowsocks" if protocol == "shadowsocks2022" else protocol,
                   "tag": node["id"], "listen": node["listen"], "listen_port": node["port"], "users": []}
        for client in clients:
            name = client["id"] + "@personal-panel"
            user = {"name": name, "uuid" if protocol in ("vless", "vmess") else "password": client["secret"]}
            if node["protocol"] == "vless-reality":
                user["flow"] = "xtls-rprx-vision"
            if protocol == "vmess":
                user["alterId"] = 0
            inbound["users"].append(user)
            config["experimental"]["v2ray_api"]["stats"]["users"].append(name)
        if protocol == "shadowsocks2022":
            inbound.update(method="2022-blake3-aes-128-gcm", password=node["server_key"])
        elif node["protocol"] == "vless-reality":
            target = node["dest"]
            if site and target == site["domain"]:
                if node["dest_port"] != site["port"]:
                    raise PanelError(f"自有域名的 REALITY 目标端口应为小站端口 {site['port']}")
                target = "127.0.0.1"
            private = base64.b64decode(node["private_key"] + "=" * (-len(node["private_key"]) % 4), altchars=b"-_")
            inbound["tls"] = {"enabled": True, "server_name": node["sni"], "reality": {
                "enabled": True, "handshake": {"server": target, "server_port": node["dest_port"]},
                "private_key": base64.urlsafe_b64encode(private).decode().rstrip("="), "short_id": [node["short_id"]]}}
        else:
            inbound["tls"] = {"enabled": True, "server_name": node["sni"], "min_version": "1.2",
                              "certificate_path": tls_dir + "/fullchain.pem", "key_path": tls_dir + "/key.pem"}
            if protocol == "hysteria2":
                inbound["tls"].update(min_version="1.3", alpn=["h3"])
                if node.get("obfs_password"):
                    inbound["obfs"] = {"type": "salamander", "password": node["obfs_password"]}
            if "ws" in node["protocol"]:
                inbound["transport"] = {"type": "ws", "path": node["path"]}
        config["inbounds"].append(inbound)
    return config
