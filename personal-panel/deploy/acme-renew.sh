#!/bin/bash
set -euo pipefail
umask 027
: "${CF_Token:?Token missing}"
: "${CF_Zone_ID:?Zone ID missing}"
: "${PANEL_DOMAIN:?Certificate domain missing}"
[[ "$PANEL_DOMAIN" =~ ^[a-zA-Z0-9.-]+$ ]] || exit 1
acme=(/opt/personal-panel/acme/acme.sh --home /opt/personal-panel/acme
  --config-home /var/lib/personal-acme/config --cert-home /var/lib/personal-acme/certs
  --server letsencrypt)
conf="/var/lib/personal-acme/certs/${PANEL_DOMAIN}_ecc/${PANEL_DOMAIN}.conf"
marker="/var/lib/personal-acme/${PANEL_DOMAIN}.installed"
if [[ ! -f "$conf" ]]; then
  "${acme[@]}" --issue --dns dns_cf -d "$PANEL_DOMAIN" --keylength ec-256
elif [[ -f "$marker" ]]; then
  # acme.sh returns 2 when renewal is not yet due. This is a successful daily check.
  rc=0
  "${acme[@]}" --renew -d "$PANEL_DOMAIN" --ecc || rc=$?
  [[ $rc == 0 || $rc == 2 ]] || exit "$rc"
fi
if [[ ! -f "$marker" ]]; then
  "${acme[@]}" --install-cert -d "$PANEL_DOMAIN" --ecc \
    --key-file /var/lib/personal-panel-tls/key.pem \
    --fullchain-file /var/lib/personal-panel-tls/fullchain.pem \
    --reloadcmd /opt/personal-panel/deploy/cert-deployed.sh
  touch "$marker"
fi
