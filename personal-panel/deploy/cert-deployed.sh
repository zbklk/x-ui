#!/bin/bash
set -euo pipefail
chmod 640 /var/lib/personal-panel-tls/key.pem /var/lib/personal-panel-tls/fullchain.pem
# The root-owned path unit validates the pair before reloading either service.
printf '%s\n' "$(date +%s%N)" > /var/lib/personal-panel-tls/reload.trigger
