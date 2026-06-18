#!/bin/bash
# Configure the PDS to mint *.zat4.com handles (default is *.pds.zat4.com),
# while the PDS service itself stays at pds.zat4.com.
set -e

# 1. Tell the PDS that handles live under .zat4.com.
if ! grep -q "PDS_SERVICE_HANDLE_DOMAINS" /pds/pds.env; then
  echo "PDS_SERVICE_HANDLE_DOMAINS=.zat4.com" >> /pds/pds.env
  echo "[pds.env] added PDS_SERVICE_HANDLE_DOMAINS=.zat4.com"
fi

# 2. Make Caddy serve (and auto-TLS) the *.zat4.com handle hostnames.
sed -i 's/\*\.pds\.zat4\.com, pds\.zat4\.com/*.zat4.com, pds.zat4.com/' /pds/caddy/etc/caddy/Caddyfile
echo "[Caddyfile] site block now:"
grep -E "zat4.com \{|reverse_proxy" /pds/caddy/etc/caddy/Caddyfile

# 3. Restart the stack so both pick up the changes.
echo "[restart] restarting pds stack..."
systemctl restart pds
sleep 6
echo "[containers]"
docker ps --format "  {{.Names}}  {{.Status}}"
