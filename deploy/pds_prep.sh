#!/bin/bash
# Prep an Ubuntu 26.04 (resolute) box for the official PDS installer:
#  1. Install Docker from Ubuntu's OWN repos (the installer's external Docker
#     repo has no 'resolute' build yet; its install block is gated on
#     `! docker version`, so a working docker makes it skip that step).
#  2. Patch the installer's OS allowlist to accept 'resolute'.
set -e
export DEBIAN_FRONTEND=noninteractive

echo "=== installing Docker from Ubuntu repos ==="
apt-get update -qq
apt-get install -y docker.io docker-compose-v2 >/dev/null
systemctl enable --now docker
docker version >/dev/null 2>&1 && echo "docker daemon OK: $(docker --version)"
echo "compose: $(docker compose version 2>&1 | head -1)"

echo "=== patching installer OS check to allow resolute (26.04) ==="
sed -i 's/ == "noble" \]\]/ == "noble" || "${DISTRIB_CODENAME}" == "resolute" ]]/' /root/pds-installer.sh
echo "resolute clauses now present: $(grep -c resolute /root/pds-installer.sh)"
