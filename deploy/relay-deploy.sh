#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Deploy the chat relay to the production box (5.161.241.93).
#
# WHY IT MATTERS RIGHT NOW. The relay held ONE subscription per connection and
# each `subscribe` overwrote the last — while every client drains several (its
# bootstrap inbox, where Welcomes arrive, plus one traffic mailbox per open
# conversation). So any client with even one conversation lost its bootstrap
# subscription and could never receive another Welcome. That is why cross-device
# chat did not work, and why it could not be repaired. The fix is server-side;
# rebuilding the apps alone changes nothing.
#
# NOTE: the relay's state is IN-MEMORY by design (delivered = deleted,
# undelivered = expired). A restart FORFEITS queued blobs. That is the retention
# promise, not a defect — but it means any Welcome currently in flight is lost and
# must be re-sent (tap "Re-establish" once after the restart).
#
#   Usage:  deploy/relay-deploy.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

BOX="${ZAT4_BOX:-root@5.161.241.93}"
KEY="${ZAT4_SSH_KEY:-$HOME/.ssh/id_zat4}"
ZIG="${ZIG:-$HOME/zig-x86_64-linux-0.16.0/zig}"

# ReleaseSafe + an explicit linux target: a native build SIGILLs on the box.
echo "[relay] building (ReleaseSafe, x86_64-linux)..."
"$ZIG" build -Doptimize=ReleaseSafe -Dtarget=x86_64-linux
[ -f zig-out/bin/zat4-relay ] || { echo "[relay] no binary produced" >&2; exit 1; }

echo "[relay] uploading..."
scp -i "$KEY" zig-out/bin/zat4-relay "$BOX:/root/zat4/zat4-relay.new"

echo "[relay] swapping + restarting..."
ssh -i "$KEY" "$BOX" 'set -e
  cd /root/zat4
  # Keep the binary we are replacing: a rollback is then one cp + restart.
  cp -f /usr/local/bin/zat4-relay ./zat4-relay.bak 2>/dev/null || true
  # The running binary is "Text file busy" — stop before cp.
  systemctl stop zat4-relay
  cp -f ./zat4-relay.new /usr/local/bin/zat4-relay
  chmod 755 /usr/local/bin/zat4-relay
  systemctl start zat4-relay
  sleep 1
  systemctl is-active zat4-relay
  systemctl status zat4-relay --no-pager -n 5 | tail -5
'
echo "[relay] deployed. Rollback:  ssh $BOX 'systemctl stop zat4-relay && cp /root/zat4/zat4-relay.bak /usr/local/bin/zat4-relay && systemctl start zat4-relay'"
