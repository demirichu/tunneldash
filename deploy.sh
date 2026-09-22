#!/usr/bin/env bash
set -e

if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

VPS_HOST="${VPS_HOST:-root@10.0.0.1}"
VPS_KEY="${VPS_KEY:-$HOME/.ssh/kvm}"
REMOTE_DIR="${REMOTE_DIR:-/root/tunneldash}"

echo "==> Deploying to ${VPS_HOST}..."

sudo chown -R "$USER:$USER" ./publish 2>/dev/null || true

ssh -i "${VPS_KEY}" "${VPS_HOST}" "systemctl stop tunneldash || true"
scp -i "${VPS_KEY}" ./publish/tunneldash "${VPS_HOST}:${REMOTE_DIR}/"
scp -i "${VPS_KEY}" ./index.html "${VPS_HOST}:${REMOTE_DIR}/"
ssh -i "${VPS_KEY}" "${VPS_HOST}" "chmod +x ${REMOTE_DIR}/tunneldash && systemctl start tunneldash"

echo "==> Done."