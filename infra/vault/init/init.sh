#!/bin/sh
set -eu

echo "[vault-init] waiting for vault..."
until wget -qO- "$VAULT_ADDR/v1/sys/health" >/dev/null 2>&1; do
  sleep 1
done

echo "[vault-init] enabling secrets engines (idempotent)..."
vault secrets enable -path=transit transit >/dev/null 2>&1 || true
vault secrets enable -path=secret kv-v2 >/dev/null 2>&1 || true

echo "[vault-init] creating transit key (idempotent): $TRANSIT_KEY_NAME"
vault write -f "transit/keys/$TRANSIT_KEY_NAME" >/dev/null 2>&1 || true

echo "[vault-init] ensuring pepper in KV (idempotent)..."
# KV v2 put/get via CLI: vault kv put secret/dcs pepper=...
if vault kv get secret/dcs >/dev/null 2>&1; then
  echo "[vault-init] pepper already exists"
else
  PEPPER="$(head -c 32 /dev/urandom | base64)"
  vault kv put secret/dcs pepper="$PEPPER" >/dev/null
  echo "[vault-init] pepper created"
fi

echo "[vault-init] writing backend policy..."
vault policy write backend-policy - <<EOF
path "transit/encrypt/$TRANSIT_KEY_NAME" {
  capabilities = ["update"]
}
path "transit/decrypt/$TRANSIT_KEY_NAME" {
  capabilities = ["update"]
}

# KV v2 read path = secret/data/*
path "secret/data/*" {
  capabilities = ["read"]
}
EOF

echo "[vault-init] creating backend token with fixed id: $BACKEND_TOKEN_ID (PoC)"
# Token ID fixé pour simplifier (à ne jamais faire en prod)
vault token create -id="$BACKEND_TOKEN_ID" -policy="backend-policy" -orphan >/dev/null 2>&1 || true

echo "[vault-init] done"
