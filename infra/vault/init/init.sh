#!/bin/sh
set -eu

export VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"

INIT_FILE="/vault/file/init.txt"
TRANSIT_KEY_NAME="${TRANSIT_KEY_NAME:-cinema-dcs}"
BACKEND_TOKEN_ID="${BACKEND_TOKEN_ID:-backend-token}"

# Si Vault n'est pas initialisé, on init et on persiste les secrets
if vault status 2>/dev/null | grep -q "Initialized.*false"; then
  echo "[vault-init] init vault (1 share)"
  mkdir -p /vault/file
  vault operator init -key-shares=1 -key-threshold=1 | tee "$INIT_FILE" >/dev/null
else
  echo "[vault-init] vault already initialized"
fi

# On lit les infos depuis le fichier persistant
UNSEAL_KEY="$(awk '/Unseal Key 1:/{print $4}' "$INIT_FILE")"
ROOT_TOKEN="$(awk '/Initial Root Token:/{print $4}' "$INIT_FILE")"

# Unseal si besoin
SEALED="$(vault status 2>/dev/null | awk '/Sealed/{print $2}')"
if [ "$SEALED" = "true" ]; then
  echo "[vault-init] unseal"
  vault operator unseal "$UNSEAL_KEY" >/dev/null
fi

# Login root
echo "[vault-init] login root"
vault login "$ROOT_TOKEN" >/dev/null

# Enable engines (idempotent)
vault secrets list | grep -q '^transit/' || vault secrets enable -path=transit transit >/dev/null
vault secrets list | grep -q '^secret/'  || vault secrets enable -path=secret kv-v2    >/dev/null

# Transit key (idempotent)
vault read "transit/keys/${TRANSIT_KEY_NAME}" >/dev/null 2>&1 || vault write -f "transit/keys/${TRANSIT_KEY_NAME}" >/dev/null

# Pepper (idempotent)
vault kv get secret/dcs >/dev/null 2>&1 || vault kv put secret/dcs pepper="dev-pepper-change-me" >/dev/null

# Policy backend
cat >/tmp/backend-policy.hcl <<EOF
path "transit/encrypt/${TRANSIT_KEY_NAME}" { capabilities = ["update"] }
path "transit/decrypt/${TRANSIT_KEY_NAME}" { capabilities = ["update"] }
path "secret/data/dcs" { capabilities = ["read"] }
EOF
vault policy write backend /tmp/backend-policy.hcl >/dev/null

# Token backend (recrée si besoin)
vault token lookup "${BACKEND_TOKEN_ID}" >/dev/null 2>&1 || vault token create -id "${BACKEND_TOKEN_ID}" -policy=backend -orphan >/dev/null

echo "[vault-init] done"
