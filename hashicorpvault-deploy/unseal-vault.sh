#!/bin/bash

# Check if credentials exist
if [ ! -f vault/credentials/unseal_key.txt ]; then
    echo "Error: Unseal key not found. Please run init-vault.sh first."
    exit 1
fi

# Set environment variables for Vault
export VAULT_SKIP_VERIFY=true
export VAULT_ADDR=https://127.0.0.1:8200

# Read the unseal key
UNSEAL_KEY=$(cat vault/credentials/unseal_key.txt)

# Check if Vault is sealed
SEAL_STATUS=$(docker exec -e VAULT_SKIP_VERIFY=true vault vault status -format=json 2>/dev/null | grep sealed || echo '{"sealed":true}')
if echo $SEAL_STATUS | grep -q '"sealed":false'; then
    echo "Vault is already unsealed!"
    docker exec -e VAULT_SKIP_VERIFY=true vault vault status
    exit 0
fi

# Unseal Vault
echo "Unsealing Vault..."
docker exec -e VAULT_SKIP_VERIFY=true vault vault operator unseal "$UNSEAL_KEY"

# Display the status
echo -e "\nVault Status:"
docker exec -e VAULT_SKIP_VERIFY=true vault vault status 