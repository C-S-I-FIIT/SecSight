#!/bin/bash

# Create directory for credentials if it doesn't exist
mkdir -p vault/credentials

# Set environment variables for Vault
export VAULT_SKIP_VERIFY=true
export VAULT_ADDR=https://127.0.0.1:8200

# Initialize Vault and save output to a temporary file
docker exec -e VAULT_SKIP_VERIFY=true vault vault operator init -key-shares=1 -key-threshold=1 > vault/credentials/temp_init.txt

# Extract the unseal key and root token
UNSEAL_KEY=$(grep "Unseal Key 1" vault/credentials/temp_init.txt | awk '{print $4}')
ROOT_TOKEN=$(grep "Initial Root Token" vault/credentials/temp_init.txt | awk '{print $4}')

# Save credentials to separate files with proper permissions
echo $UNSEAL_KEY > vault/credentials/unseal_key.txt
echo $ROOT_TOKEN > vault/credentials/root_token.txt

# Set proper permissions for credential files
chmod 600 vault/credentials/unseal_key.txt
chmod 600 vault/credentials/root_token.txt
chown -R 100:100 vault/credentials

# Unseal Vault using the key as an argument
docker exec -e VAULT_SKIP_VERIFY=true vault vault operator unseal "$UNSEAL_KEY"

# Clean up temporary file
rm vault/credentials/temp_init.txt

echo "Vault initialized successfully!"
echo "Unseal key saved to: vault/credentials/unseal_key.txt"
echo "Root token saved to: vault/credentials/root_token.txt"
echo "Please keep these credentials secure!"

# Display the status
docker exec -e VAULT_SKIP_VERIFY=true vault vault status 