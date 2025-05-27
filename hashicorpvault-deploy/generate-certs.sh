#!/bin/bash

# Create directories if they don't exist
mkdir -p vault/config
mkdir -p vault/data

# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout vault/config/key.pem \
    -out vault/config/cert.pem \
    -subj '/CN=localhost'

# Set proper permissions for config directory
chmod 600 vault/config/key.pem
chmod 644 vault/config/cert.pem
chown -R 100:100 vault/config

# Set proper permissions for data directory
chown -R 100:100 vault/data
chmod 700 vault/data

# Create core directory with proper permissions
mkdir -p vault/data/core
chown -R 100:100 vault/data/core
chmod 700 vault/data/core

echo "Certificates generated and permissions set successfully" 