#!/bin/bash
# initialize_encryption.sh
# Generates a 32-byte key file for MongoDB Transparent Data Encryption (TDE)

KEYFILE="mongo_keyfile"

if [ ! -f "$KEYFILE" ]; then
    echo "Generating new MongoDB encryption key file..."
    openssl rand -base64 32 > "$KEYFILE"
    
    # Ownership typically needs to map to MongoDB user (UID 1001 for Percona, 999 for Standard Mongo)
    # inside the container context to avoid read rejections.
    # Set permissions strictly to 400.
    sudo chown 1001:1001 "$KEYFILE" || echo "Note: sudo chown failed, check your permissions."
    sudo chmod 400 "$KEYFILE"
    
    echo "Key file $KEYFILE created successfully."
else
    echo "Key file $KEYFILE already exists. Skipping."
fi
