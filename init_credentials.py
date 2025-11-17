#!/usr/bin/env python3
import hashlib, secrets, json, sys

# Generate proper hashed admin credentials
admin_pw = b"admin123"
salt = secrets.token_bytes(16)
dk = hashlib.pbkdf2_hmac('sha256', admin_pw, salt, 100_000)
creds = {"admin": {"salt": salt.hex(), "hash": dk.hex()}}

# Write to admins.json
with open('admins.json', 'w', encoding='utf-8') as f:
    json.dump(creds, f, indent=2)

print("✓ admins.json created with hashed default admin (admin / admin123)")
print(json.dumps(creds, indent=2))

# Also create empty users.json
with open('users.json', 'w', encoding='utf-8') as f:
    json.dump({}, f, indent=2)

print("✓ users.json created (empty)")
