import hashlib, secrets, json

# default admin
admin_pw = b"admin123"
salt = secrets.token_bytes(16)
dk = hashlib.pbkdf2_hmac('sha256', admin_pw, salt, 100_000)
creds = {"admin": {"salt": salt.hex(), "hash": dk.hex()}}

with open('admins.json', 'w', encoding='utf-8') as f:
    json.dump(creds, f, indent=2)

# empty users file
with open('users.json', 'w', encoding='utf-8') as f:
    json.dump({}, f, indent=2)

print('Created admins.json and users.json')
