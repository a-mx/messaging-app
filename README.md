# Messaging App
A simple Flask web application for secure user-to-user messaging.

## Features
- User registration and login
- Password hashing with `Argon2id`
- TOTP 2FA
- Message encryption (RSA + AES-GCM)
- Digital message signatures (RSA + SHA-256)
- SQLite database
  
## Setup

```bash
cp .env.example .env
./nginx/generate_cert.sh
make venv
make run
```