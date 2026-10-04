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
git clone https://github.com/a-mx/messaging-app
cd ./messaging-app
cp .env.example .env
./nginx/generate_cert.sh
make run
```
Open `localhost` in your browser.