openssl genrsa -out ./nginx/ssl/cert.key
openssl req -new -x509 -days 365 -key ./nginx/ssl/cert.key -out ./nginx/ssl/cert.crt