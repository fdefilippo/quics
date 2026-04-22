# Test Certificates

These certificates are for development and testing only.

## Files

- `ca.crt` - Certificate Authority certificate
- `ca.key` - CA private key
- `server.crt` - Server certificate
- `server.key` - Server private key
- `client.crt` - Client certificate
- `client.key` - Client private key
- `*.csr` - Certificate signing requests (can be deleted)
- `*.srl` - Serial number files (can be deleted)

## Regeneration

To regenerate all certificates:

```bash
# CA
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=TestCA"

# Server
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# Client
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=client"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
```

## Security Note

These certificates are self-signed and should NOT be used in production.