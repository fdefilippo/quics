#!/bin/bash
# Regenerate all test certificates with proper SANs (Subject Alternative Names)
# This fixes certificate validation errors when connecting to 127.0.0.1

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Regenerating all test certificates with SANs...${NC}"
echo "This will regenerate:"
echo "  - CA certificate"
echo "  - Server certificate (with SANs: localhost, 127.0.0.1)"
echo "  - Client certificate (with SAN: client)"
echo ""
echo -e "${YELLOW}WARNING: This will overwrite existing certificates!${NC}"
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}Aborted.${NC}"
    exit 1
fi

# Clean up old files (keep user certificates)
echo -e "${YELLOW}Cleaning up old certificates...${NC}"
rm -f ca.crt ca.key ca.srl
rm -f server.crt server.key server.csr server_new.csr
rm -f client.crt client.key client.csr

# 1. Generate CA
echo -e "${YELLOW}Generating new CA...${NC}"
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/CN=QUICS-Test-CA/O=QUICS Test Organization/C=IT"

# 2. Generate server certificate with SANs
echo -e "${YELLOW}Generating server certificate with SANs...${NC}"

# Create server config with SANs
cat > server.cnf << 'EOF'
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = localhost
O = QUICS Test Organization
C = IT

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# Generate server key
openssl genrsa -out server.key 2048

# Generate CSR
openssl req -new -key server.key -out server.csr -config server.cnf

# Sign certificate with SANs
openssl x509 -req -days 365 -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -extfile server.cnf -extensions req_ext

# 3. Generate client certificate
echo -e "${YELLOW}Generating client certificate...${NC}"

# Create client config
cat > client.cnf << 'EOF'
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[ dn ]
CN = client
O = QUICS Test Organization
C = IT
EOF

# Generate client key
openssl genrsa -out client.key 2048

# Generate CSR
openssl req -new -key client.key -out client.csr -config client.cnf

# Sign certificate
openssl x509 -req -days 365 -in client.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt

# Clean up temporary files
rm -f server.cnf client.cnf
rm -f ca.srl server.csr client.csr

# Set proper permissions
chmod 600 ca.key server.key client.key
chmod 644 ca.crt server.crt client.crt

echo -e "${GREEN}All certificates regenerated successfully!${NC}"
echo ""
echo "Files created:"
echo "  CA:              ca.crt, ca.key"
echo "  Server:          server.crt, server.key (with SANs: localhost, 127.0.0.1)"
echo "  Client:          client.crt, client.key"
echo ""
echo "To verify server certificate SANs:"
echo "  openssl x509 -in server.crt -text -noout | grep -A 5 'Subject Alternative Name'"
echo ""
echo "Note: User certificates in 'users/' directory are not affected."
echo "      You may need to regenerate user certificates if they need SANs."