#!/bin/bash
# Generate user certificates with UID, email, and name fields
# Usage: ./generate-user-cert.sh [userid] [email] [fullname]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 [userid] [email] [fullname]"
    echo "  userid:  User ID (e.g., jsmith)"
    echo "  email:   Email address (e.g., john.smith@example.com)"
    echo "  fullname: Full name (e.g., 'John Smith')"
    echo ""
    echo "If arguments are not provided, they will be prompted interactively."
    echo ""
    echo "Example: $0 jsmith john.smith@example.com 'John Smith'"
}

# Check if openssl is available
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: openssl is not installed${NC}"
    exit 1
fi

# Prompt for arguments if not provided
if [ $# -lt 3 ]; then
    echo -e "${YELLOW}Certificate Generation${NC}"
    echo "-------------------"
    
    if [ $# -lt 1 ]; then
        read -p "Enter User ID (e.g., jsmith): " USERID
    else
        USERID="$1"
    fi
    
    if [ $# -lt 2 ]; then
        read -p "Enter Email Address (e.g., john.smith@example.com): " EMAIL
    else
        EMAIL="$2"
    fi
    
    if [ $# -lt 3 ]; then
        read -p "Enter Full Name (e.g., 'John Smith'): " FULLNAME
    else
        FULLNAME="$3"
    fi
else
    USERID="$1"
    EMAIL="$2"
    FULLNAME="$3"
fi

# Validate inputs
if [ -z "$USERID" ]; then
    echo -e "${RED}Error: User ID cannot be empty${NC}"
    exit 1
fi

if [ -z "$EMAIL" ]; then
    echo -e "${RED}Error: Email cannot be empty${NC}"
    exit 1
fi

if [ -z "$FULLNAME" ]; then
    echo -e "${RED}Error: Full name cannot be empty${NC}"
    exit 1
fi

# Check if CA exists
if [ ! -f "ca.crt" ] || [ ! -f "ca.key" ]; then
    echo -e "${YELLOW}CA certificate not found. Generating new CA...${NC}"
    openssl genrsa -out ca.key 2048
    openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
        -subj "/CN=QUICS-CA/O=QUICS Organization/C=IT"
    echo -e "${GREEN}CA generated: ca.crt, ca.key${NC}"
fi

# Create output directory for user certificate
USER_CERT_DIR="users/$USERID"
mkdir -p "$USER_CERT_DIR"

echo -e "${YELLOW}Generating certificate for user: $USERID${NC}"
echo "  Email:    $EMAIL"
echo "  Full Name: $FULLNAME"

# Generate private key
openssl genrsa -out "$USER_CERT_DIR/$USERID.key" 2048

# Create certificate signing request with UID field
# Using -subj with multiple attributes: CN, UID, emailAddress
# Note: UID field uses OID 0.9.2342.19200300.100.1.1
# We'll use the subjectAltName extension for email as well
cat > "$USER_CERT_DIR/$USERID.cnf" << EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = $FULLNAME
UID = $USERID
emailAddress = $EMAIL
O = QUICS Organization
C = IT

[ req_ext ]
subjectAltName = email:$EMAIL
EOF

# Generate CSR using the config file
openssl req -new -key "$USER_CERT_DIR/$USERID.key" \
    -out "$USER_CERT_DIR/$USERID.csr" \
    -config "$USER_CERT_DIR/$USERID.cnf"

# Sign the certificate with CA
openssl x509 -req -days 365 \
    -in "$USER_CERT_DIR/$USERID.csr" \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$USER_CERT_DIR/$USERID.crt" \
    -extfile "$USER_CERT_DIR/$USERID.cnf" -extensions req_ext

# Create a combined PEM file for client use
cat "$USER_CERT_DIR/$USERID.crt" "$USER_CERT_DIR/$USERID.key" > "$USER_CERT_DIR/$USERID.pem"

# Set proper permissions
chmod 600 "$USER_CERT_DIR/$USERID.key"
chmod 600 "$USER_CERT_DIR/$USERID.pem"
chmod 644 "$USER_CERT_DIR/$USERID.crt"

# Create a convenience script to copy certificates to ~/.quicsc
cat > "$USER_CERT_DIR/install-to-client.sh" << 'EOF'
#!/bin/bash
# Script to copy certificates to client configuration directory

set -e

USERID=$(basename "$(dirname "$(realpath "$0")")")
CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLIENT_DIR="$HOME/.quicsc"

echo "Installing certificates for user: $USERID"
echo "Source: $CERT_DIR"
echo "Target: $CLIENT_DIR"

mkdir -p "$CLIENT_DIR"

# Copy certificate and key
cp -v "$CERT_DIR/$USERID.crt" "$CLIENT_DIR/public.crt"
cp -v "$CERT_DIR/$USERID.key" "$CLIENT_DIR/private.key"

# Set proper permissions
chmod 600 "$CLIENT_DIR/private.key"
chmod 644 "$CLIENT_DIR/public.crt"

echo "Done. Certificates installed to $CLIENT_DIR"
echo "You can now use quicsc without specifying --client-cert/--client-key"
EOF

chmod +x "$USER_CERT_DIR/install-to-client.sh"

echo -e "${GREEN}Certificate generated successfully!${NC}"
echo ""
echo "Files created:"
echo "  Private key:        $USER_CERT_DIR/$USERID.key"
echo "  Certificate:        $USER_CERT_DIR/$USERID.crt"
echo "  Combined PEM:       $USER_CERT_DIR/$USERID.pem"
echo "  CSR:                $USER_CERT_DIR/$USERID.csr (can be deleted)"
echo "  Config:             $USER_CERT_DIR/$USERID.cnf (can be deleted)"
echo ""
echo "To install these certificates for use with the client:"
echo "  cd $USER_CERT_DIR"
echo "  ./install-to-client.sh"
echo ""
echo "This will copy the certificate and key to ~/.quicsc/"
echo ""
echo "To verify the certificate contents:"
echo "  openssl x509 -in $USER_CERT_DIR/$USERID.crt -text -noout | grep -A1 'Subject:'"
echo "  openssl x509 -in $USER_CERT_DIR/$USERID.crt -text -noout | grep -A1 'Subject Alternative Name:'"