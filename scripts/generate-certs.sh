#!/bin/bash
set -e

CERTS_DIR="${1:-./certs}"
VALIDITY_DAYS="${2:-3650}"

echo "Generating production TLS certificates..."
echo "Output directory: $CERTS_DIR"
echo "Validity period: $VALIDITY_DAYS days"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# 1. Generate CA (Certificate Authority)
echo "1. Generating CA certificate..."
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days "$VALIDITY_DAYS" -key ca.key -out ca.crt \
    -subj "/C=US/ST=California/L=San Francisco/O=AfterSec/OU=Security/CN=AfterSec Root CA"

# 2. Generate Server Certificate
echo "2. Generating server certificate..."
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=AfterSec/OU=Server/CN=aftersec-server"

# Create server certificate with SAN (Subject Alternative Names)
cat > server-ext.cnf <<EOF
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
DNS.2 = aftersec-server
DNS.3 = *.aftersec.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days "$VALIDITY_DAYS" -extfile server-ext.cnf

# 3. Generate Client Certificate (for mTLS)
echo "3. Generating client certificate..."
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=AfterSec/OU=Client/CN=aftersec-client"

cat > client-ext.cnf <<EOF
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days "$VALIDITY_DAYS" -extfile client-ext.cnf

# Cleanup temporary files
rm -f *.csr *.srl *.cnf

echo ""
echo "Certificate generation complete!"
echo "Generated files:"
echo "  - ca.crt, ca.key: Certificate Authority"
echo "  - server.crt, server.key: Server certificate for gRPC"
echo "  - client.crt, client.key: Client certificate for mTLS"
echo ""
echo "For production deployment:"
echo "  1. Keep ca.key and server.key secure (never commit to git)"
echo "  2. Distribute ca.crt to all clients for server verification"
echo "  3. Distribute client.crt and client.key to authorized clients for mTLS"
echo ""
echo "To verify certificates:"
echo "  openssl x509 -in server.crt -text -noout"
echo "  openssl verify -CAfile ca.crt server.crt"
echo "  openssl verify -CAfile ca.crt client.crt"
