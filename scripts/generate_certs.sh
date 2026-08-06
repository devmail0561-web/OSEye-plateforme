#!/usr/bin/env bash
# Generate a minimal PKI for development (CA + server cert + agent dev cert).
# Never use these certificates in production.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERTS_DIR="$REPO_ROOT/infra/certs"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "==> Generating dev PKI in $CERTS_DIR"

# 1. Root CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 \
  -key ca.key \
  -out ca.crt \
  -subj "/CN=OSEye-Dev-CA/O=OSEye/C=FR"

# 2. Server certificate (SAN: localhost + oseye-server)
openssl genrsa -out server.key 2048
openssl req -new \
  -key server.key \
  -out server.csr \
  -subj "/CN=oseye-server/O=OSEye/C=FR"
openssl x509 -req -days 365 \
  -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt \
  -extfile <(printf "subjectAltName=DNS:localhost,DNS:oseye-server,IP:127.0.0.1")

# 3. Agent dev certificate
openssl genrsa -out agent-dev.key 2048
openssl req -new \
  -key agent-dev.key \
  -out agent-dev.csr \
  -subj "/CN=agent-dev-00000000/O=OSEye/C=FR"
openssl x509 -req -days 90 \
  -in agent-dev.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out agent-dev.crt

# 4. JWT RS256 key pair
openssl genrsa -out jwt_private.pem 2048
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem

# Cleanup CSRs
rm -f server.csr agent-dev.csr

echo "==> Done. Generated files:"
ls -la "$CERTS_DIR"
echo ""
echo "  CA cert  : $CERTS_DIR/ca.crt"
echo "  Server   : $CERTS_DIR/server.{crt,key}"
echo "  Agent dev: $CERTS_DIR/agent-dev.{crt,key}"
echo "  JWT      : $CERTS_DIR/jwt_{private,public}.pem"
echo ""
echo "WARNING: These certificates are for development only. Never use in production."
