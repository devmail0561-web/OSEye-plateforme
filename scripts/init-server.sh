#!/usr/bin/env bash
# init-server.sh — OSEye server first-run initialization
#
# Generates production PKI (CA, server cert, JWT keys) and an enrollment token.
# Must be run once before starting the server stack.
# Re-running when PKI already exists exits with an error (idempotent guard).
#
# Usage:
#   sudo bash scripts/init-server.sh
#
# Optional environment overrides:
#   OSEYE_CERTS_DIR            (default: /etc/oseye/certs)
#   OSEYE_ENROLLMENT_TOKEN_DIR (default: /etc/oseye/enrollment_tokens)
#   OSEYE_ADMIN_PASSWORD       (prompted if not set)

set -euo pipefail

CERTS_DIR="${OSEYE_CERTS_DIR:-/etc/oseye/certs}"
TOKEN_DIR="${OSEYE_ENROLLMENT_TOKEN_DIR:-/etc/oseye/enrollment_tokens}"

echo "==> OSEye Server Initialization"
echo "    Certs dir : $CERTS_DIR"
echo "    Token dir : $TOKEN_DIR"
echo ""

# ── Guard against accidental re-initialization ──────────────────────────────
if [[ -f "$CERTS_DIR/ca.crt" ]]; then
    echo "ERROR: PKI already initialized ($CERTS_DIR/ca.crt exists)."
    echo "       To reinitialize, remove $CERTS_DIR/ca.* manually and re-run."
    exit 1
fi

# ── Create directories ────────────────────────────────────────────────────────
install -d -m 700 "$CERTS_DIR"
install -d -m 700 "$TOKEN_DIR"
install -d -m 700 /etc/oseye/agent_keys
install -d -m 750 /etc/oseye/plugins
install -d -m 700 /etc/oseye/plugin_keys
install -d -m 750 /var/lib/oseye
install -d -m 755 /var/run/oseye

# ── Detect server hostname and IP for SAN ────────────────────────────────────
SERVER_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="127.0.0.1"
fi

echo "    Detected hostname : $SERVER_HOSTNAME"
echo "    Detected IP       : $SERVER_IP"
echo ""

# ── 1. Root CA (4096-bit RSA, 10 years) ──────────────────────────────────────
echo "==> Generating CA (4096-bit, 10 years)..."
(umask 077; openssl genrsa -out "$CERTS_DIR/ca.key" 4096 2>/dev/null)
openssl req -new -x509 -days 3650 \
    -key "$CERTS_DIR/ca.key" \
    -out "$CERTS_DIR/ca.crt" \
    -subj "/CN=OSEye-CA/O=OSEye/C=FR" \
    2>/dev/null

# ── 2. Server certificate (4096-bit, 825 days, SAN = hostname + IP) ──────────
echo "==> Generating server certificate..."
(umask 077; openssl genrsa -out "$CERTS_DIR/server.key" 4096 2>/dev/null)
openssl req -new \
    -key "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.csr" \
    -subj "/CN=${SERVER_HOSTNAME}/O=OSEye/C=FR" \
    2>/dev/null
openssl x509 -req -days 825 \
    -in "$CERTS_DIR/server.csr" \
    -CA "$CERTS_DIR/ca.crt" \
    -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERTS_DIR/server.crt" \
    -extfile <(printf \
        "subjectAltName=DNS:%s,DNS:localhost,IP:%s,IP:127.0.0.1" \
        "$SERVER_HOSTNAME" "$SERVER_IP") \
    2>/dev/null
rm -f "$CERTS_DIR/server.csr"

# ── 3. JWT RS256 key pair (4096-bit) ─────────────────────────────────────────
echo "==> Generating JWT RS256 key pair..."
(umask 077; openssl genrsa -out "$CERTS_DIR/jwt_private.pem" 4096 2>/dev/null)
openssl rsa -in "$CERTS_DIR/jwt_private.pem" \
    -pubout -out "$CERTS_DIR/jwt_public.pem" \
    2>/dev/null

# ── 4. Admin password ─────────────────────────────────────────────────────────
if [[ -z "${OSEYE_ADMIN_PASSWORD:-}" ]]; then
    echo ""
    read -r -s -p "Set OSEYE_ADMIN_PASSWORD: " OSEYE_ADMIN_PASSWORD
    echo ""
fi
if [[ ${#OSEYE_ADMIN_PASSWORD} -lt 12 ]]; then
    echo "ERROR: Password must be at least 12 characters."
    exit 1
fi

# ── 5. Enrollment token ───────────────────────────────────────────────────────
TOKEN=$(openssl rand -hex 32)
TOKEN_FILE="$TOKEN_DIR/$TOKEN"
(umask 077; date +%s > "$TOKEN_FILE")

# ── 6. Display summary ────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║           OSEye Server Initialization Complete                   ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║ CA cert       : $CERTS_DIR/ca.crt"
echo "║ Server cert   : $CERTS_DIR/server.{crt,key}"
echo "║ JWT keys      : $CERTS_DIR/jwt_{private,public}.pem"
echo "║"
echo "║ Server address: $SERVER_HOSTNAME"
echo "║ API port      : 8000"
echo "║ gRPC port     : 50051"
echo "║"
echo "║ Enrollment token (valid 24h):"
echo "║   $TOKEN"
echo "║"
echo "║ To enroll an agent, run on the agent host:"
echo "║   OSEYE_SERVER=$SERVER_HOSTNAME:8000 \\"
echo "║   OSEYE_TOKEN=$TOKEN \\"
echo "║   sudo bash enroll-agent.sh"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║ IMPORTANT: set OSEYE_ADMIN_PASSWORD in /etc/oseye/secrets.env  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Next: copy packaging/config/server.env.example to /etc/oseye/server.env"
echo "      copy packaging/config/secrets.env.example to /etc/oseye/secrets.env"
echo "      then: docker compose -f infra/docker/docker-compose.prod.yml up -d"
