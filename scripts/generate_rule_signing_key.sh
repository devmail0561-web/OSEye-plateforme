#!/usr/bin/env bash
# Generate an Ed25519 key pair for OSEye rule signing.
# Private key → /etc/oseye/certs/rule_signing.key  (set OSEYE_RULE_SIGNING_KEY_PATH)
# Public key  → /etc/oseye/certs/rule_signing.pub.pem (deploy to agents for future verification)
set -euo pipefail

OUTDIR="${1:-/etc/oseye/certs}"
PRIV="$OUTDIR/rule_signing.key"
PUB="$OUTDIR/rule_signing.pub.pem"

mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"

openssl genpkey -algorithm Ed25519 -out "$PRIV"
chmod 600 "$PRIV"

openssl pkey -in "$PRIV" -pubout -out "$PUB"
chmod 644 "$PUB"

echo "Rule signing key pair generated:"
echo "  Private : $PRIV"
echo "  Public  : $PUB"
echo ""
echo "Set in server environment:"
echo "  OSEYE_RULE_SIGNING_KEY_PATH=$PRIV"
echo ""
echo "Deploy the public key DER bytes to agents:"
echo "  openssl pkey -in $PRIV -pubout -outform DER | base64"
