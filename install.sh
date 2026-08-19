#!/usr/bin/env bash
# OSEye — Installer
# Usage: sudo bash install.sh [--docker] [--dev]
#
# Par defaut : installe les packages .deb (serveur + agent) et lance via systemd.
# --docker  : deploiement Docker (docker-compose)
# --dev     : redirige vers scripts/dev-install.sh
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RED='\033[0;31m'; DIM='\033[2m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}✓${RESET} $*"; }
step() { echo -e "\n${BOLD}$*${RESET}"; }
ask()  { read -rp "  $1 [${2}]: " _ans; echo "${_ans:-$2}"; }
die()  { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# ── Options ──────────────────────────────────────────────────────────────────
MODE="binary"
for arg in "$@"; do
  case "$arg" in
    --docker)  MODE="docker" ;;
    --dev)     exec bash scripts/dev-install.sh "${@:2}"; exit 0 ;;
    --help|-h)
      echo "Usage: sudo bash install.sh [--docker] [--dev]"
      echo ""
      echo "  (default)  Installe via packages .deb + systemd (zero Docker)"
      echo "  --docker   Deploiement Docker (docker-compose.prod.yml)"
      echo "  --dev      Environnement de developpement (redirige vers scripts/dev-install.sh)"
      exit 0
      ;;
    *) die "Option inconnue: $arg" ;;
  esac
done

echo -e "${BOLD}${CYAN}"
echo "  ___  ____  _______   _____"
echo " / _ \/ ___|| ____\ \ / / __|"
echo "| | | \___ \|  _|  \ V /| _|"
echo "| |_| |___) | |___  |_| | |___"
echo " \___/|____/|_____| |_| |_____|"
echo -e "${RESET}"
echo "  Installation — $(cat VERSION 2>/dev/null || echo 'dev')"
echo -e "  Mode: ${BOLD}${MODE}${RESET}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# MODE DOCKER (comportement legacy)
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$MODE" == "docker" ]]; then
    step "1. Verification des prerequis"
    for cmd in curl openssl docker; do
        command -v "$cmd" >/dev/null 2>&1 || die "$cmd requis"
        ok "$cmd present"
    done
    docker compose version >/dev/null 2>&1 || die "docker compose requis"
    ok "docker compose present"

    step "2. Configuration"
    DEFAULT_HOST=$(hostname -f 2>/dev/null || hostname)
    SERVER_HOST=$(ask "Hostname ou IP du serveur" "$DEFAULT_HOST")
    ADMIN_PASS=$(ask "Mot de passe administrateur" "$(openssl rand -base64 12 | tr -d '=+')")

    step "3. Initialisation (PKI)"
    if [[ ! -f /etc/oseye/certs/ca.crt ]]; then
        sudo mkdir -p /etc/oseye
        VERSION_TAG=$(cat VERSION 2>/dev/null || echo "latest")
        docker run --rm -v /etc/oseye:/etc/oseye \
            "oseye-server:${VERSION_TAG}" oseye-server init --hostname "$SERVER_HOST" 2>/dev/null || \
        sudo bash scripts/init-server.sh "$SERVER_HOST" 2>/dev/null || true
        ok "Certificats generes"
    else
        ok "Certificats deja presents"
    fi

    step "4. Lancement"
    COMPOSE="infra/docker/docker-compose.prod.yml"
    docker compose -f "$COMPOSE" up -d
    ok "Services demarres"

    echo ""
    echo -e "${GREEN}${BOLD}  OSEye deploye via Docker${RESET}"
    echo "  Logs : docker compose -f ${COMPOSE} logs -f"
    exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════════
# MODE BINAIRE (.deb + systemd)
# ═══════════════════════════════════════════════════════════════════════════════

if [[ "$(id -u)" -ne 0 ]]; then
    die "Ce script doit etre lance en root: sudo bash install.sh"
fi

# ── 1. Prerequis ─────────────────────────────────────────────────────────────
step "1. Verification des prerequis"
command -v openssl >/dev/null 2>&1 || die "openssl requis (apt install openssl)"
ok "openssl present"

DIST_DIR="$ROOT/dist"
VERSION=$(cat "$ROOT/VERSION" 2>/dev/null || echo "0.3.0-alpha.2")

# Determiner les packages
VER_DEB="${VERSION//-/\~}"
SERVER_DEB=$(find "$DIST_DIR" -name "oseye-server_${VER_DEB}*_amd64.deb" 2>/dev/null | head -1)
AGENT_DEB=$(find  "$DIST_DIR" -name "oseye-agent_${VER_DEB}*_amd64.deb"  2>/dev/null | head -1)
UI_DEB=$(find     "$DIST_DIR" -name "oseye-ui_${VER_DEB}*_amd64.deb"     2>/dev/null | head -1)

[[ -z "$SERVER_DEB" ]] && die "Package serveur introuvable dans dist/ (oseye-server_*_amd64.deb)"
[[ -z "$AGENT_DEB" ]]  && die "Package agent introuvable dans dist/ (oseye-agent_*_amd64.deb)"

ok "Packages trouves:"
echo -e "    ${DIM}$SERVER_DEB${RESET}"
echo -e "    ${DIM}$AGENT_DEB${RESET}"
[[ -n "$UI_DEB" ]] && echo -e "    ${DIM}$UI_DEB${RESET}" || echo -e "    ${DIM}oseye-ui : absent (optionnel)${RESET}"

# ── 2. Installation ──────────────────────────────────────────────────────────
step "2. Installation des packages"

dpkg -i "$SERVER_DEB"
ok "oseye-server installe"

dpkg -i "$AGENT_DEB"
ok "oseye-agent installe"

if [[ -n "$UI_DEB" ]]; then
    dpkg -i "$UI_DEB"
    ok "oseye-ui installe"
else
    echo -e "  ${DIM}oseye-ui absent — skip (installer separement avec : sudo dpkg -i oseye-ui_*.deb)${RESET}"
fi

# ── 3. Initialisation PKI ────────────────────────────────────────────────────
step "3. Initialisation (PKI + repertoires)"

if [[ -f /etc/oseye/certs/ca.crt ]] && [[ -f /etc/oseye/certs/server.crt ]]; then
    ok "PKI deja presente (skip)"
else
    oseye-server init
fi

# ── 4. Configuration ─────────────────────────────────────────────────────────
step "4. Configuration"

DEFAULT_HOST=$(hostname -f 2>/dev/null || hostname)
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
IP=${IP:-127.0.0.1}

echo -e "  ${DIM}Choisissez le backend de base de donnees :${RESET}"
echo -e "    ${DIM}1) sqlite   — embarque, zero dependance (recommande pour test/petite infra)${RESET}"
echo -e "    ${DIM}2) postgresql — production (necessite un serveur PostgreSQL)${RESET}"
DB_CHOICE=$(ask "Backend (1 ou 2)" "1")

if [[ "$DB_CHOICE" == "2" ]]; then
    DB_BACKEND="postgresql"
    DB_HOST=$(ask "PostgreSQL host" "localhost")
    DB_PORT=$(ask "PostgreSQL port" "5432")
    DB_NAME=$(ask "Database name" "oseye")
    DB_USER=$(ask "Database user" "oseye")
    read -rsp "  Database password: " DB_PASS; echo
    DB_URL="postgresql+asyncpg://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
else
    DB_BACKEND="sqlite"
    DB_URL="sqlite+aiosqlite:///var/lib/oseye/server/oseye.db"
fi

echo -e "  ${DIM}Bus d'evenements :${RESET}"
echo -e "    ${DIM}1) memoire  — embarque (recommande pour un seul serveur)${RESET}"
echo -e "    ${DIM}2) redis    — pour multi-process ou clustering${RESET}"
BUS_CHOICE=$(ask "Bus (1 ou 2)" "1")

REDIS_URL=""
if [[ "$BUS_CHOICE" == "2" ]]; then
    REDIS_URL=$(ask "Redis URL" "redis://localhost:6379/0")
fi

ADMIN_PASS=$(ask "Mot de passe admin" "$(openssl rand -base64 12 | tr -d '=+')")
ANALYST_PASS=$(ask "Mot de passe analyste" "$(openssl rand -base64 12 | tr -d '=+')")

SECRET_KEY=$(openssl rand -hex 32)
HMAC_KEY=$(openssl rand -hex 32)

# Ecriture server.env
cat > /etc/oseye/server.env <<EOF
OSEYE_DB_BACKEND=${DB_BACKEND}
OSEYE_DB_URL=${DB_URL}
OSEYE_REDIS_URL=${REDIS_URL}
OSEYE_GRPC_PORT=50051
OSEYE_GRPC_MAX_WORKERS=10
OSEYE_API_PORT=8000
OSEYE_API_HOST=0.0.0.0
OSEYE_API_CORS_ORIGINS=["http://localhost:5173","http://localhost:5174","https://${DEFAULT_HOST}"]
OSEYE_TLS_CERT_FILE=/etc/oseye/certs/server.crt
OSEYE_TLS_KEY_FILE=/etc/oseye/certs/server.key
OSEYE_TLS_CA_CERT_FILE=/etc/oseye/certs/ca.crt
OSEYE_TLS_CA_KEY_FILE=/etc/oseye/certs/ca.key
OSEYE_JWT_PRIVATE_KEY_PATH=/etc/oseye/certs/jwt_private.pem
OSEYE_JWT_PUBLIC_KEY_PATH=/etc/oseye/certs/jwt_public.pem
OSEYE_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
OSEYE_LOG_LEVEL=info
OSEYE_SERVICE_NAME=oseye-server
OSEYE_ENROLLMENT_TOKEN_DIR=/etc/oseye/enrollment_tokens
OSEYE_DATA_DIR=/var/lib/oseye/server
OSEYE_ML_CHECKPOINT_PATH=/var/lib/oseye/server/ml_checkpoint.pkl
OSEYE_DEFAULT_SURVEILLANCE_PROFILE=workstation
OSEYE_MANAGEMENT_API_ENABLED=true
OSEYE_UI_URL=http://localhost:5173
EOF
chown root:oseye-srv /etc/oseye/server.env
chmod 640 /etc/oseye/server.env

# Ecriture secrets.env
cat > /etc/oseye/secrets.env <<EOF
OSEYE_SECRET_KEY=${SECRET_KEY}
OSEYE_CHECKPOINT_HMAC_KEY=${HMAC_KEY}
OSEYE_ADMIN_PASSWORD=${ADMIN_PASS}
OSEYE_ANALYST_PASSWORD=${ANALYST_PASS}
EOF
chown root:oseye-srv /etc/oseye/secrets.env
chmod 600 /etc/oseye/secrets.env

ok "Configuration ecrite"

# ── 5. Demarrage serveur ─────────────────────────────────────────────────────
step "5. Demarrage du serveur"

systemctl daemon-reload
systemctl enable oseye-server
systemctl start oseye-server

echo "  Attente du serveur..."
for i in $(seq 1 15); do
    if curl -sf "http://localhost:8000/api/v1/health" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

if systemctl is-active --quiet oseye-server; then
    ok "Serveur demarre et operationnel"
else
    die "Le serveur n'a pas demarre. Verifier: journalctl -u oseye-server -n 30"
fi

# ── 6. Demarrage UI ──────────────────────────────────────────────────────────
if [[ -n "$UI_DEB" ]]; then
    step "6. Demarrage de l'UI"
    systemctl enable oseye-ui
    systemctl start oseye-ui
    if systemctl is-active --quiet oseye-ui; then
        ok "UI demarree sur http://localhost:5173"
    else
        echo -e "  ${RED}UI non demarree — verifier: journalctl -u oseye-ui -n 20${RESET}"
    fi
fi

# ── 7. Enrollment + demarrage agent ──────────────────────────────────────────
step "7. Enrollment et demarrage de l'agent"

# Generer un token d'enrollment
TOKEN=$(oseye-server enrollment token create --valid-hours 72 2>&1 | grep -i "token" | head -1 | awk '{print $NF}')
if [[ -z "$TOKEN" ]]; then
    TOKEN=$(ls /etc/oseye/enrollment_tokens/ 2>/dev/null | head -1)
fi

if [[ -z "$TOKEN" ]]; then
    die "Impossible de generer un token d'enrollment"
fi

echo -e "  Token: ${DIM}${TOKEN}${RESET}"
oseye-config enroll --server "${DEFAULT_HOST}:8000" --token "$TOKEN" --grpc-port 50051

systemctl enable oseye-agent
systemctl start oseye-agent
sleep 3

if systemctl is-active --quiet oseye-agent; then
    ok "Agent enrolle et demarre"
else
    echo -e "  ${RED}Agent non demarre — verifier: journalctl -u oseye-agent -n 20${RESET}"
fi

# ── Resume ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  OSEye installe et operationnel${RESET}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo ""
echo "  Serveur   : http://localhost:8000/api/v1/health"
[[ -n "$UI_DEB" ]] && echo "  UI        : http://localhost:5173"
echo "  gRPC      : localhost:50051"
echo "  Admin     : admin / ${ADMIN_PASS}"
echo "  Analyste  : analyst / ${ANALYST_PASS}"
echo ""
echo "  Commandes :"
echo "    systemctl status oseye-server    — etat du serveur"
echo "    systemctl status oseye-agent     — etat de l'agent"
echo "    oseye-server status              — sante detaillee"
echo "    journalctl -u oseye-server -f    — logs serveur"
echo "    journalctl -u oseye-agent -f     — logs agent"
echo ""
echo "  Desinstaller :"
echo "    sudo oseye-server uninstall --server --agent --purge"
echo ""
