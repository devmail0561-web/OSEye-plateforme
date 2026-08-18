#!/usr/bin/env bash
# OSEye — Installer
# bash install.sh
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RED='\033[0;31m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}✓${RESET} $*"; }
step() { echo -e "\n${BOLD}$*${RESET}"; }
ask()  { read -rp "  $1 [${2}]: " _ans; echo "${_ans:-$2}"; }
die()  { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo -e "${BOLD}${CYAN}"
echo "  ___  ____  _______   _____"
echo " / _ \/ ___|| ____\ \ / / __|"
echo "| | | \___ \|  _|  \ V /| _|"
echo "| |_| |___) | |___  |_| | |___"
echo " \___/|____/|_____| |_| |_____|"
echo -e "${RESET}"
echo "  Installation — $(cat VERSION 2>/dev/null || echo 'dev')"
echo ""

# ─────────────────────────────────────────────────────────────
# 1. PRÉREQUIS
# ─────────────────────────────────────────────────────────────
step "1. Vérification des prérequis"

install_if_missing() {
    local cmd="$1" pkg="${2:-$1}"
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd présent"
    else
        echo "  → Installation de $pkg..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get install -y "$pkg" -qq
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y "$pkg" -q
        elif command -v brew >/dev/null 2>&1; then
            brew install "$pkg" -q
        else
            die "$cmd introuvable et impossible à installer automatiquement."
        fi
        ok "$pkg installé"
    fi
}

install_if_missing curl
install_if_missing openssl
install_if_missing docker

# Docker Compose
if ! docker compose version >/dev/null 2>&1; then
    echo "  → Installation de docker compose plugin..."
    sudo apt-get install -y docker-compose-plugin -qq 2>/dev/null || \
    sudo dnf install -y docker-compose-plugin -q 2>/dev/null || \
    die "docker compose plugin introuvable. Installer Docker Desktop ou docker-compose-plugin."
fi
ok "docker compose présent"

# ─────────────────────────────────────────────────────────────
# 2. CONFIGURATION
# ─────────────────────────────────────────────────────────────
step "2. Configuration"

# Hostname
DEFAULT_HOST=$(hostname -f 2>/dev/null || hostname)
SERVER_HOST=$(ask "Hostname ou IP du serveur" "$DEFAULT_HOST")

# Mot de passe admin
ADMIN_PASS=$(ask "Mot de passe administrateur" "$(openssl rand -base64 12 | tr -d '=+')")

# UI
UI_URL=$(ask "URL de l'interface web (laisser vide si non utilisée)" "")

echo ""
ok "Configuration enregistrée"

# ─────────────────────────────────────────────────────────────
# 3. INITIALISATION (PKI + secrets)
# ─────────────────────────────────────────────────────────────
step "3. Initialisation"

VERSION_TAG=$(cat VERSION 2>/dev/null || echo "latest")

if [[ ! -f /etc/oseye/certs/ca.crt ]]; then
    echo "  → Génération des certificats (CA, serveur, JWT)..."
    sudo mkdir -p /etc/oseye
    docker run --rm \
        -v /etc/oseye:/etc/oseye \
        "ghcr.io/devmail0561-web/oseye-plateforme/oseye-server:${VERSION_TAG}" \
        oseye-server init \
        --hostname "$SERVER_HOST" 2>/dev/null || \
    ( echo "  → Image non disponible — génération locale via oseye-server init" && \
      sudo bash scripts/init-server.sh "$SERVER_HOST" 2>/dev/null ) || \
    echo "  → Skip PKI (sera générée au premier démarrage)"
    ok "Certificats prêts"
else
    ok "Certificats déjà présents"
fi

echo "  → Génération des secrets..."
sudo mkdir -p /etc/oseye/secrets
sudo chmod 700 /etc/oseye/secrets
if [[ ! -f /etc/oseye/secrets/secret_key.txt ]]; then
    printf '%s' "$(openssl rand -hex 16)"       | sudo tee /etc/oseye/secrets/secret_key.txt >/dev/null
    printf '%s' "$(openssl rand -hex 32)"       | sudo tee /etc/oseye/secrets/hmac_key.txt >/dev/null
    printf '%s' "$ADMIN_PASS"                   | sudo tee /etc/oseye/secrets/admin_password.txt >/dev/null
    printf '%s' "$(openssl rand -base64 16)"    | sudo tee /etc/oseye/secrets/analyst_password.txt >/dev/null
    printf '%s' "$(openssl rand -base64 16)"    | sudo tee /etc/oseye/secrets/db_password.txt >/dev/null
    printf '%s' "$(openssl rand -base64 16)"    | sudo tee /etc/oseye/secrets/redis_password.txt >/dev/null
    sudo chmod 600 /etc/oseye/secrets/*.txt
    ok "Secrets générés"
else
    ok "Secrets déjà présents"
fi

# Injecter UI_URL dans server.env si configurée
if [[ -n "$UI_URL" ]]; then
    echo "OSEYE_UI_URL=${UI_URL}" | sudo tee -a /etc/oseye/server.env >/dev/null 2>&1 || true
fi

# ─────────────────────────────────────────────────────────────
# 4. LANCEMENT
# ─────────────────────────────────────────────────────────────
step "4. Lancement"

COMPOSE="infra/docker/docker-compose.prod.yml"
echo "  → Démarrage des services..."
docker compose -f "$COMPOSE" pull --quiet 2>/dev/null || true
docker compose -f "$COMPOSE" up -d
ok "Services démarrés"

# Attendre que le serveur réponde
echo "  → Attente du serveur..."
for i in $(seq 1 30); do
    if curl -sf "http://localhost:8000/api/v1/health" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

if curl -sf "http://localhost:8000/api/v1/health" >/dev/null 2>&1; then
    ok "Serveur opérationnel"
else
    echo "  (Le serveur met plus de temps à démarrer — vérifier : docker compose -f $COMPOSE logs)"
fi

# Token d'enrollment
echo "  → Génération du token d'enrollment..."
ENROLL_TOKEN=$(docker exec oseye-server oseye-server enrollment token create 2>/dev/null \
    | grep "Token" | awk '{print $3}') || ENROLL_TOKEN=""

# ─────────────────────────────────────────────────────────────
# RÉSUMÉ
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  OSEye installé et démarré                ${RESET}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${RESET}"
echo ""
echo "  API       : https://${SERVER_HOST}/api/v1/health"
[[ -n "$UI_URL" ]] && echo "  UI        : ${UI_URL}"
echo "  Admin     : ${ADMIN_PASS}"
echo ""
[[ -n "$ENROLL_TOKEN" ]] && echo "  Token enrollment agent :"
[[ -n "$ENROLL_TOKEN" ]] && echo "    oseye-config enroll --server ${SERVER_HOST}:50051 --token ${ENROLL_TOKEN}"
echo ""
echo "  Arrêter   : docker compose -f ${COMPOSE} down"
echo "  Logs      : docker compose -f ${COMPOSE} logs -f"
echo "  Réinstaller un token : docker exec oseye-server oseye-server enrollment token create"
echo ""
