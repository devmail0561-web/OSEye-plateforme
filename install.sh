#!/usr/bin/env bash
# OSEye — Installer
# Usage: sudo bash install.sh [--docker] [--dev] [--version X.Y.Z]
#
# Par defaut : telecharge et installe les packages .deb depuis GitHub Releases.
# --docker   : deploiement Docker (docker-compose)
# --dev      : redirige vers scripts/dev-install.sh
# --version  : version a installer (defaut: derniere release)
# --local    : utilise les packages dans dist/ (pour test en local)
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
INSTALL_VERSION=""
LOCAL=false
REPO="devmail0561-web/OSEye-plateforme"

for arg in "$@"; do
  case "$arg" in
    --docker)         MODE="docker" ;;
    --dev)            exec bash scripts/dev-install.sh "${@:2}"; exit 0 ;;
    --local)          LOCAL=true ;;
    --version=*)      INSTALL_VERSION="${arg#--version=}" ;;
    --version)        shift; INSTALL_VERSION="$1" ;;
    --help|-h)
      echo "Usage: sudo bash install.sh [--docker] [--dev] [--version X.Y.Z] [--local]"
      echo ""
      echo "  (default)  Telecharge et installe depuis GitHub Releases"
      echo "  --docker   Deploiement Docker (docker-compose.prod.yml)"
      echo "  --dev      Environnement de developpement"
      echo "  --version  Version a installer (ex: 0.3.0-alpha.2)"
      echo "  --local    Utilise les packages dans dist/ (test local)"
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
command -v curl    >/dev/null 2>&1 || die "curl requis (apt install curl)"
ok "openssl + curl presents"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# ── Localisation des packages ─────────────────────────────────────────────────
if [[ "$LOCAL" == true ]]; then
    # Mode local : packages dans dist/
    DIST_DIR="$ROOT/dist"
    VERSION=$(cat "$ROOT/VERSION" 2>/dev/null || echo "0.3.0-alpha.2")
    VER_DEB="${VERSION//-/\~}"
    SERVER_DEB=$(find "$DIST_DIR" -name "oseye-server_${VER_DEB}*_amd64.deb" 2>/dev/null | head -1)
    AGENT_DEB=$(find  "$DIST_DIR" -name "oseye-agent_${VER_DEB}*_amd64.deb"  2>/dev/null | head -1)
    UI_DEB=$(find     "$DIST_DIR" -name "oseye-ui_${VER_DEB}*_amd64.deb"     2>/dev/null | head -1)
    [[ -z "$SERVER_DEB" ]] && die "Package serveur introuvable dans dist/"
    [[ -z "$AGENT_DEB"  ]] && die "Package agent introuvable dans dist/"
    ok "Packages locaux: $DIST_DIR"
else
    # Mode GitHub Releases : telechargement
    if [[ -z "$INSTALL_VERSION" ]]; then
        echo "  Recherche de la derniere version..."
        INSTALL_VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" \
            | grep '"tag_name"' | grep -v 'latest' | head -1 \
            | sed 's/.*"v\?\([^"]*\)".*/\1/')
        [[ -z "$INSTALL_VERSION" ]] && die "Impossible de determiner la derniere version. Utilisez --version X.Y.Z"
    fi
    ok "Version : $INSTALL_VERSION"
    VERSION="$INSTALL_VERSION"
    VER_DEB="${VERSION//-/\~}"
    BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"

    echo "  Telechargement des packages..."
    SERVER_DEB="$TMP_DIR/oseye-server_${VER_DEB}_amd64.deb"
    AGENT_DEB="$TMP_DIR/oseye-agent_${VER_DEB}_amd64.deb"
    UI_DEB="$TMP_DIR/oseye-ui_${VER_DEB}_amd64.deb"

    curl -fsSL -o "$SERVER_DEB" "${BASE_URL}/oseye-server_${VER_DEB}_amd64.deb" \
        || die "Package serveur introuvable sur la release v${VERSION}"
    ok "oseye-server telecharge"

    curl -fsSL -o "$AGENT_DEB" "${BASE_URL}/oseye-agent_${VER_DEB}_amd64.deb" \
        || die "Package agent introuvable sur la release v${VERSION}"
    ok "oseye-agent telecharge"

    # UI optionnelle — pas d'echec si absente
    if curl -fsSL -o "$UI_DEB" "${BASE_URL}/oseye-ui_${VER_DEB}_amd64.deb" 2>/dev/null; then
        ok "oseye-ui telecharge"
    else
        UI_DEB=""
        echo -e "  ${DIM}oseye-ui absent de la release — skip${RESET}"
    fi

    # Verification SHA256 si disponible
    SHA_FILE="$TMP_DIR/SHA256SUMS"
    if curl -fsSL -o "$SHA_FILE" "${BASE_URL}/SHA256SUMS" 2>/dev/null; then
        (cd "$TMP_DIR" && sha256sum -c SHA256SUMS --ignore-missing 2>/dev/null) \
            && ok "SHA256 verifie" || echo -e "  ${DIM}SHA256 non verifie (optionnel)${RESET}"
    fi
fi

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
    echo -e "  ${DIM}oseye-ui non installe (optionnel — sudo dpkg -i oseye-ui_*.deb)${RESET}"
fi

# ── 3. Initialisation (PKI + repertoires) ────────────────────────────────────
step "3. Initialisation"

if [[ -f /etc/oseye/certs/ca.crt ]] && [[ -f /etc/oseye/certs/server.crt ]]; then
    ok "PKI deja presente (skip — utiliser 'oseye-server init --force' pour regenerer)"
else
    oseye-server init
fi

# ── 4. Configuration ─────────────────────────────────────────────────────────
step "4. Configuration"

if [[ -f /etc/oseye/server.env ]] && [[ -f /etc/oseye/secrets.env ]]; then
    ok "Configuration deja presente (skip — supprimer server.env/secrets.env pour reconfigurer)"
else
    # Deleguer entierement au wizard oseye-server setup
    oseye-server setup
fi

# Lire le mot de passe admin depuis secrets.env pour l'afficher dans le resume
ADMIN_PASS=$(grep OSEYE_ADMIN_PASSWORD /etc/oseye/secrets.env 2>/dev/null | cut -d= -f2 || echo "voir /etc/oseye/secrets.env")

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
DEFAULT_HOST=$(hostname -f 2>/dev/null || hostname)
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
echo "  Analyste  : voir /etc/oseye/secrets.env"
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
