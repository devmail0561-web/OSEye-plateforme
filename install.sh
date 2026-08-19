#!/usr/bin/env bash
# OSEye — Installeur local (machine unique)
#
# Ce script installe le serveur, l'UI et l'agent sur la MEME machine.
# Il est destine aux tests, demonstrations et petites infrastructures.
#
# PRODUCTION (machines separees) :
#   Serveur  : sudo bash install.sh --server-only   sur la machine serveur
#   Agent    : sudo bash install.sh --agent-only --server <HOST>:<PORT> --token <TOKEN>
#              sur chaque machine a surveiller
#
# Usage: sudo bash install.sh [OPTIONS]
#   (aucune)         Installe serveur + UI + agent sur cette machine
#   --server-only    Installe uniquement le serveur et l'UI
#   --agent-only     Installe uniquement l'agent (requiert --server et --token)
#   --server HOST    Adresse du serveur OSEye (pour --agent-only)
#   --token TOKEN    Token d'enrollment (pour --agent-only)
#   --version X.Y.Z  Version a installer (defaut: derniere release)
#   --local          Utilise les packages dans dist/ (test local)
#   --docker         Deploiement Docker Compose
#   --dev            Environnement de developpement
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RED='\033[0;31m'; DIM='\033[2m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}✓${RESET} $*"; }
step() { echo -e "\n${BOLD}$*${RESET}"; }
ask()  { read -rp "  $1 [${2}]: " _ans; echo "${_ans:-$2}"; }
die()  { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# ── Options ──────────────────────────────────────────────────────────────────
MODE="binary"       # binary | docker
SCOPE="all"         # all | server-only | agent-only
INSTALL_VERSION=""
LOCAL=false
REPO="devmail0561-web/OSEye-plateforme"
AGENT_SERVER=""     # adresse serveur pour --agent-only
AGENT_TOKEN=""      # token enrollment pour --agent-only

_args=("$@")
i=0
while [[ $i -lt ${#_args[@]} ]]; do
  arg="${_args[$i]}"
  case "$arg" in
    --docker)         MODE="docker" ;;
    --dev)            exec bash scripts/dev-install.sh "${_args[@]:$((i+1))}"; exit 0 ;;
    --local)          LOCAL=true ;;
    --server-only)    SCOPE="server-only" ;;
    --agent-only)     SCOPE="agent-only" ;;
    --server)         i=$((i+1)); AGENT_SERVER="${_args[$i]}" ;;
    --server=*)       AGENT_SERVER="${arg#--server=}" ;;
    --token)          i=$((i+1)); AGENT_TOKEN="${_args[$i]}" ;;
    --token=*)        AGENT_TOKEN="${arg#--token=}" ;;
    --version)        i=$((i+1)); INSTALL_VERSION="${_args[$i]}" ;;
    --version=*)      INSTALL_VERSION="${arg#--version=}" ;;
    --help|-h)
      grep "^#" "$0" | grep -v "^#!/" | sed 's/^# \?//' | head -20
      exit 0
      ;;
    *) die "Option inconnue: $arg" ;;
  esac
  i=$((i+1))
done

# Validation --agent-only
if [[ "$SCOPE" == "agent-only" ]]; then
    [[ -z "$AGENT_SERVER" ]] && die "--agent-only requiert --server <HOST>:<PORT>"
    [[ -z "$AGENT_TOKEN"  ]] && die "--agent-only requiert --token <TOKEN>"
fi

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

    # Telechargement selon le scope
    if [[ "$SCOPE" != "agent-only" ]]; then
        curl -fsSL -o "$SERVER_DEB" "${BASE_URL}/oseye-server_${VER_DEB}_amd64.deb" \
            || die "Package serveur introuvable sur la release v${VERSION}"
        ok "oseye-server telecharge"

        if curl -fsSL -o "$UI_DEB" "${BASE_URL}/oseye-ui_${VER_DEB}_amd64.deb" 2>/dev/null; then
            ok "oseye-ui telecharge"
        else
            UI_DEB=""
            echo -e "  ${DIM}oseye-ui absent de la release — skip${RESET}"
        fi
    fi

    if [[ "$SCOPE" != "server-only" ]]; then
        curl -fsSL -o "$AGENT_DEB" "${BASE_URL}/oseye-agent_${VER_DEB}_amd64.deb" \
            || die "Package agent introuvable sur la release v${VERSION}"
        ok "oseye-agent telecharge"
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

if [[ "$SCOPE" != "agent-only" ]]; then
    dpkg -i "$SERVER_DEB"
    ok "oseye-server installe"
    if [[ -n "$UI_DEB" ]]; then
        dpkg -i "$UI_DEB"
        ok "oseye-ui installe"
    else
        echo -e "  ${DIM}oseye-ui absent — skip${RESET}"
    fi
fi

if [[ "$SCOPE" != "server-only" ]]; then
    dpkg -i "$AGENT_DEB"
    ok "oseye-agent installe"
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODE AGENT-ONLY — enrollment reseau vers un serveur distant
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SCOPE" == "agent-only" ]]; then
    step "3. Enrollment vers ${AGENT_SERVER}"
    oseye-config enroll \
        --server "${AGENT_SERVER}" \
        --token  "${AGENT_TOKEN}" \
        --grpc-port 50051
    systemctl enable oseye-agent
    systemctl start oseye-agent
    sleep 3
    if systemctl is-active --quiet oseye-agent; then
        ok "Agent enrolle et demarre"
    else
        die "Agent non demarre. Verifier: journalctl -u oseye-agent -n 20"
    fi
    echo ""
    echo -e "${GREEN}${BOLD}  Agent OSEye operationnel${RESET}"
    echo "  Serveur : ${AGENT_SERVER}"
    echo "  Logs    : journalctl -u oseye-agent -f"
    exit 0
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODE SERVER-ONLY ou ALL — initialisation + configuration + lancement serveur
# ══════════════════════════════════════════════════════════════════════════════

# ── 3. Initialisation (PKI + repertoires) ────────────────────────────────────
step "3. Initialisation"

if [[ -f /etc/oseye/certs/ca.crt ]] && [[ -f /etc/oseye/certs/server.crt ]]; then
    ok "PKI deja presente (skip — 'oseye-server init --force' pour regenerer)"
else
    oseye-server init
fi

# ── 4. Configuration ─────────────────────────────────────────────────────────
step "4. Configuration"

if [[ -f /etc/oseye/server.env ]] && [[ -f /etc/oseye/secrets.env ]]; then
    ok "Configuration deja presente (skip)"
else
    oseye-server setup
fi

ADMIN_PASS=$(grep OSEYE_ADMIN_PASSWORD /etc/oseye/secrets.env 2>/dev/null | cut -d= -f2 || echo "voir /etc/oseye/secrets.env")

# ── 5. Demarrage serveur ─────────────────────────────────────────────────────
step "5. Demarrage du serveur"

systemctl daemon-reload
systemctl enable oseye-server
systemctl start oseye-server

echo "  Attente du serveur..."
for i in $(seq 1 15); do
    curl -sf "http://localhost:8000/api/v1/health" >/dev/null 2>&1 && break
    sleep 2
done

systemctl is-active --quiet oseye-server \
    && ok "Serveur demarre et operationnel" \
    || die "Le serveur n'a pas demarre. Verifier: journalctl -u oseye-server -n 30"

# ── 6. Demarrage UI + liaison serveur ────────────────────────────────────────
if [[ -n "$UI_DEB" ]]; then
    step "6. Demarrage de l'UI"
    oseye-server api enable 2>/dev/null || true
    oseye-server ui url http://localhost:5173 2>/dev/null || true
    systemctl restart oseye-server
    for i in $(seq 1 10); do
        curl -sf "http://localhost:8000/api/v1/health" >/dev/null 2>&1 && break
        sleep 2
    done
    ok "API management activee — UI liee au serveur"
    systemctl enable oseye-ui
    systemctl start oseye-ui
    systemctl is-active --quiet oseye-ui \
        && ok "UI demarree sur http://localhost:5173" \
        || echo -e "  ${RED}UI non demarree — verifier: journalctl -u oseye-ui -n 20${RESET}"
fi

# ── 7. Enrollment + demarrage agent (mode all uniquement) ────────────────────
if [[ "$SCOPE" == "all" ]]; then
    step "7. Enrollment et demarrage de l'agent"

    TOKEN=$(oseye-server enrollment token create --valid-hours 72 2>&1 | grep -i "token" | head -1 | awk '{print $NF}')
    [[ -z "$TOKEN" ]] && TOKEN=$(ls /etc/oseye/enrollment_tokens/ 2>/dev/null | head -1)
    [[ -z "$TOKEN" ]] && die "Impossible de generer un token d'enrollment"

    DEFAULT_HOST=$(hostname -f 2>/dev/null || hostname)
    echo -e "  Token: ${DIM}${TOKEN}${RESET}"
    oseye-config enroll --server "${DEFAULT_HOST}:8000" --token "$TOKEN" --grpc-port 50051
    systemctl enable oseye-agent
    systemctl start oseye-agent
    sleep 3
    systemctl is-active --quiet oseye-agent \
        && ok "Agent enrolle et demarre" \
        || echo -e "  ${RED}Agent non demarre — verifier: journalctl -u oseye-agent -n 20${RESET}"
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
echo ""
if [[ "$SCOPE" == "server-only" ]]; then
    DEFAULT_HOST=$(hostname -f 2>/dev/null || hostname)
    TOKEN=$(oseye-server enrollment token create --valid-hours 72 2>&1 | grep -i "token" | head -1 | awk '{print $NF}' || true)
    echo "  Pour enroller un agent sur une autre machine :"
    echo "    sudo bash install.sh --agent-only \\"
    echo "      --server ${DEFAULT_HOST}:8000 \\"
    echo "      --token ${TOKEN:-<generer: oseye-server enrollment token create>}"
    echo ""
fi
echo "  Commandes :"
echo "    systemctl status oseye-server    — etat du serveur"
[[ "$SCOPE" != "server-only" ]] && echo "    systemctl status oseye-agent     — etat de l'agent"
echo "    oseye-server status              — sante detaillee"
echo "    journalctl -u oseye-server -f    — logs serveur"
echo ""
echo "  Desinstaller :"
echo "    sudo oseye-server uninstall --server --agent --purge"
echo ""
