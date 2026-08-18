#!/usr/bin/env bash
# OSEye — Installeur environnement développement
# Usage : bash scripts/dev-install.sh [--docker] [--no-ui] [--ci]
#
# Par défaut : SQLite + bus en mémoire — aucun Docker requis.
# --docker installe Docker et démarre Redis + PostgreSQL (stack complète).
set -euo pipefail

# ── Couleurs ──────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  _RESET="\033[0m"
  _BOLD="\033[1m"
  _CYAN="\033[36m"
  _GREEN="\033[32m"
  _YELLOW="\033[33m"
  _RED="\033[31m"
else
  _RESET="" _BOLD="" _CYAN="" _GREEN="" _YELLOW="" _RED=""
fi

info()    { printf "${_CYAN}${_BOLD}==> ${_RESET}${_BOLD}%s${_RESET}\n" "$*"; }
success() { printf "${_GREEN}${_BOLD}==> OK${_RESET} %s\n" "$*"; }
warn()    { printf "${_YELLOW}${_BOLD}WARN${_RESET} %s\n" "$*" >&2; }
error()   { printf "${_RED}${_BOLD}ERROR${_RESET} %s\n" "$*" >&2; exit 1; }
skip()    { printf "    ${_YELLOW}skip${_RESET} %s\n" "$*"; }

# ── Options ───────────────────────────────────────────────────────────────────
OPT_DOCKER=false   # Docker est OPT-IN — pas nécessaire pour le dev de base
OPT_UI=true
OPT_CI=false

for arg in "$@"; do
  case "$arg" in
    --docker)    OPT_DOCKER=true ;;   # stack complète : Redis + PostgreSQL
    --no-docker) OPT_DOCKER=false ;;  # explicitement sans Docker (déjà le défaut)
    --no-ui)     OPT_UI=false ;;
    --ci)        OPT_CI=true ;;
    --help|-h)
      printf "Usage: %s [--docker] [--no-ui] [--ci]\n" "$0"
      printf "\n"
      printf "  Par défaut : SQLite + bus mémoire, aucun Docker requis.\n"
      printf "\n"
      printf "  --docker   Installer Docker + démarrer Redis/PostgreSQL (stack complète)\n"
      printf "  --no-ui    Skip Node.js + UI (serveur seul)\n"
      printf "  --ci       Mode non-interactif\n"
      exit 0
      ;;
    *) error "Option inconnue : $arg. Utilisez --help." ;;
  esac
done

# ── Racine du projet ──────────────────────────────────────────────────────────
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ── Version ───────────────────────────────────────────────────────────────────
VERSION="$(cat "$ROOT/VERSION" 2>/dev/null || echo "0.0.0-dev")"
info "OSEye dev installer — version $VERSION"

# ── Détection OS ─────────────────────────────────────────────────────────────
OS_ID=""
OS_PRETTY=""
PKG_MGR=""

if [ -f /etc/os-release ]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_PRETTY="${PRETTY_NAME:-$ID}"
fi

case "$OS_ID" in
  ubuntu|debian|linuxmint|pop)
    PKG_MGR="apt"
    ;;
  fedora|rhel|rocky|almalinux|centos)
    PKG_MGR="dnf"
    ;;
  "")
    if [ "$(uname -s)" = "Darwin" ]; then
      OS_ID="macos"
      OS_PRETTY="macOS $(sw_vers -productVersion 2>/dev/null || echo "")"
      PKG_MGR="brew"
    else
      error "OS non détecté. Distributions supportées : Ubuntu/Debian, Fedora/RHEL/Rocky, macOS."
    fi
    ;;
  *)
    warn "Distribution '$OS_ID' non testée — on tente avec apt/dnf/brew..."
    if command -v apt-get &>/dev/null; then PKG_MGR="apt"
    elif command -v dnf &>/dev/null;    then PKG_MGR="dnf"
    elif command -v brew &>/dev/null;   then PKG_MGR="brew"
    else error "Aucun gestionnaire de paquets reconnu (apt/dnf/brew)."
    fi
    ;;
esac

printf "\n"
info "Système : $OS_PRETTY (pkg: $PKG_MGR)"
printf "\n"
printf "  Mode : SQLite + bus mémoire (démarrage immédiat, sans Docker)\n"
[ "$OPT_DOCKER" = true ] && printf "  Mode : stack complète Redis + PostgreSQL (Docker)\n"
printf "\n"

# ── Confirmation (mode interactif uniquement) ─────────────────────────────────
if [ "$OPT_CI" = false ]; then
  printf "Ce script va installer : Go 1.25, Python 3.12"
  [ "$OPT_UI" = true ]     && printf ", Node.js 20"
  [ "$OPT_DOCKER" = true ] && printf ", Docker"
  printf " + dépendances projet.\n"
  printf "Continuer ? [y/N] "
  read -r _answer
  case "$_answer" in y|Y|yes|YES) ;; *) info "Annulé."; exit 0 ;; esac
fi

# ── Helpers installation ──────────────────────────────────────────────────────
pkg_install() {
  local pkg="$1"
  info "Installation de $pkg..."
  case "$PKG_MGR" in
    apt)  sudo apt-get install -y "$pkg" ;;
    dnf)  sudo dnf install -y "$pkg" ;;
    brew) brew install "$pkg" ;;
  esac
}

pkg_update() {
  case "$PKG_MGR" in
    apt)  sudo apt-get update -qq ;;
    dnf)  sudo dnf makecache -q ;;
    brew) brew update ;;
  esac
}

_pkg_updated=false
ensure_pkg() {
  local pkg="$1"
  local check_cmd="${2:-$1}"
  if command -v "$check_cmd" &>/dev/null; then
    skip "$pkg déjà présent ($(command -v "$check_cmd"))"
    return 0
  fi
  if [ "$_pkg_updated" = false ]; then
    info "Mise à jour de l'index des paquets..."
    pkg_update
    _pkg_updated=true
  fi
  pkg_install "$pkg"
}

# ── Outils de base ────────────────────────────────────────────────────────────
info "Vérification des outils de base..."
ensure_pkg git
ensure_pkg make
ensure_pkg curl
ensure_pkg openssl

# ── Go 1.25 ──────────────────────────────────────────────────────────────────
GO_REQUIRED_MAJOR=1
GO_REQUIRED_MINOR=25
GOROOT="${HOME}/go"
GOBIN="${GOROOT}/bin/go"

_go_ok=false
if command -v "${GOBIN}" &>/dev/null; then
  _go_ver="$("${GOBIN}" version | awk '{print $3}' | sed 's/go//')"
  _go_major="${_go_ver%%.*}"
  _go_minor="$(echo "$_go_ver" | cut -d. -f2)"
  if [ "$_go_major" -gt "$GO_REQUIRED_MAJOR" ] || \
     { [ "$_go_major" -eq "$GO_REQUIRED_MAJOR" ] && [ "$_go_minor" -ge "$GO_REQUIRED_MINOR" ]; }; then
    skip "Go ${_go_ver} déjà présent (>= ${GO_REQUIRED_MAJOR}.${GO_REQUIRED_MINOR})"
    _go_ok=true
  else
    warn "Go ${_go_ver} présent mais < ${GO_REQUIRED_MAJOR}.${GO_REQUIRED_MINOR} — mise à jour..."
  fi
fi

if [ "$_go_ok" = false ]; then
  info "Installation de Go ${GO_REQUIRED_MAJOR}.${GO_REQUIRED_MINOR}..."
  _arch="$(uname -m)"
  case "$_arch" in
    x86_64)  _goarch="amd64" ;;
    aarch64) _goarch="arm64" ;;
    armv6l)  _goarch="armv6l" ;;
    *)       error "Architecture non supportée pour Go : $_arch" ;;
  esac
  _goos="$(uname -s | tr '[:upper:]' '[:lower:]')"
  _go_tarball="go${GO_REQUIRED_MAJOR}.${GO_REQUIRED_MINOR}.${_goos}-${_goarch}.tar.gz"
  _go_url="https://go.dev/dl/${_go_tarball}"
  _tmpdir="$(mktemp -d)"
  trap 'rm -rf "$_tmpdir"' EXIT
  info "Téléchargement de $_go_url..."
  curl -fsSL -o "${_tmpdir}/${_go_tarball}" "$_go_url"
  info "Extraction dans ${HOME}/go..."
  rm -rf "${HOME}/go"
  tar -C "${HOME}" -xzf "${_tmpdir}/${_go_tarball}"
  trap - EXIT
  rm -rf "$_tmpdir"
  success "Go ${GO_REQUIRED_MAJOR}.${GO_REQUIRED_MINOR} installé dans ${HOME}/go"
fi

export PATH="${GOBIN%/go}:${PATH}"

# ── Python 3.12 ───────────────────────────────────────────────────────────────
_py_ok=false
if command -v python3.12 &>/dev/null; then
  skip "Python 3.12 déjà présent ($(command -v python3.12))"
  _py_ok=true
fi

if [ "$_py_ok" = false ]; then
  info "Installation de Python 3.12..."
  case "$PKG_MGR" in
    apt)
      if [ "$_pkg_updated" = false ]; then pkg_update; _pkg_updated=true; fi
      sudo apt-get install -y python3.12 python3.12-venv python3.12-dev
      ;;
    dnf)
      sudo dnf install -y python3.12 python3.12-devel
      ;;
    brew)
      brew install python@3.12
      ;;
  esac
  success "Python 3.12 installé"
fi

# ── Node.js 20 ────────────────────────────────────────────────────────────────
if [ "$OPT_UI" = true ]; then
  _node_ok=false
  if command -v node &>/dev/null; then
    _node_ver="$(node --version | sed 's/v//' | cut -d. -f1)"
    if [ "$_node_ver" -ge 20 ]; then
      skip "Node.js $(node --version) déjà présent (>= 20)"
      _node_ok=true
    else
      warn "Node.js $(node --version) présent mais < 20 — mise à jour..."
    fi
  fi

  if [ "$_node_ok" = false ]; then
    info "Installation de Node.js 20..."
    case "$PKG_MGR" in
      apt)
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
        ;;
      dnf)
        curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo -E bash -
        sudo dnf install -y nodejs
        ;;
      brew)
        brew install node@20
        brew link --force node@20
        ;;
    esac
    success "Node.js $(node --version) installé"
  fi
else
  skip "Node.js (--no-ui)"
fi

# ── Docker + docker compose plugin ───────────────────────────────────────────
if [ "$OPT_DOCKER" = true ]; then
  if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
    skip "Docker $(docker --version | awk '{print $3}' | tr -d ',') + compose déjà présents"
  else
    info "Installation de Docker via get.docker.com..."
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "$(id -un)"
    success "Docker installé — reconnexion nécessaire pour le groupe 'docker'"
  fi
else
  skip "Docker (--no-docker)"
fi

# ── nfpm (packaging .deb/.rpm) ────────────────────────────────────────────────
if command -v nfpm &>/dev/null; then
  skip "nfpm déjà présent ($(command -v nfpm))"
else
  info "Installation de nfpm..."
  case "$PKG_MGR" in
    apt|dnf)
      _nfpm_ver="2.38.0"
      _arch="$(uname -m)"
      case "$_arch" in
        x86_64)  _nfpm_arch="amd64" ;;
        aarch64) _nfpm_arch="arm64" ;;
        *)        _nfpm_arch="amd64" ;;
      esac
      _nfpm_url="https://github.com/goreleaser/nfpm/releases/download/v${_nfpm_ver}/nfpm_${_nfpm_ver}_Linux_${_nfpm_arch}.tar.gz"
      _tmpdir="$(mktemp -d)"
      trap 'rm -rf "$_tmpdir"' EXIT
      curl -fsSL -o "${_tmpdir}/nfpm.tar.gz" "$_nfpm_url"
      tar -C "${_tmpdir}" -xzf "${_tmpdir}/nfpm.tar.gz" nfpm
      sudo install -m 0755 "${_tmpdir}/nfpm" /usr/local/bin/nfpm
      trap - EXIT
      rm -rf "$_tmpdir"
      ;;
    brew)
      brew install nfpm
      ;;
  esac
  success "nfpm installé"
fi

# ── Python venv + dépendances ─────────────────────────────────────────────────
info "Configuration du venv Python..."
if [ ! -f "${ROOT}/.venv/bin/python3.12" ]; then
  python3.12 -m venv "${ROOT}/.venv"
  success "venv créé dans ${ROOT}/.venv"
else
  skip "venv déjà présent"
fi

info "Installation des dépendances Python (server[dev] + sdk)..."
"${ROOT}/.venv/bin/pip" install --quiet --upgrade pip
"${ROOT}/.venv/bin/pip" install -e "${ROOT}/server[dev]" -e "${ROOT}/sdk/"
success "Dépendances Python installées"

# ── Go deps ───────────────────────────────────────────────────────────────────
info "Téléchargement des dépendances Go..."
(cd "${ROOT}/agent" && "${HOME}/go/bin/go" mod download)
success "Dépendances Go prêtes"

# ── UI npm deps ───────────────────────────────────────────────────────────────
if [ "$OPT_UI" = true ]; then
  if [ -f "${ROOT}/ui/package.json" ]; then
    info "Installation des dépendances UI (npm ci)..."
    (cd "${ROOT}/ui" && npm ci --silent)
    success "Dépendances UI installées"
  else
    warn "ui/package.json absent — skip npm ci UI"
  fi

  if [ -f "${ROOT}/site/package.json" ]; then
    info "Installation des dépendances site (npm ci)..."
    (cd "${ROOT}/site" && npm ci --silent)
    success "Dépendances site installées"
  else
    warn "site/package.json absent — skip npm ci site"
  fi
else
  skip "npm deps UI/site (--no-ui)"
fi

# ── Dev certs ─────────────────────────────────────────────────────────────────
if [ ! -f "${ROOT}/infra/certs/jwt_private.pem" ]; then
  info "Génération du PKI dev..."
  make -C "${ROOT}" dev-certs
  success "Certs dev prêts dans ${ROOT}/infra/certs/"
else
  skip "Certs dev déjà présents dans infra/certs/"
fi

# ── .env.dev ──────────────────────────────────────────────────────────────────
if [ ! -f "${ROOT}/.env.dev" ]; then
  info "Création de .env.dev..."
  _hmac_key="$(openssl rand -hex 32)"
  cat > "${ROOT}/.env.dev" << EOF
# OSEye — environnement développement local
# Généré par scripts/dev-install.sh le $(date +%Y-%m-%d)
# NE PAS COMMITTER ce fichier en production.

OSEYE_SECRET_KEY=dev-secret-key-local-testing-only-x32
OSEYE_CHECKPOINT_HMAC_KEY=${_hmac_key}
OSEYE_ADMIN_PASSWORD=admin123
OSEYE_ANALYST_PASSWORD=analyst123
OSEYE_MANAGEMENT_API_ENABLED=true
OSEYE_UI_URL=http://localhost:5173

# Database (SQLite dev)
OSEYE_DB_BACKEND=sqlite
OSEYE_DB_URL=sqlite+aiosqlite:///./oseye_dev.db

# gRPC
OSEYE_GRPC_ADDR=localhost:50051
OSEYE_GRPC_INSECURE_DEV=true
OSEYE_INSECURE=true

# JWT (dev certs)
OSEYE_JWT_PRIVATE_KEY_PATH=${ROOT}/infra/certs/jwt_private.pem
OSEYE_JWT_PUBLIC_KEY_PATH=${ROOT}/infra/certs/jwt_public.pem

# Logs
OSEYE_LOG_LEVEL=DEBUG
OSEYE_ENV=development

# CORS
OSEYE_API_CORS_ORIGINS=["http://localhost:5173","http://localhost:5174"]
EOF
  success ".env.dev créé"
else
  skip ".env.dev déjà présent"
fi

# ── Pre-commit hook ───────────────────────────────────────────────────────────
if [ -d "${ROOT}/.git" ] && [ -f "${ROOT}/.venv/bin/ruff" ]; then
  if [ ! -f "${ROOT}/.git/hooks/pre-commit" ]; then
    info "Installation du hook pre-commit..."
    cat > "${ROOT}/.git/hooks/pre-commit" << 'EOF'
#!/bin/sh
# OSEye — pre-commit hook
set -e
ROOT="$(git rev-parse --show-toplevel)"
"${ROOT}/.venv/bin/ruff" check server/oseye/ sdk/ && \
  cd "${ROOT}/agent" && go vet ./... 2>/dev/null && cd ..
EOF
    chmod +x "${ROOT}/.git/hooks/pre-commit"
    success "Hook pre-commit installé"
  else
    skip "Hook pre-commit déjà présent"
  fi
else
  skip "Hook pre-commit (.git ou .venv/ruff absent)"
fi

# ── Résumé final ──────────────────────────────────────────────────────────────
printf "\n"
printf "${_GREEN}${_BOLD}==> Environnement OSEye dev prêt !${_RESET} (version %s)\n\n" "$VERSION"
printf " Pour démarrer maintenant :\n\n"
printf "   ${_BOLD}cd %s${_RESET}\n" "$ROOT"
printf "   ${_BOLD}.venv/bin/python -m oseye.main${_RESET}   # serveur (SQLite, port 8000)\n"
if [ "$OPT_UI" = true ]; then
  printf "   ${_BOLD}cd ui && npm run dev${_RESET}            # UI React (port 5173)\n"
fi
printf "\n"
if [ "$OPT_DOCKER" = true ]; then
  printf " Stack complète (Redis + PostgreSQL) :\n\n"
  printf "   ${_BOLD}docker compose -f infra/docker/docker-compose.dev.yml up -d${_RESET}\n\n"
else
  printf " ${_YELLOW}Optionnel${_RESET} — stack complète avec Redis + PostgreSQL :\n\n"
  printf "   bash scripts/dev-install.sh --docker\n\n"
fi
printf " Tests :\n\n"
printf "   ${_BOLD}.venv/bin/pytest server/tests/ -q${_RESET}\n"
printf "   ${_BOLD}cd agent && go test ./...${_RESET}\n\n"
printf "   ${_BOLD}make lint${_RESET}            Lint Go + Python\n"
printf "\n"
[ "$OPT_DOCKER" = true ] && \
  printf "   ${_YELLOW}Note :${_RESET} si Docker vient d'être installé, relancez votre session pour rejoindre le groupe 'docker'.\n\n"
