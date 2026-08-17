GOROOT    := $(HOME)/go
GOPATH    := $(HOME)/go-workspace
GOBIN     := $(GOROOT)/bin
WSBIN     := $(GOPATH)/bin
PROTOCBIN := $(HOME)/.local/bin
VENV      := $(CURDIR)/.venv
PYTHON    := $(VENV)/bin/python3.12
PIP       := $(VENV)/bin/pip
PYTEST    := $(VENV)/bin/pytest
RUFF      := $(VENV)/bin/ruff

export PATH := $(GOBIN):$(WSBIN):$(PROTOCBIN):$(PATH)
export GOROOT
export GOPATH
export VENV_PYTHON := $(PYTHON)

.PHONY: help setup proto \
        test test-go test-py test-ui \
        test-unit test-integration test-scenarios test-bench \
        test-fast test-slow test-ml \
        lint lint-py lint-go typecheck \
        audit dev-up dev-down \
        run-server run-agent run-workers dev-certs \
        ui-dev ui-build ui-test ui-lint site-dev \
        package-agent package-server package-all init-server \
        version checksums build-agent build-config

# Variables de contrôle
PYTEST_OPTS ?=
PYTEST_WORKERS ?= auto
OSEYE_SECRET_KEY ?= dev-secret-key-local-testing-only

# Chemins dev (hors /etc/oseye qui requiert root)
DEV_CERTS_DIR   := $(CURDIR)/infra/certs
DEV_DATA_DIR    := /tmp/oseye_dev
DEV_PLUGINS_DIR := $(DEV_DATA_DIR)/plugins
DEV_ML_DIR      := $(DEV_DATA_DIR)

# Variables d'environnement communes pour run-server et run-server-mtls
OSEYE_CHECKPOINT_HMAC_KEY ?= $(shell openssl rand -hex 32 2>/dev/null || echo dev-hmac-key-replace-in-prod)

define DEV_ENV
	OSEYE_SECRET_KEY=$(OSEYE_SECRET_KEY) \
	OSEYE_INSECURE=true \
	OSEYE_CHECKPOINT_HMAC_KEY=$(OSEYE_CHECKPOINT_HMAC_KEY) \
	OSEYE_ENROLLMENT_TOKEN_DIR=$(DEV_DATA_DIR)/enrollment_tokens \
	OSEYE_JWT_PRIVATE_KEY_PATH=$(DEV_CERTS_DIR)/jwt_private.pem \
	OSEYE_JWT_PUBLIC_KEY_PATH=$(DEV_CERTS_DIR)/jwt_public.pem \
	OSEYE_PLUGINS_DIR=$(DEV_PLUGINS_DIR) \
	OSEYE_PLUGIN_IPC_SOCKET=$(DEV_DATA_DIR)/plugin.sock \
	OSEYE_PLUGIN_KEYS_DIR=$(DEV_DATA_DIR)/plugin_keys \
	OSEYE_ML_CHECKPOINT_PATH=$(DEV_ML_DIR)/ml_checkpoint.pkl \
	OSEYE_GRPC_INSECURE_DEV=true
endef

help:
	@echo ""
	@echo "Tests"
	@echo "  test              — tous les tests Go + Python (unité + intégration + scénarios)"
	@echo "  test-fast         — unit uniquement (rapide, sans ML quality)"
	@echo "  test-unit         — tests unitaires Python"
	@echo "  test-integration  — tests intégration Python (requiert serveur actif)"
	@echo "  test-scenarios    — tests scénarios end-to-end"
	@echo "  test-ml           — tests ML quality (lents ~5min)"
	@echo "  test-go           — tests Go avec -race"
	@echo "  test-bench        — benchmarks Python"
	@echo ""
	@echo "Qualité"
	@echo "  lint              — ruff + go vet"
	@echo "  lint-py           — ruff check server/"
	@echo "  lint-go           — go vet ./..."
	@echo "  typecheck         — mypy --strict server/oseye/"
	@echo ""
	@echo "Infrastructure"
	@echo "  setup             — installer toutes les dépendances (Go + Python + protoc)"
	@echo "  proto             — générer les stubs depuis proto/event.proto"
	@echo "  dev-up            — docker compose up (Redis + Postgres)"
	@echo "  dev-down          — docker compose down"
	@echo "  dev-certs         — générer le PKI dev (CA + server + agent + JWT)"
	@echo ""
	@echo "Lancement local"
	@echo "  run-server        — serveur FastAPI (SQLite + InMemoryBus, port 8000)"
	@echo "  run-workers       — workers background"
	@echo "  run-agent         — agent (buffer SQLite, sans TLS)"
	@echo ""
	@echo "Site documentation"
	@echo "  site-dev          — site docs Starlight (port 4321)"
	@echo ""
	@echo "Packaging & déploiement"
	@echo "  package-agent     — build .deb + .rpm pour oseye-agent (requiert nfpm)"
	@echo "  package-server    — build images Docker serveur + UI"
	@echo "  package-all       — package-agent + package-server"
	@echo "  init-server       — initialiser PKI prod + token enrollment"
	@echo ""

# ── Setup ────────────────────────────────────────────────────────────────────

setup: $(VENV)/bin/python3.12
	@echo "==> Environnement prêt"
	@echo "    Go    : $(shell $(GOBIN)/go version)"
	@echo "    Python: $(shell $(PYTHON) --version)"
	@echo "    protoc: $(shell protoc --version)"

$(VENV)/bin/python3.12:
	python3.12 -m venv $(VENV)
	$(PIP) install -e "$(CURDIR)/server[dev]"

# ── Proto codegen ─────────────────────────────────────────────────────────────

proto:
	bash scripts/generate_proto.sh

# ── Tests ─────────────────────────────────────────────────────────────────────

test: test-go test-py test-ui

# Go — race detector activé
test-go:
	cd agent && OSEYE_SECRET_KEY=$(OSEYE_SECRET_KEY) $(GOBIN)/go test -race -count=1 ./... $(PYTEST_OPTS)

# Python — tous les tests (unité + intégration + scénarios), ML quality inclus
test-py:
	OSEYE_SECRET_KEY=$(OSEYE_SECRET_KEY) \
	  cd server && $(PYTEST) tests/ -v --tb=short $(PYTEST_OPTS)

# Rapide : unité seulement, ML quality et intégration exclus (~5min → ~1min)
test-fast:
	OSEYE_SECRET_KEY=$(OSEYE_SECRET_KEY) \
	  cd server && $(PYTEST) tests/unit/ -q --tb=short \
	    --ignore=tests/unit/test_ml_quality.py \
	    $(PYTEST_OPTS)

# Tests unitaires uniquement
test-unit:
	OSEYE_SECRET_KEY=$(OSEYE_SECRET_KEY) \
	  cd server && $(PYTEST) tests/unit/ -v --tb=short $(PYTEST_OPTS)

# Tests ML quality (lents — ~5min, River HalfSpaceTrees)
test-ml:
	OSEYE_SECRET_KEY=$(OSEYE_SECRET_KEY) \
	  cd server && $(PYTEST) tests/unit/test_ml_quality.py tests/unit/test_ml_worker.py \
	    -v --tb=short $(PYTEST_OPTS)

# Tests intégration (requiert Redis ou SQLite)
test-integration:
	OSEYE_SECRET_KEY=$(OSEYE_SECRET_KEY) \
	  cd server && $(PYTEST) tests/integration/ -v --tb=short $(PYTEST_OPTS)

# Tests scénarios end-to-end
test-scenarios:
	OSEYE_SECRET_KEY=$(OSEYE_SECRET_KEY) \
	  cd server && $(PYTEST) tests/scenarios/ -v --tb=short $(PYTEST_OPTS)

# Benchmarks (affiche les résultats sans assertion)
test-bench:
	OSEYE_SECRET_KEY=$(OSEYE_SECRET_KEY) \
	  cd server && $(PYTEST) tests/benchmarks/ -v --tb=short -s $(PYTEST_OPTS)

# ── Lint ──────────────────────────────────────────────────────────────────────

lint: lint-py lint-go

lint-py:
	$(RUFF) check server/oseye/ sdk/oseye_sdk/

lint-go:
	cd agent && $(GOBIN)/go vet ./...

typecheck:
	cd server && $(VENV)/bin/mypy --strict oseye/ --ignore-missing-imports

# ── Audit engine ──────────────────────────────────────────────────────────────

audit:
	$(PYTHON) tools/oseye_audit.py --mode all

# ── Docker dev ────────────────────────────────────────────────────────────────

dev-up:
	docker compose -f infra/docker/docker-compose.dev.yml up -d redis postgres
	@echo "==> Redis + Postgres démarrés"

dev-down:
	docker compose -f infra/docker/docker-compose.dev.yml down

# ── Run locally (no Docker) ───────────────────────────────────────────────────

run-server: dev-certs
	@echo "==> Lancement du serveur OSEye (SQLite + InMemoryBus, port 8000)"
	cd server && $(DEV_ENV) \
	  $(PYTHON) -m oseye.main

run-workers:
	@echo "==> Lancement des workers (normalizer + storage_writer)"
	cd server && $(PYTHON) -m oseye.workers.runner

run-agent:
	@echo "==> Lancement de l'agent OSEye (buffer SQLite, transport désactivé sans certs)"
	cd agent && OSEYE_BUFFER_PATH=/tmp/oseye_dev_buffer.db OSEYE_GRPC_ADDR=localhost:50051 \
	  $(GOBIN)/go run ./cmd/oseye-agent

dev-certs:
	@if [ ! -f $(DEV_CERTS_DIR)/jwt_private.pem ]; then \
	  echo "==> Génération du PKI dev (CA + server + agent-dev + JWT)"; \
	  bash scripts/generate_certs.sh; \
	  echo "==> Certs prêts dans $(DEV_CERTS_DIR)/"; \
	else \
	  echo "==> Certs dev déjà présents dans $(DEV_CERTS_DIR)/ (skip)"; \
	fi

# ── UI ────────────────────────────────────────────────────────────────────────

UI_DIR := $(CURDIR)/ui

ui-dev:
	@echo "==> Lancement du dashboard UI (port 5173)"
	cd $(UI_DIR) && npm run dev

site-dev:
	@echo "==> Lancement du site docs (port 4321)"
	cd $(CURDIR)/site && npx astro dev --port 4321

ui-build:
	@echo "==> Build de production UI → ui/dist/"
	cd $(UI_DIR) && npm ci --ignore-scripts && npm run build

ui-test:
	@echo "==> Tests unitaires UI (Vitest, couverture → ui/coverage/lcov.info)"
	cd $(UI_DIR) && npm test -- --coverage

test-ui: ui-test

ui-lint:
	@echo "==> Lint TypeScript/ESLint (zero warnings)"
	cd $(UI_DIR) && npm run lint

run-agent-mtls:
	@echo "==> Lancement de l'agent avec mTLS (requiert make dev-certs)"
	cd agent && \
	  OSEYE_GRPC_ADDR=localhost:50051 \
	  OSEYE_TLS_CERT=$(CURDIR)/infra/certs/agent-dev.crt \
	  OSEYE_TLS_KEY=$(CURDIR)/infra/certs/agent-dev.key \
	  OSEYE_TLS_CA=$(CURDIR)/infra/certs/ca.crt \
	  OSEYE_BUFFER_PATH=/tmp/oseye_dev_buffer.db \
	  $(GOBIN)/go run ./cmd/oseye-agent

# ── Packaging ─────────────────────────────────────────────────────────────────

VERSION  ?= $(shell cat VERSION 2>/dev/null || echo "0.0.0-dev")
OS       ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH     ?= $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
PLATFORM := $(OS)-$(ARCH)
DIST_DIR := $(CURDIR)/dist
NFPM     := nfpm
LDFLAGS  := -s -w -X main.version=$(VERSION)

version:
	@echo $(VERSION)

# Convenience aliases
build-agent: $(DIST_DIR)/oseye-agent-$(PLATFORM)
build-config: $(DIST_DIR)/oseye-config-$(PLATFORM)
build-windows: ## Cross-compile Windows agent (amd64)
	mkdir -p $(DIST_DIR)
	cd agent && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	  $(GOBIN)/go build -trimpath -ldflags "$(LDFLAGS)" \
	  -o $(DIST_DIR)/oseye-agent-windows-amd64.exe ./cmd/oseye-agent
	ln -sf oseye-agent-windows-amd64.exe $(DIST_DIR)/oseye-agent.exe
build-darwin-amd64: ## Cross-compile macOS agent (Intel)
	mkdir -p $(DIST_DIR)
	cd agent && GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
	  $(GOBIN)/go build -trimpath -ldflags "$(LDFLAGS)" \
	  -o $(DIST_DIR)/oseye-agent-darwin-amd64 ./cmd/oseye-agent
	ln -sf oseye-agent-darwin-amd64 $(DIST_DIR)/oseye-agent-darwin
build-darwin-arm64: ## Cross-compile macOS agent (Apple Silicon)
	mkdir -p $(DIST_DIR)
	cd agent && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
	  $(GOBIN)/go build -trimpath -ldflags "$(LDFLAGS)" \
	  -o $(DIST_DIR)/oseye-agent-darwin-arm64 ./cmd/oseye-agent
build-all-agents: build-agent build-windows build-darwin-amd64 build-darwin-arm64

# Build the static agent binary
$(DIST_DIR)/oseye-agent-$(PLATFORM):
	@echo "==> Build oseye-agent-$(PLATFORM) $(VERSION) (CGO_ENABLED=0, -trimpath)"
	mkdir -p $(DIST_DIR)
	cd agent && CGO_ENABLED=0 GOOS=linux \
	  $(GOBIN)/go build -trimpath \
	  -ldflags "$(LDFLAGS)" \
	  -o $(DIST_DIR)/oseye-agent-$(PLATFORM) \
	  ./cmd/oseye-agent
	ln -sf oseye-agent-$(PLATFORM) $(DIST_DIR)/oseye-agent

# Build the config CLI binary
$(DIST_DIR)/oseye-config-$(PLATFORM):
	@echo "==> Build oseye-config-$(PLATFORM) $(VERSION) (CGO_ENABLED=0, -trimpath)"
	mkdir -p $(DIST_DIR)
	cd agent && CGO_ENABLED=0 GOOS=linux \
	  $(GOBIN)/go build -trimpath \
	  -ldflags "$(LDFLAGS)" \
	  -o $(DIST_DIR)/oseye-config-$(PLATFORM) \
	  ./cmd/oseye-config
	ln -sf oseye-config-$(PLATFORM) $(DIST_DIR)/oseye-config

# Build .deb + .rpm packages for the agent
package-agent: $(DIST_DIR)/oseye-agent-$(PLATFORM) $(DIST_DIR)/oseye-config-$(PLATFORM)
	@echo "==> Packaging oseye-agent $(VERSION) (.deb + .rpm) [$(PLATFORM)]"
	mkdir -p $(DIST_DIR)
	# nfpm needs unversioned names — symlink then package
	ln -sf oseye-agent-$(PLATFORM) $(DIST_DIR)/oseye-agent
	ln -sf oseye-config-$(PLATFORM) $(DIST_DIR)/oseye-config
	VERSION=$(VERSION) ARCH=$(ARCH) $(NFPM) package \
	  --config packaging/nfpm-agent.yaml \
	  --packager deb \
	  --target $(DIST_DIR)
	VERSION=$(VERSION) ARCH=$(ARCH) $(NFPM) package \
	  --config packaging/nfpm-agent.yaml \
	  --packager rpm \
	  --target $(DIST_DIR)
	rm -f $(DIST_DIR)/oseye-agent $(DIST_DIR)/oseye-config
	@echo "==> Packages:"
	@ls -lh $(DIST_DIR)/oseye-agent_* $(DIST_DIR)/oseye-agent-*.rpm 2>/dev/null || true

# Generate SHA256SUMS for all dist artifacts
checksums:
	@echo "==> Generating SHA256SUMS"
	cd $(DIST_DIR) && sha256sum * > SHA256SUMS

# Build production Docker images for the server stack
package-server:
	@echo "==> Build image oseye-server:$(VERSION)"
	DOCKER_HOST=unix://$(HOME)/.docker/desktop/docker.sock docker build -t oseye-server:$(VERSION) server/
	@echo "==> Build image oseye-ui:$(VERSION)"
	DOCKER_HOST=unix://$(HOME)/.docker/desktop/docker.sock docker build -t oseye-ui:$(VERSION) ui/
	@echo "==> Images prêtes. Compose de prod: infra/docker/docker-compose.prod.yml"

package-all: package-agent package-server

# First-run server initialization (PKI + enrollment token)
init-server:
	@echo "==> Initialisation du serveur OSEye (PKI prod + token enrollment)"
	sudo bash scripts/init-server.sh

run-server-mtls: dev-certs
	@echo "==> Lancement du serveur avec mTLS (requiert make dev-certs)"
	cd server && $(DEV_ENV) \
	  OSEYE_TLS_CERT_FILE=$(DEV_CERTS_DIR)/server.crt \
	  OSEYE_TLS_KEY_FILE=$(DEV_CERTS_DIR)/server.key \
	  OSEYE_TLS_CA_CERT_FILE=$(DEV_CERTS_DIR)/ca.crt \
	  $(PYTHON) -m oseye.main
