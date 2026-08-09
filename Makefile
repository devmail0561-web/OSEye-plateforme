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
        test test-go test-py \
        test-unit test-integration test-scenarios test-bench \
        test-fast test-slow test-ml \
        lint lint-py lint-go typecheck \
        audit dev-up dev-down \
        run-server run-agent run-workers dev-certs

# Variables de contrôle
PYTEST_OPTS ?=
PYTEST_WORKERS ?= auto
OSEYE_SECRET_KEY ?= dev-secret-key-local-testing-only

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

test: test-go test-py

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
	$(PYTHON) tools/oseye_audit.py --mode full

# ── Docker dev ────────────────────────────────────────────────────────────────

dev-up:
	docker compose -f infra/docker/docker-compose.dev.yml up -d redis postgres
	@echo "==> Redis + Postgres démarrés"

dev-down:
	docker compose -f infra/docker/docker-compose.dev.yml down

# ── Run locally (no Docker) ───────────────────────────────────────────────────

run-server:
	@echo "==> Lancement du serveur OSEye (SQLite + InMemoryBus, port 8000)"
	cd server && $(PYTHON) -m oseye.main

run-workers:
	@echo "==> Lancement des workers (normalizer + storage_writer)"
	cd server && $(PYTHON) -m oseye.workers.runner

run-agent:
	@echo "==> Lancement de l'agent OSEye (buffer SQLite, transport désactivé sans certs)"
	cd agent && OSEYE_BUFFER_PATH=/tmp/oseye_dev_buffer.db OSEYE_GRPC_ADDR=localhost:50051 \
	  $(GOBIN)/go run ./cmd/oseye-agent

dev-certs:
	@echo "==> Génération du PKI dev (CA + server + agent-dev + JWT)"
	bash scripts/generate_certs.sh
	@echo "==> Certs prêts dans infra/certs/"

run-agent-mtls:
	@echo "==> Lancement de l'agent avec mTLS (requiert make dev-certs)"
	cd agent && \
	  OSEYE_GRPC_ADDR=localhost:50051 \
	  OSEYE_TLS_CERT=$(CURDIR)/infra/certs/agent-dev.crt \
	  OSEYE_TLS_KEY=$(CURDIR)/infra/certs/agent-dev.key \
	  OSEYE_TLS_CA=$(CURDIR)/infra/certs/ca.crt \
	  OSEYE_BUFFER_PATH=/tmp/oseye_dev_buffer.db \
	  $(GOBIN)/go run ./cmd/oseye-agent

run-server-mtls:
	@echo "==> Lancement du serveur avec mTLS (requiert make dev-certs)"
	cd server && \
	  OSEYE_TLS_CERT_FILE=$(CURDIR)/infra/certs/server.crt \
	  OSEYE_TLS_KEY_FILE=$(CURDIR)/infra/certs/server.key \
	  OSEYE_TLS_CA_CERT_FILE=$(CURDIR)/infra/certs/ca.crt \
	  OSEYE_JWT_PRIVATE_KEY_PATH=$(CURDIR)/infra/certs/jwt_private.pem \
	  OSEYE_JWT_PUBLIC_KEY_PATH=$(CURDIR)/infra/certs/jwt_public.pem \
	  $(PYTHON) -m oseye.main
