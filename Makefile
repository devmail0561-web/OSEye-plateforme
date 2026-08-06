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

.PHONY: help setup proto test test-go test-py lint audit dev-up dev-down run-server run-agent run-workers dev-certs

help:
	@echo ""
	@echo "  setup        — installer toutes les dépendances (Go + Python + protoc)"
	@echo "  proto        — générer les stubs Go et Python depuis proto/event.proto"
	@echo "  test         — lancer tous les tests (Go + Python)"
	@echo "  test-go      — tests Go uniquement"
	@echo "  test-py      — tests Python uniquement"
	@echo "  lint         — ruff + mypy (Python)"
	@echo "  audit        — scanner de sécurité interne (tools/audit/)"
	@echo "  dev-up       — docker compose up (Redis + Postgres)"
	@echo "  dev-down     — docker compose down"
	@echo ""
	@echo "  run-server   — lancer le serveur FastAPI en local (SQLite, port 8000)"
	@echo "  run-workers  — lancer les workers background (normalizer + storage_writer)"
	@echo "  run-agent    — lancer l'agent en local (procfs collector, buffer SQLite)"
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

test-go:
	cd agent && $(GOBIN)/go test -race ./...

test-py:
	cd server && $(PYTEST) tests/ -v --tb=short

# ── Lint ──────────────────────────────────────────────────────────────────────

lint:
	$(RUFF) check server/
	cd agent && $(GOBIN)/go vet ./...

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
