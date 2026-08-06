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

.PHONY: help setup proto test test-go test-py lint audit dev-up dev-down run-server run-agent run-workers

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
