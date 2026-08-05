# OSEye — Plan de développement modulaire — Phase 1 Foundation

**Version :** 1.0  
**Date :** 2026-08-05  
**Statut :** En cours — branche active : `M0/foundation-contracts`

---

## Lecture du plan

- Un **module** = une **branche Git** = une **PR** vers `main`
- **Statuts :** `[ ]` à faire · `[~]` en cours · `[x]` terminé
- **Dépendances :** un module ne démarre pas si ses prérequis ne sont pas `[x]`
- **Tests inclus** : chaque module livre ses tests dans la même PR

---

## Statut des modules

| # | Module | Branche | Dépend de | Statut |
|---|--------|---------|-----------|--------|
| M0 | Scaffolding + Contrats | `M0/foundation-contracts` | — | `[~]` |
| M1 | Crypto & Buffer (Go) | `M1/agent-crypto-buffer` | M0 | `[ ]` |
| M2 | Collectors Linux (Go) | `M2/agent-collectors-linux` | M1 | `[ ]` |
| M3 | Transport gRPC Agent (Go) | `M3/agent-grpc-transport` | M1 | `[ ]` |
| M4 | Agent Bootstrap (Go) | `M4/agent-bootstrap` | M2, M3 | `[ ]` |
| M5 | Event Bus (Python) | `M5/server-event-bus` | M0 | `[ ]` |
| M6 | Ingestion gRPC (Python) | `M6/server-ingest` | M5 | `[ ]` |
| M7 | Normalizer (Python) | `M7/server-normalizer` | M5 | `[ ]` |
| M8 | Storage (Python) | `M8/server-storage` | M0 | `[ ]` |
| M9 | API REST + Auth (Python) | `M9/server-api` | M8 | `[ ]` |
| M10 | Workers dev (Python) | `M10/server-workers` | M6, M7, M8 | `[ ]` |
| M11 | Infra & CI | `M11/infra-ci` | M0 | `[ ]` |

---

## Graphe de dépendances

```
M0 ──► M1 ──► M2 ──► M4
       M1 ──► M3 ──► M4
M0 ──► M5 ──► M6 ──► M10
       M5 ──► M7 ──► M10
M0 ──► M8 ──► M9
              M8 ──► M10
M0 ──► M11
```

**Parallélisme dès M0 mergé :** M1 + M5 + M8 + M11 simultanément

---

## M0 — Scaffolding + Contrats `[~]`

**Branche :** `M0/foundation-contracts`  
**Livrable :** Arborescence monorepo + 11 fichiers contrats + `go.mod` + `pyproject.toml`

### Fichiers contrats (⚠ revue obligatoire avant merge)

- [ ] `proto/event.proto` — UniversalEventPB, IngestRequest/Response, AgentService
- [ ] `server/oseye/core/schema.py` — tous les modèles Pydantic v2
- [ ] `server/oseye/bus/interface.py` — Protocol EventBus
- [ ] `agent/internal/platform/interface.go` — PlatformDriver + PlatformCapabilities
- [ ] `agent/internal/platform/registry.go` — Register() + Resolve()
- [ ] `agent/internal/collector/interface.go` — Collector + RawEvent
- [ ] `server/oseye/storage/interface.py` — Protocols Repository
- [ ] `server/oseye/storage/router.py` — StorageRouter
- [ ] `server/oseye/config.py` — Settings pydantic-settings
- [ ] `server/oseye/core/observability.py` — OTel + structlog JSON
- [ ] `scripts/generate_proto.sh` — codegen Go + Python

### Scaffolding

- [ ] `agent/go.mod` initialisé
- [ ] `server/pyproject.toml` initialisé
- [ ] Arborescence complète du monorepo (répertoires + `.gitkeep`)
- [ ] `infra/docker/docker-compose.dev.yml`
- [ ] `scripts/generate_certs.sh`

### Tests M0

- [ ] `server/tests/unit/test_schema_completeness.py` — instancier tous les modèles Pydantic
- [ ] `scripts/test_proto_compile.sh` — generate_proto.sh sans erreur
- [ ] `agent/internal/platform/contracts_test.go` — compilation suffit

---

## M1 — Crypto & Buffer (Go) `[ ]`

**Branche :** `M1/agent-crypto-buffer`  
**Dépend de :** M0 mergé

- [ ] `agent/internal/chain/hasher.go` — BLAKE3 hash chain
- [ ] `agent/internal/signer/ed25519.go` — signature batch Ed25519
- [ ] `agent/internal/buffer/sqlite_buffer.go` — queue offline WAL

**Tests :** `hasher_test.go`, `ed25519_test.go`, `sqlite_buffer_test.go` — couverture > 90%

---

## M2 — Collectors Linux (Go) `[ ]`

**Branche :** `M2/agent-collectors-linux`  
**Dépend de :** M1 mergé

- [ ] `platform/linux/driver.go` — LinuxDriver + auto-register
- [ ] `platform/linux/ebpf/loader.go` + `execve.c`, `openat.c`, `connect.c`
- [ ] `platform/linux/auditd/reader.go`
- [ ] `platform/linux/procfs/scanner.go`
- [ ] `collector/manager.go` — CollectorManager fan-in

**Tests :** loader, auditd, procfs, manager — build tag linux

---

## M3 — Transport gRPC Agent (Go) `[ ]`

**Branche :** `M3/agent-grpc-transport`  
**Dépend de :** M1 mergé

- [ ] `transport/grpc_client.go` — streaming + reconnexion exponentielle + mTLS

**Tests :** mock gRPC server, reconnexion, backpressure, mTLS

---

## M4 — Agent Bootstrap (Go) `[ ]`

**Branche :** `M4/agent-bootstrap`  
**Dépend de :** M2 + M3 mergés

- [ ] `cmd/oseye-agent/main.go` — pipeline complet + SIGTERM drain
- [ ] `internal/config/config.go`

**Tests :** intégration mock server, signal handler

---

## M5 — Event Bus (Python) `[ ]`

**Branche :** `M5/server-event-bus`  
**Dépend de :** M0 mergé

- [ ] `bus/memory.py` — InMemoryBus (asyncio.Queue)
- [ ] `bus/redis_streams.py` — RedisBus (XADD/XREADGROUP)

**Tests :** memory bus unitaire, redis bus intégration

---

## M6 — Ingestion gRPC (Python) `[ ]`

**Branche :** `M6/server-ingest`  
**Dépend de :** M5 mergé

- [ ] `ingest/grpc_service.py` — AgentServiceServicer + vérif mTLS CN
- [ ] `ingest/validator.py` — BatchValidator (Ed25519 + BLAKE3)

**Tests :** validator unitaire, grpc_service avec mock bus

---

## M7 — Normalizer (Python) `[ ]`

**Branche :** `M7/server-normalizer`  
**Dépend de :** M5 mergé

- [ ] `normalizer/engine.py` — NormalizerEngine dispatch OS/source
- [ ] `normalizer/adapters/linux/{ebpf,auditd,procfs}.py`
- [ ] `normalizer/secret_masker.py`

**Tests :** 3 adapters, secret masker, engine dispatch

---

## M8 — Storage (Python) `[ ]`

**Branche :** `M8/server-storage`  
**Dépend de :** M0 mergé

- [ ] `storage/migrations/V001_initial_schema.py` — Alembic + triggers
- [ ] `storage/backends/postgresql.py`
- [ ] `storage/backends/sqlite.py`
- [ ] `storage/repositories/event_repo.py`

**Tests :** event_repo (SQLite in-memory), migrations, triggers immuabilité

---

## M9 — API REST + Auth (Python) `[ ]`

**Branche :** `M9/server-api`  
**Dépend de :** M8 mergé

- [ ] `api/auth/jwt.py` — JWT RS256
- [ ] `api/auth/rbac.py` — 4 dépendances FastAPI
- [ ] `api/routers/{events,auth,health}.py`
- [ ] `api/ws/manager.py` — WebSocketManager
- [ ] `audit/middleware.py`
- [ ] `api/app.py` — factory

**Tests :** JWT, RBAC, /events filtres, WebSocket, audit middleware

---

## M10 — Workers dev (Python) `[ ]`

**Branche :** `M10/server-workers`  
**Dépend de :** M6 + M7 + M8 mergés

- [ ] `workers/storage_writer.py` — batch consumer 500ms
- [ ] `workers/{rule,ml,ti,correlation,decision}_worker.py` — stubs
- [ ] `core/runner.py` — asyncio.gather monolithe dev

**Tests :** storage_writer mock, pipeline intégration end-to-end

---

## M11 — Infra & CI `[ ]`

**Branche :** `M11/infra-ci`  
**Dépend de :** M0 mergé

- [ ] `.github/workflows/ci.yml` — lint + test + build matrix
- [ ] `infra/docker/docker-compose.dev.yml` — redis + postgres + services
- [ ] `infra/docker/init.sql` — extensions pgcrypto + uuid-ossp
- [ ] `scripts/generate_certs.sh` — PKI dev openssl
- [ ] `scripts/generate_proto.sh` — codegen protoc

---

## Convention nommage des branches

```
M<n>/<scope>-<description-kebab>
ex: M2/agent-collectors-linux
    M8/server-storage
```

## Critères d'acceptance Phase 1

- [ ] `go test -race ./...` — verts, couverture > 80%
- [ ] `pytest server/tests/ --cov-fail-under=80` — verts
- [ ] `docker compose up --build --wait` — tous services healthy
- [ ] Events eBPF réels insérés en DB SQLite
- [ ] `GET /api/v1/events` retourne les events
- [ ] Client WS reçoit les events en < 1s
- [ ] CI GitHub Actions passe sur `main`
