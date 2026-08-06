# OSEye — Plan de développement modulaire — Phase 1 Foundation

**Version :** 1.1  
**Date :** 2026-08-06  
**Statut :** En cours — branche active : `main` · Phase 1 (M2/M3/M4/M6/M7/M9/M10 restants)

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
| M0 | Scaffolding + Contrats | `M0/foundation-contracts` | — | `[x]` mergé |
| M1 | Crypto & Buffer (Go) | `M1/agent-crypto-buffer` | M0 | `[x]` mergé |
| M2 | Collectors Linux (Go) | `M2/agent-collectors-linux` | M1 | `[ ]` débloqué |
| M3 | Transport gRPC Agent (Go) | `M3/agent-grpc-transport` | M1 | `[ ]` débloqué |
| M4 | Agent Bootstrap (Go) | `M4/agent-bootstrap` | M2, M3 | `[ ]` |
| M5 | Event Bus (Python) | `M5/server-event-bus` | M0 | `[x]` mergé |
| M6 | Ingestion gRPC (Python) | `M6/server-ingest` | M5 | `[ ]` débloqué |
| M7 | Normalizer (Python) | `M7/server-normalizer` | M5 | `[ ]` débloqué |
| M8 | Storage (Python) | `M8/server-storage` | M0 | `[x]` mergé |
| M9 | API REST + Auth (Python) | `M9/server-api` | M8 | `[ ]` débloqué |
| M10 | Workers dev (Python) | `M10/server-workers` | M6, M7, M8 | `[ ]` |
| M11 | Infra & CI | `M11/infra-ci` | M0 | `[x]` mergé |

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

**Parallélisme disponible maintenant :** M2 + M3 + M6 + M7 + M9 simultanément

---

## M0 — Scaffolding + Contrats `[x]` — mergé 2026-08-06

**Branche :** `M0/foundation-contracts` → `main`  
**Livrable :** Arborescence monorepo + 11 fichiers contrats + `go.mod` + `pyproject.toml`

### Fichiers contrats

- [x] `proto/event.proto` — UniversalEventPB, IngestRequest/Response, AgentService
- [x] `server/oseye/core/schema.py` — tous les modèles Pydantic v2
- [x] `server/oseye/bus/interface.py` — Protocol EventBus
- [x] `agent/internal/platform/interface.go` — PlatformDriver + PlatformCapabilities
- [x] `agent/internal/platform/registry.go` — Register() + Resolve()
- [x] `agent/internal/collector/interface.go` — Collector + RawEvent
- [x] `server/oseye/storage/interface.py` — Protocols Repository (dict[str,Any], Page[T])
- [x] `server/oseye/storage/router.py` — StorageRouter
- [x] `server/oseye/config.py` — Settings pydantic-settings, env OSEYE_*
- [x] `server/oseye/core/observability.py` — structlog JSON (OTel stub — M6/M9)
- [x] `scripts/generate_proto.sh` — codegen Go + Python

### Scaffolding

- [x] `agent/go.mod` — Go 1.23, grpc v1.68, protobuf v1.35
- [x] `server/pyproject.toml` — Python 3.12+
- [x] Arborescence complète du monorepo
- [x] `infra/docker/docker-compose.dev.yml`
- [x] `scripts/generate_certs.sh`
- [x] `agent/.golangci.yml`
- [x] `.env.example`
- [x] Dockerfiles (server, agent, ui — stubs)
- [ ] `ui/package.json` — React/TypeScript/Vite (Phase 9)
- [ ] `scripts/test_proto_compile.sh`

### Tests M0

- [x] `server/tests/unit/test_schema_completeness.py` — 15 tests, 100% couverture schema
- [x] `agent/internal/platform/contracts_test.go` — assertions compilation
- [ ] `scripts/test_proto_compile.sh`

---

## M1 — Crypto & Buffer (Go) `[x]` — mergé 2026-08-06

**Branche :** `M1/agent-crypto-buffer` → `main`

- [x] `agent/internal/chain/chain.go` — BLAKE3 hash chain (zeebo/blake3, asm AVX2)
- [x] `agent/internal/signer/signer.go` — signature Ed25519 stdlib, chargement PEM PKCS8
- [x] `agent/internal/buffer/buffer.go` — queue offline modernc/sqlite (CGO=0, CI)
- [x] `agent/internal/buffer/buffer_cgo.go` — queue offline mattn/go-sqlite3 + WAL (CGO=1, prod)
- [x] `agent/internal/config/config.go` + tests — lecture env OSEYE_*

**Tests :** 43 tests Go, couverture chain 100%, signer 87%, config 100%, buffer 73%

**Benchmarks mesurés :**
- BLAKE3 1 KB : 428 MB/s (2.4 µs/op)
- Ed25519 sign : 43.7 µs → 11 450× de marge vs cible
- Buffer Push/1000 : 14 ms CGO+WAL, 34 ms pure-Go

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

## M5 — Event Bus (Python) `[x]` — mergé 2026-08-06

**Branche :** `M5/server-event-bus` → `main`

- [x] `server/oseye/bus/memory_bus.py` — InMemoryEventBus, subscriptions eagerly-registered
- [x] `server/oseye/bus/redis_bus.py` — RedisEventBus (XADD/XREADGROUP/XAUTOCLAIM)
- [x] `server/oseye/bus/factory.py` — create_bus() selon settings.redis_url
- [x] `server/oseye/bus/__init__.py` — exports publics

**Tests :** 9/9 tests InMemoryEventBus (publish, subscribe, pattern, multiple subscribers, close)
**Note :** redis_bus coverage 21% — tests d'intégration Redis en M5-bis avant M10
**Dette :** DESIGN-003 — `subscribe_pattern` utilise `KEYS *` O(N), à migrer vers `SCAN` en M5-bis

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

## M8 — Storage (Python) `[x]` — mergé 2026-08-06

**Branche :** `M8/server-storage` → `main`

- [x] `server/oseye/storage/models.py` — ORM SQLAlchemy déclaratif (8 tables)
- [x] `server/oseye/storage/migrations/__init__.py` — `run_migrations()` + triggers immuabilité PG (SEC-0002 ✅)
- [x] `server/oseye/storage/backends/sqlite.py` — SQLiteBackend async
- [x] `server/oseye/storage/repositories/events.py` — insert_batch, get, query, count
- [x] `server/oseye/storage/repositories/alerts.py`
- [x] `server/oseye/storage/repositories/decisions.py` — append-only, list_decisions
- [x] `server/oseye/storage/repositories/cases.py` — custody append-only

**Tests :** 16/16, SQLite :memory:. Couverture : events 86%, alerts 90%, decisions 93%, cases 75%

**Benchmarks :** insert_batch 1000 events → 189 ms / 5 290 events/s (SQLite :memory:)

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

## M11 — Infra & CI `[x]` — mergé 2026-08-06

**Branche :** `M11/infra-ci` → `main`

- [x] `agent/.golangci.yml` — 10 linters activés
- [x] `.env.example` — toutes les variables OSEYE_*
- [x] `agent/Dockerfile` — multi-stage Go 1.23-alpine
- [x] `server/Dockerfile` — Python 3.12-slim
- [x] `ui/Dockerfile` — node:20-alpine + nginx
- [x] `.github/workflows/ci.yml` — coverage threshold enforcement (BUG-002 ✅)

**Limitations actuelles :** lint-typescript, test-typescript, build-docker échouent — UI vide jusqu'en Phase 9

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
