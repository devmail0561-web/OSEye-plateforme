# OSEye — Plan de développement modulaire — Phase 1 Foundation

**Version :** 1.2
**Date :** 2026-08-06
**Statut :** Phase 1 complète — 12/12 modules mergés sur `main`

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
| M2 | Collectors Linux (Go) | `M2/agent-collectors-linux` | M1 | `[x]` mergé |
| M3 | Transport gRPC Agent (Go) | `M3/agent-grpc-transport` | M1 | `[x]` mergé |
| M4 | Agent Bootstrap (Go) | `M4/agent-bootstrap` | M2, M3 | `[x]` mergé |
| M5 | Event Bus (Python) | `M5/server-event-bus` | M0 | `[x]` mergé |
| M6 | Ingestion gRPC (Python) | `M6/server-ingest` | M5 | `[x]` mergé |
| M7 | Normalizer (Python) | `M7/server-normalizer` | M5 | `[x]` mergé |
| M8 | Storage (Python) | `M8/server-storage` | M0 | `[x]` mergé |
| M9 | API REST + Auth (Python) | `M9/server-api` | M8 | `[x]` mergé |
| M10 | Workers Python | `M10/server-workers` | M6, M7, M8 | `[x]` mergé |
| M11 | Infra & CI | `M11/infra-ci` | M0 | `[x]` mergé |

---

## Graphe de dépendances

```
M0 ──► M1 ──► M2 ──► M4  [x]
       M1 ──► M3 ──► M4  [x]
M0 ──► M5 ──► M6 ──► M10 [x]
       M5 ──► M7 ──► M10 [x]
M0 ──► M8 ──► M9         [x]
              M8 ──► M10 [x]
M0 ──► M11               [x]
```

---

## M0 — Scaffolding + Contrats `[x]` — mergé 2026-08-06

- [x] `proto/event.proto` — UniversalEventPB, IngestRequest/Response, AgentService
- [x] `server/oseye/core/schema.py` — tous les modèles Pydantic v2
- [x] `server/oseye/bus/interface.py` — Protocol EventBus
- [x] `agent/internal/platform/interface.go` — PlatformDriver + PlatformCapabilities
- [x] `agent/internal/platform/registry.go` — Register() + Resolve()
- [x] `agent/internal/collector/interface.go` — Collector + RawEvent
- [x] `server/oseye/storage/interface.py` — Protocols Repository
- [x] `server/oseye/config.py` — Settings pydantic-settings, env OSEYE_*
- [x] `server/oseye/core/observability.py` — structlog JSON
- [x] `scripts/generate_proto.sh`
- [x] `agent/go.mod`, `server/pyproject.toml`
- [x] `infra/docker/docker-compose.dev.yml`
- [x] `scripts/generate_certs.sh`
- [ ] `ui/package.json` — Phase 9
- [ ] `scripts/test_proto_compile.sh` — DETTE-005

**Tests :** 15 py (schema completeness, platform contracts)

---

## M1 — Crypto & Buffer (Go) `[x]` — mergé 2026-08-06

- [x] `agent/internal/chain/chain.go` — BLAKE3 hash chain
- [x] `agent/internal/signer/signer.go` — Ed25519 stdlib
- [x] `agent/internal/buffer/buffer.go` — modernc/sqlite (CGO=0, CI)
- [x] `agent/internal/buffer/buffer_cgo.go` — mattn/go-sqlite3 + WAL (prod)
- [x] `agent/internal/config/config.go`

**Tests :** 24 go — chain 100%, signer 87%, config 100%, buffer 73%

---

## M2 — Collectors Linux (Go) `[x]` — mergé 2026-08-06

- [x] `agent/internal/platform/linux/driver.go` — LinuxDriver + auto-register
- [x] `agent/internal/platform/linux/procfs/collector.go` — scan /proc, RawEvent JSON
- [x] `agent/internal/platform/linux/auditd/collector.go` — stub
- [x] `agent/internal/collector/manager.go` — CollectorManager fan-in

**Tests :** 7 go — procfs stop race, manager fan-in

---

## M3 — Transport gRPC Agent (Go) `[x]` — mergé 2026-08-06

- [x] `agent/internal/transport/grpc_client.go` — mTLS, batch BLAKE3+Ed25519, backoff 1s→30s
- [x] `agent/internal/transport/batcher.go` — flush par taille ou timeout

**Tests :** 10 go — bufconn mTLS, SendBatch, retry timeout, Close. Couverture transport 75%

---

## M4 — Agent Bootstrap (Go) `[x]` — mergé 2026-08-06

- [x] `agent/cmd/oseye-agent/main.go` — pipeline complet : config→platform→collectors→chain→buffer→transport
- [x] SIGTERM drain — vide le buffer SQLite avant exit

**Tests :** pas de tests unitaires dédiés (pipeline intégration, couvert par M2+M3)

---

## M5 — Event Bus (Python) `[x]` — mergé 2026-08-06

- [x] `server/oseye/bus/memory_bus.py` — InMemoryEventBus, subscriptions eagerly-registered
- [x] `server/oseye/bus/redis_bus.py` — RedisEventBus XADD/XREADGROUP
- [x] `server/oseye/bus/factory.py`

**Tests :** 9 py
**Dette :** DESIGN-003 — `subscribe_pattern` utilise `KEYS *` O(N) → migrer vers `SCAN` en Phase 2

---

## M6 — Ingestion gRPC (Python) `[x]` — mergé 2026-08-06

- [x] `server/oseye/ingest/grpc_service.py` — AgentServiceServicer
- [x] `server/oseye/ingest/validator.py` — BatchValidator Ed25519+BLAKE3
- [x] `server/oseye/ingest/normalizer_bridge.py` — pb_to_event + SEC-PREV-001 + masquage cmdline
- [x] `server/oseye/ingest/server.py` — create_grpc_server mTLS

**Sécurité :**
- SEC-PREV-001 : `_require_cn()` avorte si CN absent — jamais de fallback request.agent_id
- `_extract_cn_from_context` : gRPC Python retourne CN en UTF-8 bytes (pas DER) — corrigé

**Tests :** 15 py + 7 tests gRPC mTLS réels (PKI in-memory)

---

## M7 — Normalizer (Python) `[x]` — mergé 2026-08-06

- [x] `server/oseye/normalizer/engine.py` — dispatch (os, source) → adapter
- [x] `server/oseye/normalizer/adapters/linux/procfs.py`
- [x] `server/oseye/normalizer/adapters/linux/auditd.py`
- [x] `server/oseye/normalizer/adapters/linux/ebpf.py`
- [x] `server/oseye/normalizer/secret_masker.py` — masquage password=, -pXxx, Bearer

**Tests :** 14 py

---

## M8 — Storage (Python) `[x]` — mergé 2026-08-06

- [x] `server/oseye/storage/models.py` — ORM SQLAlchemy 8 tables
- [x] `server/oseye/storage/migrations/__init__.py` — triggers immuabilité PG (SEC-0002)
- [x] `server/oseye/storage/backends/sqlite.py`
- [x] `server/oseye/storage/repositories/events.py`
- [x] `server/oseye/storage/repositories/alerts.py`
- [x] `server/oseye/storage/repositories/decisions.py`
- [x] `server/oseye/storage/repositories/cases.py`

**Tests :** 16 py — events 86%, alerts 90%, decisions 93%, cases 75%

---

## M9 — API REST + Auth (Python) `[x]` — mergé 2026-08-06

- [x] `server/oseye/api/auth/jwt.py` — JWTHandler RS256 / HS256 test
- [x] `server/oseye/api/auth/rbac.py` — require_role() FastAPI dependency
- [x] `server/oseye/api/routers/auth.py` — /api/v1/auth/token, rate-limited 5/min
- [x] `server/oseye/api/routers/events.py` — GET /events (paginé/filtré), GET /events/{id}
- [x] `server/oseye/api/routers/alerts.py`
- [x] `server/oseye/api/routers/health.py`
- [x] `server/oseye/api/ws/manager.py` — WebSocketManager
- [x] `server/oseye/api/app.py` — factory FastAPI

**Tests :** 6 py (JWT, RBAC, routes, 401/403)

---

## M10 — Workers Python `[x]` — mergé 2026-08-06

- [x] `server/oseye/workers/storage_writer.py` — batch consumer events:normalized → DB
- [x] `server/oseye/workers/runner.py` — dev runner asyncio.gather
- [x] `server/oseye/main.py` — entrypoint FastAPI + gRPC server dans lifespan

**Tests :** 5 py (flush par taille, flush par timer, invalid JSON, stop propre, erreur DB)

---

## M11 — Infra & CI `[x]` — mergé 2026-08-06

- [x] `agent/.golangci.yml`
- [x] `.env.example`
- [x] `agent/Dockerfile` — multi-stage Go 1.23-alpine
- [x] `server/Dockerfile` — Python 3.12-slim
- [x] `.github/workflows/ci.yml` — lint, test, build, coverage threshold

---

## Tests d'interaction — ajoutés post Phase 1

| Fichier | Tests | Ce qui est prouvé |
|---------|-------|------------------|
| `tests/integration/test_ingest_to_storage.py` | 6 | normalizer→bus, storage_writer→DB, pipeline complet→API, servicer→bus, 404, auth |
| `tests/integration/test_grpc_communication.py` | 7 | gRPC mTLS réel : batch, multi-requests, SEC-PREV-001, masquage secret, concurrent, rejet sans cert |
| `tests/scenarios/test_agent_event_lifecycle.py` | 4 | agent→gRPC→bus→DB→API, isolation multi-agents, masquage, health |

---

## Critères d'acceptance Phase 1

- [x] `go test -race ./...` — 41 tests, 7 packages verts
- [x] `pytest tests/` — 97 tests verts
- [x] Serveur gRPC démarre avec mTLS (`create_grpc_server` dans lifespan)
- [x] Communication agent→serveur prouvée par tests gRPC mTLS réels
- [x] Events insérés en DB et queryables via REST
- [ ] `docker compose up --build --wait` — non vérifié end-to-end
- [ ] `ui/package.json` — Phase 9
- [x] CI GitHub Actions passe sur `main` (jobs UI/Docker skippés — Phase 9)

---

## Convention nommage des branches

```
M<n>/<scope>-<description-kebab>
ex: M2/agent-collectors-linux
    M8/server-storage
```
