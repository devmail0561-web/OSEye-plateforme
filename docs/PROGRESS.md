# OSEye — Suivi de progression

**Version :** 1.7
**Dernière mise à jour :** 2026-08-06
**Branche active :** `main` (`04c1611`)
**Phase courante :** Phase 2 — Full Collection `[~]` EN COURS — M12 complété (1/7 modules)

---

## Légende

| Symbole | Signification |
|---------|--------------|
| `[x]` | Terminé |
| `[~]` | En cours |
| `[ ]` | À faire |
| ⚠ | Bloque la suite |
| 🔴 | Bug critique / faille CRITICAL |
| 🟠 | Bug majeur / faille MAJOR |
| 🟡 | Problème mineur / dette technique |
| ✅ | Faux positif accepté / risque assumé / corrigé |

---

## Vue d'ensemble des modules

### Phase 1 — Foundation `[x]` COMPLÈTE

| # | Module | Statut | Tests | Notes |
|---|--------|--------|-------|-------|
| M0 | Scaffolding + Contrats | `[x]` Mergé | 15 py | — |
| M1 | Crypto & Buffer (Go) | `[x]` Mergé | 24 go | BLAKE3, Ed25519, SQLite dual |
| M2 | Collectors Linux (Go) | `[x]` Mergé | 7 go | procfs, auditd stub, CollectorManager |
| M3 | Transport gRPC Agent (Go) | `[x]` Mergé | 10 go | mTLS, batch sign, backoff exponentiel |
| M4 | Agent Bootstrap (Go) | `[x]` Mergé | — | Pipeline complet + SIGTERM drain |
| M5 | Event Bus (Python) | `[x]` Mergé | 9 py | InMemory + Redis Streams |
| M6 | Ingestion gRPC (Python) | `[x]` Mergé | 15 py | SEC-PREV-001 enforced |
| M7 | Normalizer (Python) | `[x]` Mergé | 14 py | procfs, auditd, eBPF adapters |
| M8 | Storage (Python) | `[x]` Mergé | 16 py | SEC-0002 triggers immuabilité |
| M9 | API REST + Auth (Python) | `[x]` Mergé | 6 py | JWT RS256, RBAC, slowapi |
| M10 | Workers Python | `[x]` Mergé | 5 py | storage_writer + runner |
| M11 | Infra & CI | `[x]` Mergé | — | Dockerfiles, CI coverage threshold |

**12/12 modules mergés sur main.** Phase 1 Foundation complète.

### Phase 2 — Full Collection `[~]` EN COURS

| # | Module | Statut | Tests | Notes |
|---|--------|--------|-------|-------|
| M12 | Collectors fanotify + inotify (Go) | `[x]` Mergé | 11 go | P2.01 + P2.02 complétés |

---

## Qualité du code — tableau de bord

| Dimension | Valeur | Seuil | Statut |
|-----------|--------|-------|--------|
| Tests Python (unit + integration + scenarios) | **97/97** | 100% | ✅ |
| Tests Go | **41 tests / 7 packages** | 100% | ✅ |
| ruff (server/oseye) | **0 erreur** | 0 | ✅ |
| mypy --strict (64 fichiers) | **0 erreur** | 0 | ✅ |
| go vet | **0 erreur** | 0 | ✅ |
| Couverture Go (code écrit) | chain 100%, config 100%, signer 87%, transport 75%, collector 97%, procfs 79%, buffer 73% | 80% | 🟡 buffer/transport |

### Répartition tests Python

| Répertoire | Tests | Ce qui est testé |
|------------|-------|-----------------|
| `tests/unit/` | 80 | Composants isolés (bus, schema, storage, API, ingest, normalizer, workers) |
| `tests/integration/` | 13 | Interaction entre modules (normalizer→bus, storage_writer→DB, gRPC mTLS réel) |
| `tests/scenarios/` | 4 | Scénarios bout-en-bout (agent→gRPC→bus→DB→API) |

---

## Failles de sécurité

| ID | Description | Statut |
|----|-------------|--------|
| SEC-0001 | CORS wildcard (faux positif — valeur par défaut `localhost:5173`) | ✅ FP accepté |
| SEC-0002 | Triggers immuabilité DB décisions/custody (M8) | ✅ Fermé |
| SEC-0003 | `shell=True` dans audit scanner (patterns versionnés, périmètre dev) | ✅ Risque assumé |
| SEC-0004 | Credentials dev en clair dans docker-compose | 🟡 Accepté dev |
| SEC-PREV-001 | agent_id depuis CN mTLS — jamais depuis payload (M6) | ✅ Enforced + testé mTLS |
| SEC-PREV-002 | Rate limiting `/auth/token` 5/min via slowapi (M9) | ✅ Enforced |
| SEC-RISK-001 | Fallback request.agent_id si CN absent — supprimé | ✅ Corrigé |

---

## Bugs corrigés (historique complet)

| ID | Description | Corrigé dans |
|----|-------------|-------------|
| BUG-001 | `getenvDuration` retournait des nanosecondes | M0 audit |
| BUG-002 | CI coverage threshold non enforced | M11 |
| BUG-003 | Pattern DBG-P003 incohérent | 🟡 Ouvert |
| BUG-004 | `Page[T]` non instanciable — workaround PageResult | M10 (DESIGN-002) |
| BUG-005 | go.mod M1 écrasé grpc+protobuf | fix commit |
| BUG-006 | `grpc_service` publiait sur `events:raw` au lieu de `events:normalized` | tests interaction |
| BUG-007 | `normalizer_bridge` : cmdline non masqué dans chemin gRPC | tests interaction |
| BUG-008 | `secret_masker` : pattern `-p` ne couvrait pas `-pPassword` (mysql) | tests interaction |
| BUG-009 | `_extract_cn_from_context` parsait CN comme certificat DER — gRPC Python retourne CN en UTF-8 bytes | test gRPC mTLS |
| BUG-010 | `main.py` ne démarrait pas le serveur gRPC dans le lifespan | test gRPC mTLS |

---

## Dettes techniques

| ID | Élément | Statut |
|----|---------|--------|
| DETTE-001 | `ui/package.json` absent — React/TypeScript/Vite (Phase 9) | 🟡 Ouvert (Phase 9) |
| DETTE-005 | `scripts/test_proto_compile.sh` non créé | ✅ Fermé (commit 94e25ff) |
| DETTE-007 | Proto codegen non exécuté (gen/ pré-existants, pas depuis protoc) | ✅ Fermé (generate_proto.sh détecte .venv) |
| DESIGN-001 | `EventBus` Protocol sans méthode `close()` — risque de leak | ✅ Fermé (déjà présent dans interface + implémentations) |
| DESIGN-002 | `PageResult[T]` redéfini dans chaque repository — factoriser | ✅ Fermé (core/pagination.py créé) |
| DESIGN-003 | `redis_bus.py subscribe_pattern` utilise `KEYS *` O(N) bloquant | ✅ Fermé (remplacé par scan_iter) |
| OTel-001 | `observability.py` : OTel SDK non initialisé (stub) | ✅ Fermé (commit 4f30268 — OTLP + Console exporters) |
| WARN-001 | `test_storage.py` : warnings `Event loop is closed` (aiosqlite teardown) | ✅ Fermé (commit 4f30268 — fixture avec close()) |

**7/8 dettes résolues** — seule reste DETTE-001 (UI Phase 9).

---

## Critères d'acceptance Phase 1

| Critère | Statut |
|---------|--------|
| `go test -race ./...` verts | ✅ 7 packages, 41 tests |
| `pytest tests/ --cov-fail-under=80` | 🟡 97 tests / couverture 73–86% selon module |
| `docker compose up --build --wait` | 🟡 `server/main.py` présent, build Docker non vérifié |
| Events gRPC insérés en DB | ✅ Prouvé par 7 tests mTLS réels |
| `GET /api/v1/events` retourne les events | ✅ Couvert par tests scénarios |
| CI GitHub Actions passe sur `main` | 🟡 Jobs UI/Docker skippés (Phase 9) |

---

## Benchmarks — chemins chauds (Intel i7-8665U, 1.9 GHz)

| Opération | Résultat | Cible | Marge |
|-----------|---------|-------|-------|
| BLAKE3 chain 1 KB (Go) | 428 MB/s — 2.4 µs/op | 500 MB/s | 0.9× |
| Ed25519 sign 32B (Go) | 43.7 µs → 22 900 signs/s | 2 signs/s | **11 450×** |
| Buffer Push/1000 — modernc (CGO=0) | 34 ms | — | CI cross-platform |
| Buffer Push/1000 — mattn+WAL (CGO=1) | 14 ms | — | prod |
| insert_batch 1000 events (Python/SQLite) | 189 ms → 5 290 events/s | — | pipeline M10 |

---

## Optimisations Python (perf/python-optimizations)

**30 bottlenecks résolus dans 13 fichiers** — mergé dans main le 2026-08-06 (commit `9323f13`).

| Fichier | Optimisations appliquées |
|---------|------------------------|
| `bus/redis_bus.py` | `scan_iter` natif (remplace `KEYS *`), batch `XACK`, dict O(1), purge `seen_topics` bornée |
| `bus/memory_bus.py` | timeout 1s sur `asyncio.wait_for`, dict O(1) pour lookup subscribers |
| `storage/repositories/events.py` | bulk insert `executemany`, helper `_event_to_dict`, `_apply_filters` exécuté une seule fois |
| `storage/repositories/alerts.py` | imports déplacés en tête de fichier |
| `storage/repositories/decisions.py` | imports déplacés en tête de fichier |
| `storage/repositories/cases.py` | imports déplacés en tête de fichier |
| `ingest/grpc_service.py` | index rejet O(1), compatibilité `asyncio` Python 3.12, `all_errors` borné |
| `workers/storage_writer.py` | `model_validate_json()` fast path (évite double décodage JSON) |
| `normalizer/engine.py` | appel direct callable (supprime indirection inutile) |
| `api/ws/manager.py` | `set` O(1) pour lookup/suppression connexions |
| `api/routers/events.py` | dataclasses et constantes définies au niveau module |
| `main.py` | `lru_cache` sur `Settings` (singleton settings) |

---

## Historique des commits (récents)

| Hash | Message | Date |
|------|---------|------|
| `04c1611` | Merge perf/python-optimizations → main | 2026-08-06 |
| `9323f13` | perf: optimisations Python M0-M12 — 30 bottlenecks résolus | 2026-08-06 |
| `018958a` | Merge M12/collectors-files → main | 2026-08-06 |
| `4f30268` | fix: résolution dettes OTel-001 et WARN-001 | 2026-08-06 |
| `3306675` | docs: PROGRESS v1.5 — Phase 1 complète, dettes résolues | 2026-08-06 |
| `94e25ff` | fix: résolution dettes techniques DETTE-007, DESIGN-001/002/003, DETTE-005 | 2026-08-06 |
| `422e66b` | docs: référencer DESCRIPTION.md et CONDUCT.md dans README | 2026-08-06 |
| `4c06d38` | docs: ajouter DESCRIPTION.md et CONDUCT.md | 2026-08-06 |
| `9559885` | docs: PROGRESS v1.4 + DEVELOPMENT_PLAN v1.2 — Phase 1 complète | 2026-08-06 |
| `f17dcaf` | docs: mettre à jour note.txt — commandes mTLS, dev-certs, tests gRPC | 2026-08-06 |
| `0fe6126` | feat: communication gRPC réelle + 3 corrections de bugs critiques | 2026-08-06 |
| `2850ed7` | tests: tests d'interaction modules + 3 corrections de bugs | 2026-08-06 |
