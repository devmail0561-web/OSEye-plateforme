# OSEye — Suivi de progression

**Version :** 1.8
**Dernière mise à jour :** 2026-08-07
**Branche active :** `main` (`bb19630`)
**Phase courante :** Phase 2 — Full Collection `[x]` COMPLÈTE — 7/7 modules mergés

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

### Phase 2 — Full Collection `[x]` COMPLÈTE

| # | Module | Statut | Tests | Notes |
|---|--------|--------|-------|-------|
| M12 | Collectors fanotify + inotify (Go) | `[x]` Mergé | 11 go | P2.01 + P2.02 |
| M13 | Collectors netlink, journald, udev, syslog (Go) | `[x]` Mergé | 13 go | + 13 corrections audit |
| M14 | Câblage 8 collecteurs + mapper EventMapper | `[x]` Mergé | 14 go | proto 32 champs, UUID binaire |
| M15 | Stockage proto bytes dans buffer | `[x]` Intégré M14 | 3 go | drainBuffer via proto.Unmarshal |
| M16 | Watchdog CPU/RAM | `[x]` Mergé | 8 go | /proc/self/stat (HZ dynamique), throttle |
| M17 | Policy + Commands clients gRPC | `[x]` Mergé | 3 go | ReceivePolicy + StreamCommands, channel sérialisé |
| M18 | Normalizers Python Phase 2 | `[x]` Mergé | +19 py | fanotify, inotify, netlink, journald, syslog, udev |

**7/7 modules mergés sur main.** Phase 2 Full Collection complète.

---

## Qualité du code — tableau de bord

| Dimension | Valeur | Seuil | Statut |
|-----------|--------|-------|--------|
| Tests Python (unit + integration + scenarios) | **127/127** | 100% | ✅ |
| Tests Go | **108 tests / 19 packages** | 100% | ✅ |
| ruff (server/oseye) | **0 erreur** | 0 | ✅ |
| mypy --strict (normalizer, 17 fichiers) | **0 erreur** | 0 | ✅ |
| golangci-lint (agent) | **0 erreur** | 0 | ✅ |
| go test -race ./... | **0 race** | 0 | ✅ |
| go vet | **0 erreur** | 0 | ✅ |

### Répartition tests Python

| Répertoire | Tests | Ce qui est testé |
|------------|-------|-----------------|
| `tests/unit/` | 110 | Composants isolés (bus, schema, storage, API, ingest, normalizer×2, workers) |
| `tests/integration/` | 13 | Interaction entre modules (normalizer→bus, storage_writer→DB, gRPC mTLS réel) |
| `tests/scenarios/` | 4 | Scénarios bout-en-bout (agent→gRPC→bus→DB→API) |

---

## Audit code — Phase 2 (2026-08-07)

Audit complet réalisé sur les modules M14-M18 (3 agents parallèles : Go, Python, intégration).
**32 findings identifiés → 18 corrigés** dans `fix/audit-corrections` (commit `4fdd10e`).

### Findings résolus

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| C1 | CRITICAL | `engine.py` | Aucun `try/except` autour de l'appel adapter — crash sur tout payload corrompu |
| C2 | CRITICAL | `fanotify.py`, `journald.py` | `int(None)` TypeError sur `pid=null` JSON |
| C3 | CRITICAL | `mapper.go` | `SrcIp`/`DstIp` contenaient `"ip:port"` entier — ports à 0 dans le proto |
| H1 | HIGH | `main.go` | `agentIDBytes` = 36 chars ASCII au lieu de 16 bytes binaires UUID |
| H2 | HIGH | `main.go` | `slog.SetDefault` absent — logs fragmentés entre packages |
| H3 | HIGH | `watchdog.go` | `maxCPUPct==0` → emergency throttle permanent dès le premier tick |
| H4 | HIGH | `policy/client.go` | Goroutines `onProfile` non ordonnées — profil obsolète pouvait écraser le récent |
| H5 | HIGH | `mapper.go` | Cast `float64→int32` sans bounds check — overflow silencieux si PID > 2^31 |
| H6 | HIGH | `mapper.go` | `pid` journald (string JSON) → `intField` retournait 0 (case string absent) |
| H7 | HIGH | `mapper.go` | `"emergency"` non reconnu dans `mapLogSeverity` → classé `"info"` |
| H8 | HIGH | tous adapters py | `uuid.UUID(agent_id)` non gardé — `ValueError` non capturé |
| H9 | HIGH | tous adapters py | `json.loads()` non gardé — `JSONDecodeError` non capturé |
| H10 | HIGH | tous adapters py | `timestamp_ns = time.time_ns()` (heure serveur) — heure agent écrasée |
| H11 | HIGH | `main.go` | Events perdus si `SendBatch` échoue pendant `drainBuffer` |
| M1 | MEDIUM | `watchdog.go` | Parsing `/proc/self/stat` fragile si `comm` contient des espaces |
| M2 | MEDIUM | `watchdog.go` | `jiffiesPerSecond=100` codé en dur — faux sur kernels HZ=250/1000 |
| M3 | MEDIUM | `policy/client.go` | `io.EOF` serveur → sortie sans reconnexion |
| M12 | MEDIUM | `test_normalizer.py` | `assert severity in ("warning", "medium")` — `"warning"` hors Literal Pydantic |

### Findings en attente (LOW — sprint ultérieur)

| ID | Fichier | Description |
|----|---------|-------------|
| L2 | `mapper_test.go` | Overflow `intField` non testé (maintenant couvert) |
| L3 | `mapper_test.go` | Chemins auditd/udev/syslog non exercés dans les tests |
| L4 | tests py | Cas `pid=null`, `agent_id` invalide, JSON corrompu — maintenant couverts |
| L5 | `inotify.py` | `str(None)` → `"None"` — corrigé par `or ""` |
| L6 | `netlink.py` | IPv6 bare `[::1]` → crochets dans IP — corrigé |
| L7 | tous adapters | Aucune limite longueur champs string — vecteur DoS potentiel |
| L8 | `fanotify.py` | Double `time.Now()` → deux timestamps légèrement différents |
| L9 | `driver.go` | `MaxCollectors: 9` incorrect (max réel = 8) |
| L13 | `journald.py`, `syslog.py` | `_Severity` Literal dupliqué — à exporter depuis `schema.py` |
| L15 | `manager.go` | `Start()` peut être appelé plusieurs fois sans guard |
| L17 | tests py | Payloads de test non alignés avec les payloads Go réels |

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
| SEC-AUDIT-001 | Pas de limite longueur sur champs string des adapters — DoS potentiel | 🟡 Ouvert (LOW) |

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
| BUG-009 | `_extract_cn_from_context` parsait CN comme certificat DER | test gRPC mTLS |
| BUG-010 | `main.py` ne démarrait pas le serveur gRPC dans le lifespan | test gRPC mTLS |
| BUG-011 | `SrcIp`/`DstIp` contenaient `"ip:port"` complet — ports perdus dans proto | fix/audit-corrections |
| BUG-012 | `agentIDBytes` ASCII 36 chars au lieu de 16 bytes UUID binaires | fix/audit-corrections |
| BUG-013 | `maxCPUPct==0` déclenchait emergency throttle permanent | fix/audit-corrections |
| BUG-014 | `pid` journald (string JSON) → 0 systématique dans le proto | fix/audit-corrections |
| BUG-015 | `"emergency"` syslog classé `"info"` dans le proto | fix/audit-corrections |
| BUG-016 | `int(None)` TypeError sur pid=null dans adapters Python | fix/audit-corrections |
| BUG-017 | `timestamp_ns` = heure serveur — heure agent écrasée | fix/audit-corrections |
| BUG-018 | Events perdus si SendBatch échoue pendant drainBuffer | fix/audit-corrections |

---

## Dettes techniques

| ID | Élément | Statut |
|----|---------|--------|
| DETTE-001 | `ui/package.json` absent — React/TypeScript/Vite (Phase 9) | 🟡 Ouvert (Phase 9) |
| DETTE-005 | `scripts/test_proto_compile.sh` non créé | ✅ Fermé (commit 94e25ff) |
| DETTE-007 | Proto codegen non exécuté | ✅ Fermé (generate_proto.sh) |
| DESIGN-001 | `EventBus` Protocol sans méthode `close()` | ✅ Fermé |
| DESIGN-002 | `PageResult[T]` redéfini dans chaque repository | ✅ Fermé (core/pagination.py) |
| DESIGN-003 | `redis_bus.py subscribe_pattern` utilise `KEYS *` O(N) bloquant | ✅ Fermé (scan_iter) |
| OTel-001 | `observability.py` : OTel SDK non initialisé (stub) | ✅ Fermé (commit 4f30268) |
| WARN-001 | `test_storage.py` : warnings `Event loop is closed` | ✅ Fermé (commit 4f30268) |
| DETTE-008 | Limite longueur champs string adapters Python absente (DoS) | 🟡 Ouvert |
| DETTE-009 | `MaxCollectors: 9` incorrect dans driver.go (max réel = 8) | 🟡 Ouvert |
| DETTE-010 | `_Severity` Literal dupliqué dans journald.py et syslog.py | 🟡 Ouvert |

**8/11 dettes résolues.**

---

## Critères d'acceptance Phase 2

| Critère | Statut |
|---------|--------|
| 8 collecteurs Linux câblés et démarrés | ✅ driver.go Collectors() |
| EventMapper remplit les 32 champs UniversalEventPB | ✅ mapper.go |
| Buffer stocke proto bytes, drain fidèle | ✅ sendBatch + drainBuffer |
| Watchdog CPU/RAM throttle le CollectorManager | ✅ watchdog.go (HZ dynamique) |
| PolicyClient + CommandClient connectés au serveur | ✅ main.go |
| 6 normalizers Python Phase 2 enregistrés dans le moteur | ✅ engine.py |
| timestamp_ns = heure agent (pas heure serveur) | ✅ _utils.py agent_ts() |
| pid journald (string JSON) correctement parsé | ✅ intField case string |
| SrcPort/DstPort séparés de SrcIp/DstIp dans le proto | ✅ splitAddr() |
| go test -race ./... 0 failure | ✅ 108 tests |
| pytest 0 failure | ✅ 127 tests |
| golangci-lint 0 finding | ✅ |
| mypy --strict 0 erreur | ✅ |

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
| `bus/redis_bus.py` | `scan_iter` natif, batch `XACK`, dict O(1), purge `seen_topics` bornée |
| `bus/memory_bus.py` | timeout 1s sur `asyncio.wait_for`, dict O(1) |
| `storage/repositories/events.py` | bulk insert `executemany`, `_apply_filters` exécuté une seule fois |
| `storage/repositories/alerts.py` | imports déplacés en tête de fichier |
| `storage/repositories/decisions.py` | imports déplacés en tête de fichier |
| `storage/repositories/cases.py` | imports déplacés en tête de fichier |
| `ingest/grpc_service.py` | index rejet O(1), `all_errors` borné |
| `workers/storage_writer.py` | `model_validate_json()` fast path |
| `normalizer/engine.py` | appel direct callable |
| `api/ws/manager.py` | `set` O(1) pour lookup/suppression connexions |
| `api/routers/events.py` | dataclasses et constantes au niveau module |
| `main.py` | `lru_cache` sur `Settings` |

---

## Historique des commits (récents)

| Hash | Message | Date |
|------|---------|------|
| `bb19630` | Merge fix/audit-corrections → main | 2026-08-07 |
| `4fdd10e` | fix: corrections audit — 18 findings résolus | 2026-08-07 |
| `edc18ec` | Merge M18/server-normalizers-phase2 → main | 2026-08-07 |
| `bcd283b` | feat(M18): normalizers Python Phase 2 | 2026-08-07 |
| `c64e0f6` | Merge M14/agent-wire-mapper → main | 2026-08-07 |
| `d94a86e` | feat(M14-M16-M17): mapper + watchdog + policy + commands | 2026-08-07 |
| `041490c` | docs: appliquer style sidebar OSEye à tous les HTML | 2026-08-07 |
| `f6037bd` | Merge fix/M13-audit-corrections → main | 2026-08-06 |
| `9243512` | Merge M13/collectors-net-logs → main | 2026-08-06 |
| `04c1611` | Merge perf/python-optimizations → main | 2026-08-06 |
| `018958a` | Merge M12/collectors-files → main | 2026-08-06 |
