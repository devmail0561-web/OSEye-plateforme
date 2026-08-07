# OSEye — Suivi de progression

**Version :** 2.3
**Dernière mise à jour :** 2026-08-07
**Branche active :** `main` (`latest`)
**Phase courante :** Phase 4 — Intelligence `[ ]` À DÉMARRER

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
| M19 | Auditd collector (sans CGO) | `[x]` Mergé | 12 go | tail audit.log, parse SYSCALL, hex comm, dégradation gracieuse |
| M20 | eBPF collector (cilium/ebpf) | `[x]` Mergé | 9 go | execve+openat+connect, stub bpf2go, dégradation gracieuse |
| M21 | Tests de résilience E2E | `[x]` Mergé | 4 go | buffer drain, proto roundtrip, batcher flush |

**10/10 modules Phase 2 mergés sur main.** Phase 2 Full Collection **COMPLÈTE**.

### Phase 3 — Détection `[x]` COMPLÈTE

| # | Module | Branche | Statut | Tests |
|---|--------|---------|--------|-------|
| M22 | Rule Engine — parser, evaluator, engine, worker, 30 règles YAML | `M22/rule-engine` | `[x]` Mergé | 34 py |
| M23 | API `/rules` + `/alerts` étendu + WS `/ws/alerts` + câblage main | `M23/api-rules-ws-alerts` | `[x]` Mergé | 17 py |
| — | Audit Phase 3 — 32 corrections (RCE, auth, eBPF, règles mortes, races Go) | `fix/audit-phase3` | `[x]` Mergé | 178 py |
| M24 | API Keys (P3.12) + RBAC enforced (P3.13) + rule_versions (P3.14) | `M24/phase3-completion` | `[x]` Mergé | 18 py |

**Phase 3 Détection COMPLÈTE — 14/14 tâches (P3.01–P3.15).**

---

## Qualité du code — tableau de bord

| Dimension | Valeur | Seuil | Statut |
|-----------|--------|-------|--------|
| Tests Python (unit + integration + scenarios) | **196/196** | 100% | ✅ |
| Tests Go | **133 tests / 21 packages** | 100% | ✅ |
| ruff (server/oseye) | **0 erreur** | 0 | ✅ |
| mypy (rule_engine, workers, api, main — 23 fichiers) | **0 erreur** | 0 | ✅ |
| golangci-lint (agent) | **0 erreur** | 0 | ✅ |
| go build ./... | **0 erreur** | 0 | ✅ |
| go vet ./... | **0 erreur** | 0 | ✅ |
| go test -race ./... | **0 race** | 0 | ✅ |

### Répartition tests Python

| Répertoire | Tests | Ce qui est testé |
|------------|-------|-----------------|
| `tests/unit/` | 179 | Composants isolés (bus, schema, storage, API×3, ingest, normalizer×2, workers, rule_engine) |
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

## Audit code — Phase 3 (2026-08-07)

Audit complet réalisé sur les modules M22-M23 + agent Go (collecteurs eBPF, transport, policy, mapper).
**32 findings identifiés → 32 corrigés** dans `fix/audit-phase3` (commits `a2290bd` + `b9be613`).

### Findings résolus — Go (agent)

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| G1 | HIGH | `ebpf/loader.go` | `parseConnect` : guard `len(raw) < 44` insuffisant (struct 52 bytes) → panic |
| G2 | HIGH | `ebpf/loader.go` | `parseOpenat` : guard `len(raw) < 284` insuffisant (struct 292 bytes) → panic |
| G3 | HIGH | `ebpf/loader.go` | `ReadEvents` : double-close channel `out` si les deux goroutines se terminent |
| G4 | HIGH | `ebpf/collector.go` | Race condition sur `c.loader` entre `Start()` et `Stop()` |
| G5 | HIGH | `fanotify/collector.go` | Double-close `c.fd` si `Stop()` appelé 2× — undefined behavior kernel |
| G6 | HIGH | `inotify/collector.go` | Même double-close fd que fanotify |
| G7 | HIGH | `transport/grpc_client.go` | `SendBatch` : boucle retry infinie sans cap → agent bloqué définitivement |
| G8 | MEDIUM | `policy/handler.go` | Directive `collectors_enabled` no-op silencieux — ignoré sans log |
| G9 | MEDIUM | `config/config.go` | Absence de `Validate()` — config invalide détectée trop tard au runtime |
| G10 | CRITICAL | `mapper/mapper.go` | `mapCategory` retourne `"process"` pour tous events eBPF y compris réseau |
| G11 | CRITICAL | `mapper/mapper.go` | `mapFields` : champs eBPF `comm`/`filename`/`event_type` non extraits |

### Findings résolus — Python (server)

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| P1 | CRITICAL | `rule_engine/evaluator.py` | Module `re` complet dans sandbox → accès `__globals__` → RCE |
| P2 | CRITICAL | `api/routers/auth.py` | Stub d'auth acceptant tout → n'importe qui peut s'authentifier |
| P3 | CRITICAL | `main.py` | Lifespan incomplet : `jwt_handler` et `event_repo` absents de `app.state` |
| P4 | HIGH | `rule_engine/evaluator.py` | `_temporal_windows` sans verrou threading → race + memory leak sans purge |
| P5 | HIGH | `api/ws/alerts.py` | WebSocket `/ws/alerts` sans authentification JWT |
| P6 | HIGH | `api/auth/jwt.py` | `detail=f"Invalid token: {exc}"` → fuite d'information dans les 401 |
| P7 | MEDIUM | `workers/storage_writer.py` | Double parse JSON (`json.loads` + `model_validate_json`) inutile |
| P8 | MEDIUM | `bus/redis_bus.py` | `except Exception: pass` silencieux sans backoff exponentiel |
| P9 | MEDIUM | `normalizer/adapters/linux/procfs.py` | `int(data.get(...))` non gardé → crash si champ manquant |
| P10 | MEDIUM | `normalizer/adapters/linux/auditd.py` | Idem procfs pour pid/ppid/uid/gid |
| P11 | MEDIUM | `normalizer/adapters/linux/ebpf.py` | `executable` depuis `"exe"` (absent) ; `src_ip`/`src_port` extraits (collecteur Go n'émet que dst) |
| P12 | MEDIUM | `storage/repositories/alerts.py` | `list()` sans `ORDER BY` → ordre non déterministe |
| P13 | MEDIUM | `api/routers/alerts.py` | `AlertPatch.assigned_to` sans contrainte longueur |
| P14 | LOW | `rule_engine/engine.py` | Hot-reload ne scanne que `*.yaml`, ignore `*.yml` |
| P15 | LOW | `workers/runner.py` | `hostname="localhost"` codé en dur |
| P16 | LOW | `core/observability.py` | `ExceptionPrettyPrinter(file=sys.stderr)` non structuré ; OTEL `insecure=True` hardcodé |

### Findings résolus — Règles YAML

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| R1 | CRITICAL | `credential_access.yaml` | `rule_ssh_bruteforce` : condition `event.result == "denied"` toujours false → règle morte |
| R2 | HIGH | `lateral_movement.yaml` | `rule_port_scan` : condition `event.result == "refused"` toujours false → règle morte |
| R3 | HIGH | `defense_evasion.yaml` | `rule_history_clear` : `category==process AND type==delete` impossible → règle morte |
| R4 | MEDIUM | `credential_access.yaml` | `rule_ssh_private_key_access` : faux positifs ssh/ssh-agent/git |
| R5 | MEDIUM | `lateral_movement.yaml` | `rule_ssh_lateral` : `dst_ip contains "172."` trop large (non RFC 1918) |
| R6 | MEDIUM | `lateral_movement.yaml` | `rule_rsync_exfil` : sans timeframe/threshold → alerte sur chaque rsync |
| R7 | MEDIUM | `discovery.yaml` | `rule_recon_enumeration` + `rule_process_discovery` : thresholds trop bas → faux positifs |
| R8 | MEDIUM | `impact_c2.yaml` | `rule_outbound_c2_beaconing` : même problème `"172."` que R5 |
| R9 | LOW | `privilege_escalation.yaml` | `rule_polkit_abuse` : MITRE `T1548` trop large → `T1548.003` |
| R10 | LOW | `credential_access.yaml` | `rule_memory_dump_mimipenguin` : MITRE `T1003.001` incorrect → `T1003.007` |

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
| SEC-AUDIT3-001 | RCE sandbox : module `re` complet dans l'évaluateur → accès `__globals__` | ✅ Corrigé (fix/audit-phase3) |
| SEC-AUDIT3-002 | Auth stub : `POST /auth/token` acceptait tout login/password | ✅ Corrigé — bcrypt passlib |
| SEC-AUDIT3-003 | WebSocket `/ws/alerts` sans auth JWT | ✅ Corrigé — token query param |
| SEC-AUDIT3-004 | `jwt.py` : detail exception révélait le type d'erreur dans les 401 | ✅ Corrigé — opacifié |

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
| BUG-019 | eBPF mapper : tous les events réseau classés `"process"` au lieu de `"network"` | fix/audit-phase3 |
| BUG-020 | `parseConnect` panic si payload < 52 bytes (guard à 44) | fix/audit-phase3 |
| BUG-021 | `parseOpenat` panic si payload < 292 bytes (guard à 284) | fix/audit-phase3 |
| BUG-022 | Double-close fd fanotify/inotify → undefined behavior | fix/audit-phase3 |
| BUG-023 | `SendBatch` retry infini sans cap → agent bloqué | fix/audit-phase3 |
| BUG-024 | `rule_ssh_bruteforce` condition morte (`event.result == "denied"`) | fix/audit-phase3 |
| BUG-025 | `rule_port_scan` condition morte (`event.result == "refused"`) | fix/audit-phase3 |
| BUG-026 | `rule_history_clear` condition impossible (`process AND type==delete`) | fix/audit-phase3 |
| BUG-027 | `main.py` lifespan : `jwt_handler` / `event_repo` absents de `app.state` | fix/audit-phase3 |
| BUG-028 | `_temporal_windows` memory leak (pas de purge TTL) + race threading | fix/audit-phase3 |

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
| `28c9185` | feat(M24): P3.12 API Keys + P3.13 RBAC + P3.14 rule_versions — Phase 3 COMPLÈTE | 2026-08-07 |
| `b9be613` | fix(audit-phase3): corrections Python, règles YAML et adapters | 2026-08-07 |
| `a2290bd` | fix(audit-phase3): 32 corrections audit — RCE sandbox, auth, eBPF, regles mortes, races Go | 2026-08-07 |
| `41ea617` | docs: PROGRESS v2.1 — M23 mergé, 178 tests, P3.09-P3.11 cochés | 2026-08-07 |
| `3552819` | Merge M23/api-rules-ws-alerts → main | 2026-08-07 |
| `9894ea5` | feat(M23): API rules + WS alerts + câblage RuleWorker en production | 2026-08-07 |
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
