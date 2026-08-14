# OSEye — Suivi de progression

**Version :** 3.9
**Dernière mise à jour :** 2026-08-14
**Branche active :** `main` (`latest`)
**Phase courante :** Post-Phase 10 — Autonomie locale + Audit complet 2026-08-14

---

## Session 2026-08-14 — Autonomie locale + Audit complet `[x]` TERMINÉ

### Moteur d'autonomie locale (v0.1.0-alpha.1)
- Implémentation complète : `agent/internal/localrules/`, `hostprofile/`, `autonomy/`
- 3 types de règles : Simple, Correlation, Sequence
- 4 niveaux d'autonomie : `always_act`, `critical_high`, `critical_only`, `log_only`
- Kill switch double verrou (flag atomique + sentinel file /etc/oseye/disable_autonomy)
- Rollback automatique cascade (≥3 cibles en 60s)
- Server-side : `rule_signer.py`, `rules/agent/core.yaml` (10 règles), push dans PolicyEngine
- CLI `oseye-config`, SAD mis à jour (v1.2)

### Audit complet 2026-08-14 — 94 findings, 94 corrigés
| Sévérité | Findings | Corrigés |
|----------|----------|----------|
| CRITICAL | 5 | 5 |
| HIGH | 18 | 18 |
| MEDIUM | 42 | 42 |
| LOW | 29 | 29 |
| **Total** | **94** | **94** |

**Commits :** `07e1979` (10 CRITICAL/HIGH) · `4676e80` (4 HIGH) · `b4e427c` (71 MEDIUM/LOW) · `ccf6715` (régressions tests)

**Tests :** Go 31 packages OK (race-free) · Python 451 passed, 0 failed · ruff 0 erreurs · binary 24MB

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

### Phase 5 — Decision Engine `[x]` COMPLÈTE

| # | Module | Statut | Tests | Notes |
|---|--------|--------|-------|-------|
| M27 | Decision Engine — WeightedScorer, RiskMatrix, PolicyOverrides, Journal BLAKE3 | `[x]` Mergé | 30 py | decision/engine.py + journal.py |
| M28 | HumanQueue, ActionExecutor, DecisionWorker, API /decisions | `[x]` Mergé | — | câblage complet main.py |
| — | Audit Phase 5 — 6 corrections (journal, TOCTOU, flooding, filtre, str(None)) | `main` | `[x]` Mergé | 251 py |

**Phase 5 Decision Engine COMPLÈTE — 251 tests verts.**

---

### Phase 6 — ML Engine `[x]` COMPLÈTE

| # | Module | Statut | Tests | Notes |
|---|--------|--------|-------|-------|
| M29 | MLEngine complet — features, anomaly, classifier, engine, ab_test, ml_worker | `[x]` Mergé | 54 py | P6.01–P6.10 tous livrés |

**Composants livrés (M29) :**

- `ml_engine/features.py` — vecteur 10-dim [0,1] depuis UniversalEvent
- `ml_engine/anomaly.py` — EntityAnomalyDetector (HalfSpaceTrees River, LRU 10 000 modèles, window adaptative, decaying-max, save/load pickle)
- `ml_engine/classifier.py` — MITREClassifier (LogisticRegression online par technique)
- `ml_engine/engine.py` — MLEngine : `ml_score = 0.7×anomaly + 0.3×classifier` + checkpoint
- `ml_engine/ab_test.py` — ABTestSession champion/challenger, métriques (mean, p95, disagree_rate, promote) — P6.08 ✓
- `workers/ml_worker.py` — consomme `events:normalized`, publie `analysis:ml`, checkpoint auto — P6.06 ✓
- `storage/models.py` — EntityHourlyStatsRow (10 agrégats, index composite) — P6.09 ✓
- `storage/migrations/__init__.py` — refresh_entity_hourly_stats() PostgreSQL + SQLite UNIQUE INDEX
- Tests FP < 5% workloads propres, recall > 80% DNS exfil + priv esc — P6.10 ✓

**311 tests verts (35 ml_engine + 7 ml_worker + 12 quality + 257 existants).**

**Phase 6 ML Engine COMPLÈTE.**

---

### Phase 8 — Policy Engine + Plugin SDK `[x]` COMPLÈTE

| # | Module | Statut | Tests | Notes |
|---|--------|--------|-------|-------|
| M31 | Policy Engine + Plugin SDK | `[x]` Mergé | 18 py | P8.01-P8.15 livrés ; P8.04 agent Go reporté Phase 10 |

**Composants livrés (M31) :**

- `policy/profiles/` — 6 profils YAML (workstation, server, investigation, minimal, compliance, stealth)
- `policy/engine.py` — PolicyEngine : load_profiles(), push_to_agent(), push_to_all()
- `sdk/oseye_sdk/` — Plugin SDK : Event (frozen), Plugin/Analyzer/Exporter/Collector ABC, IPCClient/Server NDJSON Unix socket
- `plugin/verifier.py` — signature Ed25519 (cryptography)
- `plugin/sandbox.py` — subprocess + rlimit + cgroups v2 fallback
- `plugin/manager.py` — lifecycle install/enable/disable/delete + asyncio.Lock
- `plugin/examples/` — notifier_pagerduty.py, exporter_s3.py (stubs)
- `api/routers/policies.py` + `api/routers/plugins.py` — API REST complète
- `sdk/pyproject.toml` — SDK installable (`pip install -e sdk/`)

**Phase 8 Policy Engine + Plugin SDK COMPLÈTE — 333 tests verts.**

---

### Phase 7 — Forensics `[x]` COMPLÈTE

| # | Module | Statut | Tests | Notes |
|---|--------|--------|-------|-------|
| M30 | Forensics serveur — CaseManager, Snapshot, Timeline, Exporters, API | `[x]` Mergé | 23 py | P7.03-P7.12 livrés ; P7.01-P7.02 (agent Go snapshot.go) reportés Phase 10 |

**Composants livrés (M30) :**

- `forensic/case_manager.py` — CRUD ForensicCase + custody log BLAKE2b chaîné + append-only
- `forensic/snapshot.py` — AgentSnapshot, diff_snapshots() (processus + connexions), SQLSnapshotRepository
- `forensic/timeline.py` — build_timeline() — event/alert/custody triés par timestamp_ns
- `forensic/exporter/json_export.py` — bundle JSON complet
- `forensic/exporter/html_report.py` — rapport HTML autonome dark theme, XSS-safe
- `forensic/exporter/pdf_report.py` — PDF via WeasyPrint (graceful si absent)
- `forensic/exporter/misp_export.py` — MISP v2.4 (threat_level, IPs, techniques MITRE)
- `forensic/exporter/thehive_export.py` — TheHive 5 /api/v1/case
- `api/routers/cases.py` — CRUD + notes + evidence + close + timeline + custody + 5 exports
- `api/routers/snapshots.py` — POST/GET snapshot + diff
- `core/schema.py` — +ProcessInfo, ConnectionInfo, AgentSnapshot
- `storage/models.py` — +SnapshotRow

**Phase 7 Forensics COMPLÈTE — 315 tests verts.**

---

### Phase 4 — Intelligence `[x]` COMPLÈTE

| # | Module | Branche | Statut | Tests |
|---|--------|---------|--------|-------|
| M25 | Threat Intelligence — AbuseIPDB, VirusTotal, MISP, cache, TIWorker, API /ti | `main` | `[x]` Mergé | 10 py |
| M26 | Correlation Engine — SameHostLinker, CorrelationWorker, Incidents, API /incidents | `main` | `[x]` Mergé | 9 py |

**Phase 4 Intelligence COMPLÈTE — M25 + M26 livrés, 215 tests verts.**

---

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
| Tests Python (unit + integration + scenarios) | **466/466** | 100% | ✅ |
| Tests Go | **133 tests + 25 config / 21 packages** | 100% | ✅ |
| ruff (server/oseye) | **0 erreur** | 0 | ✅ |
| mypy (rule_engine, workers, api, main — 23 fichiers) | **0 erreur** | 0 | ✅ |
| golangci-lint (agent) | **0 erreur** | 0 | ✅ |
| go build ./... | **0 erreur** | 0 | ✅ |
| go vet ./... | **0 erreur** | 0 | ✅ |
| go test -race ./... | **0 race** | 0 | ✅ |

_Dernière vérification : 2026-08-12._

### Répartition tests Python

| Répertoire | Tests | Ce qui est testé |
|------------|-------|-----------------|
| `tests/unit/` | 214 | Composants isolés (bus, schema, storage, API×3, ingest, normalizer×2, workers, rule_engine, ml_engine) |
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

## Audit code — Full Audit OSEye (2026-08-08)

Audit complet tous modules (Go agent + Python server + Règles YAML) — 80 findings identifiés.
**26 CRITICAL/HIGH confirmés → 26 corrigés. 48 MEDIUM/LOW identifiés (correction sprint suivant).**

### Findings CRITICAL/HIGH résolus

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| GO-001 | CRITICAL | `agent/ebpf/loader.go:129` | Send on closed channel — panic dans ReadEvents goroutines → errgroup + context cancel |
| F1/SEC-001/F-01/F-02 | CRITICAL | `rule_engine/evaluator.py` | RCE via 4 vecteurs sandbox eval — `_check_ast` bloque `_*`, `_SafeCallable`, `_Event.__getattribute__` |
| RULE-001 | CRITICAL | `rules/builtin/credential_access.yaml` + 4 fichiers | Types invalides `read`/`write` → 8 règles silencieuses → remplacés par `open/access`/`modify/close_write` |
| RULE-002 | CRITICAL | `rules/builtin/defense_evasion.yaml:88` | `rule_rootkit_detection` logique UID inversée (`uid != 0` → `uid == 0`) |
| RULE-003 | CRITICAL | `rules/builtin/privilege_escalation.yaml:71` | `rule_ptrace_injection` type `ptrace` jamais émis → réécriture sur syscall + patterns exec |
| F2/SEC-003 | HIGH | `api/routers/auth.py:34` | Credentials hardcodés `admin123/analyst123` → avertissement CRITICAL au démarrage si valeurs faibles |
| SEC-006 | HIGH | `api/routers/auth.py:92` | Pas de rate limiting sur `/refresh` → 10 req/min par IP |
| SEC-002 | HIGH | `api/routers/api_keys.py:21` | Pas de validation des rôles à la création → allowlist `{analyst, admin}` |
| F4 | HIGH | `storage/repositories/api_keys.py:17` | SHA-256 sans sel pour les API keys → HMAC-SHA256 avec pepper serveur |
| SEC-004 | HIGH | `api/ws/alerts.py:18` | JWT exposé en query string (logs uvicorn) → authentification par premier frame WebSocket |
| SEC-005 | HIGH | `api/ws/alerts.py:28` | Pas de vérification de rôle sur WebSocket → close 4003 si rôle invalide |
| F-03/SEC-012 | HIGH | `rule_engine/evaluator.py:139` | ReDoS bloque la boucle asyncio → limite 200 chars + détection quantificateurs imbriqués |
| F-04 | HIGH | `workers/rule_worker.py:114` | Erreur publish avorte tous les matches restants → try/except par itération |
| F-05 | HIGH | `rule_engine/evaluator.py:33` | Fuite mémoire `_temporal_windows` avec PIDs éphémères → purge TTL eagerly |
| TI-001 | HIGH | `threat_intel/breaker.py:52` | Race condition HALF_OPEN → multiple probes concurrentes → flag `_half_open_probe_in_flight` |
| TI-002 | HIGH | `threat_intel/client.py:110` | `ti_unavailable=False` sur timeout global → `True` si providers > 0 |
| RULE-005 | HIGH | `rules/builtin/privilege_escalation.yaml:53` | `rule_capabilities_add` UID inversé → filtre uid supprimé |
| RULE-006 | HIGH | `rules/builtin/impact_c2.yaml:98` | `rule_outbound_c2_beaconing` port 8080 spam + exclusion RFC1918 cassée → corrigé |
| RULE-007 | HIGH | `rules/builtin/credential_access.yaml:86` | `rule_ssh_bruteforce` compte toutes connexions → ajout `event.result == 'failed'` |
| RULE-009 | HIGH | `rules/builtin/impact_c2.yaml:56` | `rule_data_destruction` UID inversé sur mkfs → `uid == 0` |
| RULE-010 | HIGH | `rules/builtin/lateral_movement.yaml:47` | Nom trompeur `rule_rsync_exfil` → renommé `rule_rsync_scp_large_transfer` |
| RULE-011 | HIGH | `rules/builtin/lateral_movement.yaml:73` | `rule_nfs_smb_mount_suspicious` UID inversé → filtre supprimé |

### Findings MEDIUM/LOW ouverts (sprint suivant)

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| GO-003 | MEDIUM | `watchdog.go:97` | Memory soft-limit ne réduit jamais le throttle |
| GO-004 | MEDIUM | `fanotify/collector.go:174` | Boucle infinie si `Event_len == 0` |
| GO-005 | MEDIUM | `fanotify/collector.go:135` | Race fd concurrent entre `Start()` et `readLoop()` |
| GO-006 | MEDIUM | `cmd/main.go:39` | `Config.Validate()` jamais appelé — config invalide silencieuse |
| GO-007 | LOW | `policy/client.go:46` | Backoff reconnect jamais réinitialisé après succès |
| GO-008 | LOW | `transport/grpc_client.go:164` | Paramètre `ch *chain.Chain` inutilisé dans `batchSignature` |
| GO-009 | LOW | `auditd/collector.go:121` | `stopCh` jamais recréé — `Start()` no-op après `Stop()` |
| GO-010 | LOW | `procfs/collector.go:49` | Émet tous les processus à chaque scan — volume non borné |
| F5 | MEDIUM | `ingest/grpc_service.py:127` | IndexError/ValueError non capturés dans set comprehension |
| F6 | MEDIUM | `api/routers/auth.py:91` | Rate limiting absent sur `/auth/refresh` (MEDIUM — doublon SEC-006 corrigé) |
| F7 | MEDIUM | `api/auth/jwt.py:44` | JWT sans claims `aud` et `iss` |
| F8 | MEDIUM | `bus/redis_bus.py:32` | Race condition init Redis — connexions leakées |
| F9 | MEDIUM | `bus/redis_bus.py:127` | Suppression topic par substring — fragile |
| F10 | MEDIUM | `threat_intel/providers/virustotal.py:101` | Paramètre `ip`/`hash` interpolé dans URL VT sans validation |
| F11 | LOW | `normalizer/engine.py:22` | `logging` stdlib au lieu de structlog |
| F12 | LOW | `api/routers/incidents.py:36` | `status` param masque l'import `fastapi.status` |
| SEC-007 | MEDIUM | `api/routers/auth.py:50` | Side-channel timing — énumération des usernames |
| SEC-008 | MEDIUM | `api/routers/ti.py:33` | Pas de validation format/longueur sur paramètres lookup TI |
| SEC-009 | MEDIUM | `api/app.py:42` | CORS `allow_methods=["*"]` + `allow_headers=["*"]` trop permissif |
| SEC-010 | MEDIUM | `api/routers/rules.py:101` | `/rules/validate` accessible au rôle analyst — vecteur RCE à privilège bas |
| SEC-011 | MEDIUM | `api/routers/events.py:80` | Pas de contrainte longueur sur filtres string — DoS |
| SEC-013 | LOW | `api/routers/health.py:10` | Health endpoint non authentifié |
| SEC-014 | LOW | `api/auth/jwt.py:34` | HS256 activable via paramètre `secret` — algorithme faible |
| SEC-015 | LOW | `api/auth/jwt.py:55` | Pas de JTI / mécanisme de révocation token |
| F-08 | MEDIUM | `correlation/linkers/same_host.py:28` | SameHostLinker groupe toutes les alertes du même hôte → faux positifs massifs |
| F-09 | MEDIUM | `correlation/linkers/same_host.py:29` | `min_severity=medium` hardcodé, écrase la config CorrelationEngine |
| F-10 | MEDIUM | `workers/ti_worker.py:101` | Échec lookup TI → `ti_score=0 / malicious=False` silencieux |
| F-11 | MEDIUM | `workers/correlation_worker.py:127` | Divergence état incident/alerte si `alert_repo.update` échoue après incident update |
| F-12 | MEDIUM | `main.py:75` | Deux instances RuleEngine — `app.state` expose l'instance périmée |
| F-13 | MEDIUM | `rule_engine/evaluator.py:69` | Évaluation temporelle O(N×M×W) — CPU exhaustion à débit modéré |
| F-14 | LOW | `correlation/linkers/same_host.py:12` | `_SEVERITY_ORDER` dupliqué dans engine.py et same_host.py |
| F-15 | LOW | `correlation/engine.py:95` | `self._linkers[0]._timeframe` lève IndexError si `linkers=[]` |
| TI-003 | MEDIUM | `threat_intel/providers/virustotal.py:123` | Injection path URL VT via `hash_value` non validé |
| TI-004 | MEDIUM | `threat_intel/providers/misp.py:20` | URL MISP interne loguée en clair au niveau WARNING |
| TI-005 | LOW | `threat_intel/client.py:165` | IPs privées/loopback soumises aux providers TI externes |
| TI-006 | LOW | `storage/repositories/incidents.py:190` | Comparaison temporelle par chaîne ISO — risque divergence TZ |
| RULE-012 | MEDIUM | `defense_evasion.yaml:46` | `rule_timestomp` : uid != 0 + `process_name == 'touch'` trop large |
| RULE-013 | MEDIUM | `privilege_escalation.yaml:91` | `rule_polkit_abuse` : `ppid != 1` déclenche sur tous les pkexec légitimes |
| RULE-014 | MEDIUM | `lateral_movement.yaml:1` | `rule_ssh_lateral` : alerte sur chaque connexion SSH interne, pas de seuil |
| RULE-015 | MEDIUM | `lateral_movement.yaml:35` | `rule_port_scan` : threshold 20 TCP/30s sans restriction IPs distinctes |
| RULE-016 | MEDIUM | `persistence.yaml:83` | `rule_ld_preload_abuse` : LD_LIBRARY_PATH — faux positifs venv Python/Conda |
| RULE-017 | MEDIUM | `impact_c2.yaml:11` | `rule_reverse_shell` : `>&` correspond à `2>&1` — faux positifs |
| RULE-018 | MEDIUM | `lateral_movement.yaml:93` | `rule_rdp_tunneling` : `-D` trop large — SSH SOCKS légitime |
| RULE-019 | MEDIUM | `privilege_escalation.yaml:30` | `rule_sudo_abuse` : `bash`/`sh` trop larges |
| RULE-020 | LOW | `discovery.yaml:84` | `rule_sudo_discovery` : tag `privilege_escalation` incorrect pour T1069.001 |
| RULE-021 | LOW | `impact_c2.yaml:33` | `rule_crypto_mining` : `stratum+tcp` dans `executable` — logiquement impossible |
| RULE-022 | LOW | `defense_evasion.yaml:9` | `rule_log_deletion` : pas d'exclusion logrotate |

---

## Audit code — Phase 5 Decision Engine (2026-08-08)

Audit ciblé sur les modules M27/M28. **6 findings confirmés → 6 corrigés.**

### Findings CRITICAL/HIGH résolus

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| P5-F01 | CRITICAL | `decision/engine.py:182` + `workers/decision_worker.py` | Journal BLAKE3 avance `_last_hash` avant persist — si `create()` échoue, chaîne mémoire ≠ DB → `rollback_journal(prev_hash)` appelé en cas d'échec |
| P5-F02 | CRITICAL | `decision/journal.py:28` + `main.py` | Journal non restauré au redémarrage — `_last_hash` repartirait à `0×64` → `get_last_journal_hash()` charge le dernier hash DB au démarrage |
| P5-F03 | HIGH | `decision/human_queue.py:81` + `storage/repositories/decisions.py` | TOCTOU approve/reject concurrent — UPDATE sans `WHERE human_decision IS NULL` → clause atomique ajoutée, seule la première requête gagne |
| P5-F04 | HIGH | `workers/correlation_worker.py:154` | N alertes vers même incident = N décisions ISOLATE — publication `analysis:correlated` uniquement si `incident.alert_count == 1` |

### Findings MEDIUM/LOW résolus

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| P5-F05 | MEDIUM | `storage/repositories/decisions.py:112` | `requires_human=False` ignoré (`if filters.get(...)` falsy) → `is not None` |
| P5-F06 | LOW | `workers/decision_worker.py:127` | `str(None)='None'` contourne guard alert_id → `raw_alert_id is not None` avant `str()` |

---

## Audit code — Full Audit Engines (2026-08-09)

Audit complet tous modules (Rule Engine, ML Engine, Correlation Engine, Normalizer, Go agent, Règles YAML).
**59 findings totaux, 23 CRITICAL/HIGH → 21 confirmés et corrigés.**

### Findings CRITICAL/HIGH résolus

| ID | Sévérité | Fichier | Fix |
|----|----------|---------|-----|
| F-02/SEC-003 | CRITICAL | `rule_engine/engine.py:192` | pickle.load() → JSON atomique dans save/load_temporal_state |
| TI-CRIT-001 | CRITICAL | `threat_intel/providers/abuseipdb.py` + `virustotal.py` | Circuit breaker wrape chaque tentative individuelle, plus le batch |
| RULE-001 | CRITICAL | `rules/builtin/credential_access.yaml:90` | `event.result == "denied"` (était "failed" + auth_result inexistant) |
| GO-001 | CRITICAL | `agent/ebpf/loader.go:234` | guard `< 292` → `< 296` (off-by-4 parseExecve) |
| F-01 | CRITICAL | `rule_engine/evaluator.py:60` | `record_event_for_temporal()` accepte entity_key stable en paramètre — règles temporelles fonctionnelles |
| SEC-001/SEC-KEY-001 | HIGH | `storage/repositories/api_keys.py:19` | logger.critical() si OSEYE_SECRET_KEY absent |
| SEC-002/SEC-AUTH-002 | HIGH | `api/routers/auth.py:132` | Refresh re-vérifie _USERS, rôles non réutilisés depuis JWT |
| BUG-001 | HIGH | `ingest/grpc_service.py:127` | try/except ValueError autour du int() |
| BUG-002 | HIGH | `main.py:274` | guard `if __name__ != "__main__"` contre double lifespan |
| GO-002 | HIGH | `agent/fanotify/collector.go:155` | guard bounds + guard Event_len==0 (OOB + infinite loop) |
| GO-003 | HIGH | `agent/inotify/collector.go:224` | end>n avant slice nameBytes |
| GO-004 | HIGH | `agent/ebpf/loader.go:173` | slog.Error() au lieu de `_ = err` silencieux |
| SEC-WS-001 | HIGH | `api/ws/manager.py:22` | Suppression double ws.accept() (DoS ws/alerts) |
| F-03 | HIGH | `workers/storage_writer.py:93` | batch restauré avant log erreur (plus de perte) |
| F-04 | HIGH | `workers/runner.py:61` | RuleWorker câblé dans asyncio.gather |
| TI-HIGH-001 | HIGH | `threat_intel/client.py:132` | ti_unavailable persisté et restauré depuis cache |
| RULE-002 | HIGH | `rules/builtin/privilege_escalation.yaml:15` | rule_suid_execution : conditions per-binary sans filtre -exec global |
| RULE-003 | HIGH | `rules/builtin/privilege_escalation.yaml:71` | event.syscall → event.type == "ptrace" |
| RULE-004 | HIGH | `rules/builtin/lateral_movement.yaml:13` | contains → starts_with pour IPs RFC1918 |
| RULE-005 | HIGH | `rules/builtin/persistence.yaml:30` | uid!=0 supprimé, exclusion package managers |
| RULE-006 | HIGH | `rules/builtin/defense_evasion.yaml:49` | rule_timestomp : uid!=0 supprimé |

### Findings MEDIUM/LOW ouverts (sprint suivant)

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| GO-005 | MEDIUM | `config.go:84` | Validate() jamais appelé |
| GO-006 | MEDIUM | `watchdog.go:145` | uint64 underflow CPU delta |
| GO-007 | MEDIUM | `fanotify/collector.go` | race fd Stop()/readLoop() |
| GO-008 | LOW | `journald/collector.go` | itoa() → strconv.Itoa |
| GO-009 | LOW | `procfs/collector.go` | mutex → atomic |
| BUG-003 | MEDIUM | `api/routers/auth.py:33` | _refresh_rate_store unbounded |
| BUG-004 | MEDIUM | `storage/repositories/incidents.py:152` | N+1 query list() |
| BUG-005 | MEDIUM | `normalizer/adapters/procfs.py` + `auditd.py` | server timestamp au lieu agent timestamp |
| BUG-006 | MEDIUM | `api/routers/decisions.py:177` | sort by string created_at |
| BUG-007 | MEDIUM | `rule_engine/engine.py:185` | load_temporal_state exception handling partiel |
| BUG-008 | MEDIUM | `api/routers/rules.py:77` | accès direct _lock/_rules |
| BUG-009 | MEDIUM | `ingest/grpc_service.py:147` | ensure_future sans error handler |
| BUG-010 | LOW | `normalizer/adapters/netlink.py:51` | empty string au lieu de None pour src_ip/dst_ip |
| BUG-011 | LOW | `workers/storage_writer.py:52` | timer flush ignore stop_event jusqu'au flush |
| SEC-004 | MEDIUM | `threat_intel/ti.py:54` | no format validation ip/hash |
| SEC-DOS-001 | MEDIUM | `api/routers/auth.py:33` | _refresh_rate_store DoS |
| SEC-DOS-002 | MEDIUM | `api/ws/manager.py:17` | WebSocket pool unbounded |
| SEC-RATELIMIT-001 | MEDIUM | `api/app.py:31` | no rate limiting expensive endpoints |
| SEC-JWT-001 | MEDIUM | `api/auth/jwt.py:55` | no JWT revocation |
| SEC-INFO-001 | LOW | `api/routers/rules.py:118` | /validate leaks exception messages |
| SEC-INPUT-001 | LOW | `api/routers/incidents.py:35` | no max_length on filter params |
| F-05 | MEDIUM | `correlation/linkers/same_host.py:50` | severity hardcodée |
| F-06 | MEDIUM | `rule_engine/engine.py:124` | eval exceptions loguées DEBUG |
| F-07 | MEDIUM | `correlation/engine.py:102` | couplage fragile _timeframe linkers[0] |
| TI-MED-001 | MEDIUM | `threat_intel/providers/virustotal.py:101` | path traversal URL |
| TI-MED-002 | MEDIUM | `threat_intel/providers/misp.py:22` | URL MISP loguée WARNING |
| TI-LOW-001 | LOW | `threat_intel/retry.py:36` | retry amplification |
| RULE-007 | MEDIUM | `rules/builtin/defense_evasion.yaml:65` | rule_disable_selinux_apparmor : category=process + resource fichier |
| RULE-008 | MEDIUM | `rules/builtin/discovery.yaml:53` | rule_process_discovery threshold=10 trop élevé |
| RULE-009 | MEDIUM | `rules/builtin/impact_c2.yaml:98` | rule_outbound_c2_beaconing ports C2 liste trop étroite |
| RULE-010 | MEDIUM | `rules/builtin/persistence.yaml:83` | rule_ld_preload_abuse LD_LIBRARY_PATH FP massifs |
| RULE-011 | MEDIUM | `rules/builtin/lateral_movement.yaml:39` | rule_port_scan FP massifs sur trafic TCP légitime |
| RULE-012 | LOW | `rules/builtin/discovery.yaml:88` | rule_sudo_discovery tag MITRE incorrect + pas de threshold |

---

### Audit Phase 4 — ancienne section (2026-08-08)

Audit partiel réalisé sur les modules M25-M26 + corrections auth (F1/F2 ouverts depuis audit Phase 3).
**25 findings confirmés → 25 corrigés** (23 déjà présents dans fix/audit-phase3 + 2 nouveaux).

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| F1 | CRITICAL | `api/routers/auth.py:43` | Comptes `admin1`/`analyst1` hardcodés sans variable d'env — supprimés |
| F2 | HIGH | `api/routers/auth.py:103` | JWT `/auth/refresh` en query parameter → `Body(...)` |

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

## Audit code — Full Audit OSEye 2026-08-12

Audit complet de tous les modules (Go + Python + Règles YAML) — 102 findings bruts identifiés.
**21 CRITICAL/HIGH confirmés après vérification adversariale → 21 corrigés (commits ebe4b17, 5c09c4a, ff494d8).**

Périmètre : Go Core, Go Nouveaux (enrollment, responder), Python Core, Python API, Python Workers, Decision Engine, Forensic, ML/Plugin, ThreatIntel, Règles YAML.

### Findings CRITICAL/HIGH résolus

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| GO-001 | CRITICAL | `commands/client.go` | KillProcess PID=1 non rejeté |
| G-E-01 | CRITICAL | `enrollment/client.go` | Enrollment HTTP clair accepté |
| GO-002 | CRITICAL | `commands/client.go` | QuarantineFile path traversal |
| G-X-01 | CRITICAL | `responder/executor.go` | nft flush chain efface tous les blocages |
| D-01 | CRITICAL | `decision/action_executor.py` | ISOLATE dead code |
| F-01 | CRITICAL | `forensic/case_manager.py` | Notes/preuves forensiques perdues |
| R-02 | CRITICAL | `discovery.yaml` | rule_sensitive_file_discovery uid=0 par défaut |
| GO-003 | HIGH | `commands/client.go` | BlockIP sans validation IP (DoS CIDR) |
| GO-004 | HIGH | `commands/client.go` | RestoreFile paths non validés |
| GO-005 | HIGH | `auditd/collector.go` | decodeComm corrompt les noms hex |
| GO-006 | HIGH | `journald/collector.go` | ErrTooLong tue le collector |
| G-E-04 | HIGH | `enrollment/client.go` | Certificat non validé |
| G-E-02 | HIGH | `enrollment/client.go` | Token dans URL |
| G-E-03 | HIGH | `enrollment/client.go` | Pas de limite taille body |
| G-X-02 | HIGH | `responder/executor.go` | IP non validée avant nft/iptables |
| PC-01 | HIGH | `bus/redis_bus.py` | Race condition connexion Redis |
| PC-04 | HIGH | `storage/repositories/agents.py` | Race condition upsert |
| PC-05 | HIGH | `ingest/validator.py` | Signature Ed25519 bypassée |
| W-02 | HIGH | `rule_engine/engine.py` | I/O synchrone bloque asyncio |
| D-03 | HIGH | `decision/human_queue.py` | approve() sans alerte → KILL_PROCESS jamais émis |
| F-03 | HIGH | `forensic/exporter/html_report.py` | Timeline clés erronées |
| PL-02 | HIGH | `plugin/manager.py` | require_signature=False par défaut |
| R-05 | HIGH | `defense_evasion.yaml` | rule_rootkit_detection sans filtre module |
| D-02 | HIGH | `decision/action_executor.py` | execute_after_approval guard trop large |
| ML-01 | HIGH | `ml_engine/engine.py` | pickle.load sans HMAC (déjà présent avant audit) |
| PL-01 | HIGH | `plugin/sandbox.py` | Sandbox sans isolation réseau/syscall |
| TI-01 | HIGH | `threat_intel/breaker.py` | CancelledError deadlock circuit breaker |
| R-03 | HIGH | `lateral_movement.yaml` | rule_port_scan uid toujours 0 |
| F-02 | HIGH | `forensic/case_manager.py` | TOCTOU mutations |
| PC-05 | HIGH | `ingest/validator.py` | Bypass signature |
| B-01 | HIGH | `api/routers/enrollment.py` | Token enrollment dans URL |
| B-02 | HIGH | `api/routers/enrollment.py` | Pas de rate limit enrollment |

**API Audit (audit-py-api) :** 2 HIGH + 7 MEDIUM + 9 LOW/INFO — 18 findings corrigés.

---

## Audit code — ROADMAP Modules (2026-08-12)

Audit ciblé des modules implémentés dans ROADMAP_REMAINING (Blocs 1-9).
**42 findings bruts — 12 CRITICAL/HIGH confirmés → 12 corrigés (commit 52716de).**

### Findings CRITICAL/HIGH résolus

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| ML-R-03 | CRITICAL | `ml_engine/engine.py` | Clé HMAC défaut publique → pickle RCE |
| ML-R-01 | HIGH | `decision/engine.py` | Double-entraînement anomalie |
| ML-R-02 | HIGH | `ml_engine/classifier.py` | _models dict non borné |
| ML-R-06 | HIGH | `api/routers/alerts.py` | Feedback faux-positifs no-op |
| D-R-01 | HIGH | `decision/engine.py` | NOTIFY jamais produit par risk_matrix |
| D-R-02 | HIGH | `decision/action_executor.py` | Alert sans dst_ip/pid → ISOLATE no-op |
| AG-R-01 | HIGH | `ingest/grpc_service.py` | IDOR ReportActions |
| AG-R-02 | HIGH | `api/routers/response_actions.py` | TOCTOU rollback double-emit |
| AG-R-03 | HIGH | `api/routers/response_actions.py` | KILL_PROCESS rollback silencieux |
| RE-R-01 | HIGH | `workers/rule_worker.py` | purge_stale_windows sans try/except |
| NE-R-01 | HIGH | `decision/action_executor.py` | notifications:pending sans subscriber |
| NE-R-04 | HIGH | `agent/internal/commands/client.go` | quarantineDir sans filepath.Clean |

---

## Audit code — Final Review (2026-08-12)

Audit final complet de tous les modules — 107 findings bruts, 29 CRITICAL/HIGH confirmés après vérification adversariale.
**25 CRITICAL/HIGH corrigés (commit a7da4b1).** 4 findings différés (PL-01 seccomp, ML-01 hard-block, G-N-01 nosec, PC-04 mode enforcé par config).

### Findings CRITICAL/HIGH résolus

| ID | Sévérité | Fichier | Description |
|----|----------|---------|-------------|
| GO-A1 | CRITICAL | `ebpf/loader.go` | `defer closeOut()` dans goroutines eBPF → send-on-closed-channel panic |
| GO-A2 | CRITICAL | `fanotify/collector.go` | readLoop sans WaitGroup → write après close canal |
| GO-A3 | CRITICAL | `inotify/collector.go` | même problème que GO-A2 (readLoop non synchronisé) |
| R-01 | CRITICAL | `rule_engine/{models,parser,engine}.py` | `entity_key` YAML ignoré → toutes les règles temporelles réseau dans un seul bucket |
| D-01 | HIGH | `decision/human_queue.py` | Replay approbation → double KILL_PROCESS (approve() sur décision déjà traitée) |
| D-03 | HIGH | `decision/action_executor.py` | dst_ip envoyé à l'agent sans validation de format |
| D-04 | HIGH | `decision/journal.py` | rollback() accepte prev_hash arbitraire (pas de validation SHA-256) |
| PC-02 | HIGH | `ingest/grpc_service.py` | CN agent injecté dans topic Redis sans validation regex |
| PC-04 | HIGH | `ingest/grpc_service.py` | require_agent_keys mode ajouté (rejet agents sans Ed25519 key) |
| API-02 | HIGH | `api/app.py` | Rate limiting get_remote_address inefficace derrière reverse proxy |
| API-03 | HIGH | `api/auth/jwt.py` | JWT blocklist dans /tmp world-readable → chmod 0600 |
| PL-02 | HIGH | `plugin/sandbox.py` | Plugin lancé via PATH 'python' → sys.executable |
| PL-03 | HIGH | `plugin/manager.py` | TOCTOU verify/copy → verify APRÈS copy (defensive copy) |
| TI-01 | HIGH | `threat_intel/breaker.py` | Circuit breaker _opened_at réinitialisé par échecs concurrents |
| ML-02 | HIGH | `ml_engine/classifier.py` | negative_feedback empoisonne tous les classifieurs (pas filtré par technique) |
| PC-01 | HIGH | `storage/repositories/api_keys.py` | RuntimeError import si OSEYE_SECRET_KEY absent → chargement lazy |
| F-01 | HIGH | `forensic/case_manager.py` | object.__setattr__ bypass Pydantic validation |
| F-04 | HIGH | `forensic/exporter/json_export.py` | JSON export sans redaction de champs sensibles |
| R-02 | MEDIUM→LOW | `defense_evasion.yaml` | rule_timestomp fires on every touch → sevérité réduite, exclusions /tmp |
| R-03 | HIGH | `privilege_escalation.yaml` | event.type "exec" jamais émis → ajout "execve" |
| R-04 | MEDIUM | `impact_c2.yaml` | "stratum+tcp" dans executable → noms de mineurs connus |
| R-05 | MEDIUM | `privilege_escalation.yaml` | sudo contains "-i" trop large → " -i " avec espaces |

### Findings différés (design ou effort élevé)

| ID | Sévérité | Raison |
|----|----------|--------|
| PL-01 | HIGH | Sandbox seccomp — nécessite python-seccomp + libseccomp-dev (TODO documenté dans le code) |
| ML-01 | MEDIUM | HMAC key hard-block mode prod — warning suffit pour l'instant, mode dev fonctionnel |
| G-N-01 | LOW | nosec annotations Go — faux positifs gosec |
| PC-04 enforce | MEDIUM | require_agent_keys ajouté mais False par défaut — activation manuelle en prod |

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
| SEC-AUDIT4-001 | `auth.py` : comptes `admin1`/`analyst1` hardcodés avec `password` non configurable | ✅ Corrigé — supprimés |
| SEC-AUDIT4-002 | `auth.py` `/refresh` : JWT en query parameter → exposé dans les access logs | ✅ Corrigé — Body(...) |
| SEC-FULL-001 | `evaluator.py` : RCE via 4 vecteurs sandbox eval (dunder chain, `__globals__`, MRO walk) | ✅ Corrigé — `_check_ast` + `_SafeCallable` + `_Event.__getattribute__` |
| SEC-FULL-002 | `api/ws/alerts.py` : JWT en query string loggé uvicorn + RBAC absent WS | ✅ Corrigé — first-frame auth + close 4003 |
| SEC-FULL-003 | `api/routers/api_keys.py` : rôles arbitraires assignables à la création | ✅ Corrigé — allowlist |
| SEC-FULL-004 | `storage/repositories/api_keys.py` : SHA-256 sans sel pour API keys | ✅ Corrigé — HMAC-SHA256 |
| SEC-FULL-005 | `auth.py` : credentials `admin123/analyst123` sans avertissement démarrage | ✅ Corrigé — CRITICAL log |
| SEC-FULL-006 | `threat_intel/breaker.py` : race HALF_OPEN — probes concurrentes | ✅ Corrigé — flag atomique |
| SEC-P5-001 | `decision/human_queue.py` : TOCTOU approve/reject — double update concurrent possible | ✅ Corrigé — WHERE human_decision IS NULL atomique |
| SEC-P5-002 | `workers/correlation_worker.py` : flooding décisions — N commandes ISOLATE sur même hôte | ✅ Corrigé — publication unique à la création d'incident |
| SEC-ENG-001 | `rule_engine/engine.py` : pickle.load() pour temporal state — RCE si fichier compromis | ✅ Corrigé — JSON atomique via os.replace |
| SEC-ENG-002 | `threat_intel/providers/abuseipdb.py` + `virustotal.py` : circuit breaker insuffisant — probes individuelles non protégées | ✅ Corrigé — circuit breaker par tentative individuelle |
| SEC-ENG-003 | `storage/repositories/api_keys.py` : OSEYE_SECRET_KEY absent silencieux | ✅ Corrigé — logger.critical() au démarrage |
| SEC-ENG-004 | `api/ws/manager.py` : double ws.accept() — DoS WebSocket /ws/alerts | ✅ Corrigé — suppression double accept |
| SEC-ENG-005 | `api/routers/auth.py:132` : refresh réutilise rôles JWT sans re-vérifier — escalade possible | ✅ Corrigé — re-vérification _USERS |

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
| BUG-029 | `auth.py` : comptes dev `admin1`/`analyst1` actifs en production | 2026-08-08 |
| BUG-030 | `auth.py` `/refresh` : JWT exposé via query parameter dans les logs | 2026-08-08 |
| BUG-031 | `ebpf/loader.go` : send on closed channel → panic agent eBPF (ReadEvents) | 2026-08-08 |
| BUG-032 | `evaluator.py` : RCE via dunder chain + `__globals__` closure + MRO walk | 2026-08-08 |
| BUG-033 | `evaluator.py` : ReDoS bloque event loop asyncio via `_safe_re_match` | 2026-08-08 |
| BUG-034 | `evaluator.py` : fuite mémoire `_temporal_windows` avec PIDs éphémères | 2026-08-08 |
| BUG-035 | `workers/rule_worker.py` : erreur publish avorte tous les matches restants | 2026-08-08 |
| BUG-036 | `threat_intel/client.py` : `ti_unavailable=False` sur timeout global | 2026-08-08 |
| BUG-037 | 8 règles YAML silencieuses — types `read`/`write` jamais émis par aucun collector | 2026-08-08 |
| BUG-038 | `rule_rootkit_detection` + 4 autres règles : logique UID inversée (`!= 0` au lieu de `== 0`) | 2026-08-08 |
| BUG-039 | `rule_ptrace_injection` : type `ptrace` jamais émis — règle morte | 2026-08-08 |
| BUG-040 | `rule_ssh_bruteforce` : compte toutes connexions, pas seulement les échecs | 2026-08-08 |
| BUG-041 | `rule_outbound_c2_beaconing` : exclusion RFC1918 cassée + port 8080 spam | 2026-08-08 |
| BUG-042 | `decision/journal.py` : `_last_hash` non restauré au redémarrage — chaîne BLAKE3 casse après restart | fix/audit-phase5 |
| BUG-043 | `decision/engine.py` : journal avance avant persist — divergence mémoire/DB si `create()` échoue | fix/audit-phase5 |
| BUG-044 | `decision/human_queue.py` : TOCTOU approve/reject concurrent — UPDATE sans `WHERE human_decision IS NULL` | fix/audit-phase5 |
| BUG-045 | `correlation_worker.py` : N alertes → N décisions ISOLATE pour le même incident (flooding) | fix/audit-phase5 |
| BUG-046 | `decisions.py` repo : `requires_human=False` ignoré (`if filters.get(...)` falsy) | fix/audit-phase5 |
| BUG-047 | `decision_worker.py` : `str(None)='None'` contourne le guard `trigger_alert_id` | fix/audit-phase5 |
| BUG-048 | `rule_engine/engine.py` : pickle.load() pour temporal state → RCE potentiel | 2026-08-09 |
| BUG-049 | `threat_intel/providers/abuseipdb.py` + `virustotal.py` : circuit breaker ne wrape pas chaque tentative individuelle | 2026-08-09 |
| BUG-050 | `rules/builtin/credential_access.yaml:90` : `event.result == "failed"` + auth_result inexistant — règle morte | 2026-08-09 |
| BUG-051 | `agent/ebpf/loader.go:234` : guard off-by-4 parseExecve (`< 292` au lieu de `< 296`) — panic possible | 2026-08-09 |
| BUG-052 | `rule_engine/evaluator.py:60` : entity_key instable dans record_event_for_temporal — règles temporelles non fonctionnelles | 2026-08-09 |
| BUG-053 | `storage/repositories/api_keys.py:19` : OSEYE_SECRET_KEY absent silencieux — pas d'avertissement critique | 2026-08-09 |
| BUG-054 | `api/routers/auth.py:132` : refresh réutilise les rôles du JWT sans re-vérifier _USERS | 2026-08-09 |
| BUG-055 | `ingest/grpc_service.py:127` : int() sans try/except ValueError — crash sur payload invalide | 2026-08-09 |
| BUG-056 | `main.py:274` : double lifespan possible si importé comme module | 2026-08-09 |
| BUG-057 | `agent/fanotify/collector.go:155` : OOB + boucle infinie si Event_len==0 | 2026-08-09 |
| BUG-058 | `agent/inotify/collector.go:224` : slice hors-bornes nameBytes si end>n | 2026-08-09 |
| BUG-059 | `agent/ebpf/loader.go:173` : erreur sysfs ignorée silencieusement (`_ = err`) | 2026-08-09 |
| BUG-060 | `api/ws/manager.py:22` : double ws.accept() → DoS WebSocket /ws/alerts | 2026-08-09 |
| BUG-061 | `workers/storage_writer.py:93` : batch perdu avant log d'erreur | 2026-08-09 |
| BUG-062 | `workers/runner.py:61` : RuleWorker non câblé dans asyncio.gather | 2026-08-09 |
| BUG-063 | `threat_intel/client.py:132` : ti_unavailable non persisté — perdu entre redémarrages | 2026-08-09 |
| BUG-064 | `rules/builtin/privilege_escalation.yaml:15` : rule_suid_execution — filtre -exec global trop large | 2026-08-09 |
| BUG-065 | `rules/builtin/privilege_escalation.yaml:71` : event.syscall inexistant — règle ptrace morte | 2026-08-09 |
| BUG-066 | `rules/builtin/lateral_movement.yaml:13` : contains au lieu de starts_with pour IPs RFC1918 | 2026-08-09 |
| BUG-067 | `rules/builtin/persistence.yaml:30` : uid!=0 incorrect — bloque les persistances root | 2026-08-09 |
| BUG-068 | `rules/builtin/defense_evasion.yaml:49` : rule_timestomp uid!=0 — bloque les timestomps root | 2026-08-09 |

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
| DETTE-011 | GO-005 — `config.go` : Validate() jamais appelé | ✅ Corrigé (Load() + hardened 2026-08-12 : 10 validations strictes) |
| DETTE-012 | GO-006 — `watchdog.go:145` : uint64 underflow CPU delta | ✅ Corrigé 2026-08-10 |
| DETTE-013 | GO-007 — fanotify : race fd Stop()/readLoop() | ✅ Corrigé (closeOnce + atomic fd) |
| DETTE-014 | GO-008 — journald : itoa() → strconv.Itoa | ✅ Corrigé 2026-08-10 |
| DETTE-015 | GO-009 — procfs : mutex → atomic.Value pour throttle | ✅ Corrigé 2026-08-10 |
| DETTE-016 | BUG-003 — `auth.py:33` : _refresh_rate_store unbounded | ✅ Corrigé (LRU cap 10 000) |
| DETTE-017 | BUG-004 — `incidents.py:152` : N+1 query list() | ✅ Corrigé 2026-08-10 (batch IN query) |
| DETTE-018 | BUG-005 — procfs+auditd : server timestamp au lieu agent timestamp | ✅ Corrigé (_utils.agent_ts) |
| DETTE-019 | BUG-006 — `decisions.py:177` : sort by string created_at | ✅ Corrigé (ORDER BY colonne ORM) |
| DETTE-020 | BUG-007 — `rule_engine/engine.py:185` : load_temporal_state exception partielle | ✅ Corrigé (except générique avec warning) |
| DETTE-021 | BUG-008 — `routers/rules.py:77` : accès direct _lock/_rules | ✅ Corrigé 2026-08-10 (list_rules() public) |
| DETTE-022 | BUG-009 — `grpc_service.py:147` : ensure_future sans error handler | ✅ Corrigé 2026-08-10 (done callback) |
| DETTE-023 | BUG-010 — `netlink.py:51` : empty string au lieu de None pour src_ip/dst_ip | ✅ Corrigé 2026-08-10 |
| DETTE-024 | BUG-011 — `storage_writer.py:52` : timer flush ignore stop_event | ✅ Corrigé 2026-08-10 |
| DETTE-025 | SEC-004 — `ti.py:54` : no format validation ip/hash | ✅ Corrigé (ipaddress + regex hex) |
| DETTE-026 | SEC-DOS-001 — `auth.py:33` : _refresh_rate_store DoS | ✅ Corrigé (OrderedDict LRU cap 10 000) |
| DETTE-027 | SEC-DOS-002 — `ws/manager.py:17` : WebSocket pool unbounded | ✅ Corrigé (cap 500 global + 5/user) |
| DETTE-028 | SEC-RATELIMIT-001 — endpoints coûteux sans rate limit | ✅ Corrigé 2026-08-10 (events 60/min, exports JSON/HTML/PDF/MISP/TheHive, snapshots) |
| DETTE-029 | SEC-JWT-001 — no JWT revocation | ✅ Corrigé 2026-08-10 (jti blocklist + /logout + token rotation sur refresh) |
| DETTE-030 | SEC-INFO-001 — `routers/rules.py:118` : /validate leaks exception messages | ✅ Corrigé 2026-08-10 (messages génériques) |
| DETTE-031 | SEC-INPUT-001 — `routers/incidents.py:35` : no max_length on filter params | ✅ Corrigé 2026-08-10 (Query max_length) |
| DETTE-032 | F-05 — `correlation/linkers/same_host.py:50` : severity hardcodée | ✅ Corrigé (severity issue _SEVERITY_ORDER) |
| DETTE-033 | F-06 — `rule_engine/engine.py:124` : eval exceptions loguées DEBUG | 🟡 Ouvert (DEBUG intentionnel pour bruit) |
| DETTE-034 | F-07 — `correlation/engine.py:102` : couplage fragile _timeframe linkers[0] | ✅ Corrigé (ValueError si linkers=[]) |
| DETTE-035 | TI-MED-001 — `virustotal.py:101` : path traversal URL | ✅ Corrigé (urllib.parse.quote) |
| DETTE-036 | TI-MED-002 — `misp.py:22` : URL MISP loguée WARNING | ✅ Corrigé 2026-08-10 (URL masquée) |
| DETTE-037 | TI-LOW-001 — `retry.py:36` : retry amplification | ✅ Corrigé (breaker wrape le retry entier) |
| DETTE-038 | RULE-007 — `defense_evasion.yaml:65` : rule_disable_selinux_apparmor condition mixte | ✅ Corrigé 2026-08-10 |
| DETTE-039 | RULE-008 — `discovery.yaml:53` : rule_process_discovery threshold=10 trop élevé | ✅ Corrigé 2026-08-10 (→ 3) |
| DETTE-040 | RULE-009 — `impact_c2.yaml:98` : rule_outbound_c2_beaconing ports trop étroits | ✅ Corrigé 2026-08-10 (+8443/8080/2222/31337) |
| DETTE-041 | RULE-010 — `persistence.yaml:83` : rule_ld_preload_abuse FP venv/Conda | ✅ Corrigé 2026-08-10 (exclusions + LD_LIBRARY_PATH retiré) |
| DETTE-042 | RULE-011 — `lateral_movement.yaml:39` : rule_port_scan FP trafic TCP | ✅ Corrigé 2026-08-10 (uid!=0 + threshold 100) |
| DETTE-043 | RULE-012 — `discovery.yaml:88` : rule_sudo_discovery tag incorrect + pas de threshold | ✅ Corrigé 2026-08-10 |

**8/11 dettes résolues (+ 33 nouvelles dettes identifiées audit 2026-08-09).**

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

## Bloc 7 + Bloc 9 `[x]` — 2026-08-11

**Bloc 7 — Enrollment automatique agent Go**
- `OSEYE_ENROLL_URL` + `OSEYE_ENROLL_TOKEN` dans la config
- `agent/internal/enrollment/client.go` : `NeedsEnrollment()` + `Enroll()` — CSR RSA 2048, GET CA cert, POST CSR, écriture atomique des fichiers
- Appelé dans `main.go` avant l'init gRPC, non-fatal si échoue (buffer-only mode)
- Idempotent : no-op si `TLSCertFile` existe déjà

**Bloc 9 — Tests manquants**
- `agent/internal/responder/dedup_test.go` — 5 tests Deduplicator (TTL, cibles différentes, types différents)
- `agent/internal/responder/executor_test.go` — QuarantineFile, RestoreFile, KillProcess PID guard
- `agent/internal/enrollment/client_test.go` — 4 tests (no-op sans token, cert existant, succès complet, idempotence)
- `server/tests/unit/test_api_agents.py` — list agents, list blocked, block/unblock, RBAC analyst/admin
- `server/tests/unit/test_decision_ml_integration.py` — ml_score > 0 quand ml_engine câblé, = 0 sinon

---

## Hardening Config Agent + CLI `oseye-config` `[x]` — 2026-08-12

Renforcement complet de la validation de configuration de l'agent Go et création d'un outil CLI de gestion de configuration.

**`agent/internal/config/config.go` — 10 validations ajoutées :**

| Validation | Avant | Après |
|---|---|---|
| GRPCAddr port | Acceptait `localhost:abc` | Port numérique [1, 65535] requis |
| SyslogAddr | Non validé | Même validation host:port |
| MaxCPUPct | Acceptait > 100 | Borné [0, 100] |
| MaxMemMB | Acceptait 0 / négatif | Doit être > 0 |
| BatchSize | Illimité | Borné [1, 100 000] |
| AgentID | Aucun format vérifié | UUID v4 strict (si non-vide) |
| Paths TLS/Buffer | Relatifs acceptés | Absolus obligatoires |
| QuarantineDir | Non validé | Absolu + rejet paths critiques (`/`, `/bin`…) |
| FanotifyPaths | Relatifs acceptés | Absolus obligatoires |
| EnrollServerURL | Non validé | URL valide http/https avec host |
| Parsing numériques | Fallback silencieux sur valeurs invalides | Erreur explicite si env var set mais non-parseable |

**`agent/cmd/oseye-config/main.go` — nouvel outil CLI :**

| Commande | Description |
|---|---|
| `oseye-config show` | Affiche la config effective (secrets masqués) |
| `oseye-config validate` | Valide et retourne OK ou l'erreur |
| `oseye-config get <KEY>` | Lit une valeur (refuse les clés sensibles) |
| `oseye-config set KEY=VAL` | Écriture atomique + dry-run validation |
| `oseye-config unset <KEY>` | Supprime une clé du env file |
| `oseye-config check-files` | Vérifie existence certs/clés/répertoires |

**Sécurité CLI :**
- Écriture atomique (temp + fsync + rename) — pas de corruption sur crash
- File locking (`flock` LOCK_EX) — pas de race sur writes concurrents
- Rejet des newlines dans les valeurs (anti-injection)
- Permissions 0600 sur le fichier env
- Secrets masqués dans tous les outputs (show, set, get refuse les clés sensibles)

**Tests :** 25 tests unitaires config (dont edge cases : port hors range, UUID invalide, paths relatifs, BatchSize > max, QuarantineDir = `/`, EnrollURL invalide).

---

## Gaps fonctionnels résolus `[x]` — 2026-08-11

**Bloc 1 — Câblage ML (CRITIQUE)**
- `ml_engine` passé à `DecisionEngine` → `ml_score` réel dans toutes les décisions
- `event_repo` passé à `DecisionWorker` → `trigger_event` disponible pour le scoring
- `ml_engine` passé à `RuleWorker` → `learn_from_alert()` appelé sur chaque alerte confirmée

**Bloc 2 — Feedback faux positifs**
- `POST /alerts/{id}/false-positive` appelle `ml_engine.learn_from_alert(event, [])` → update négatif sur le classifieur MITRE

**Bloc 3 — Consommation `analysis:ml`**
- `MLWorker._process()` appelle `event_repo.update_ml_score()` après chaque scoring
- `SQLEventRepository.update_ml_score()` ajouté

**Bloc 4 — Tâches périodiques**
- `CorrelationWorker` : boucle `_stale_incidents_loop()` toutes les 5 min → `close_stale_incidents()`

**Bloc 5 — Table agents + API + UI**
- Table `AgentRow` (cn, online, first_seen, last_seen, version, active_profile, ip_address)
- `SQLAgentRepository` (upsert, set_offline, list, get)
- `IngestEvents` gRPC : upsert à la connexion, set_offline à la déconnexion
- `GET /api/v1/agents` et `GET /api/v1/agents/{cn}` (analyst+)
- Page UI `Agents.tsx` dans la sidebar Surveillance

**Bloc 6 — Poids WeightedScorer configurables**
- 4 settings : `OSEYE_DECISION_WEIGHT_RULE/ML/TI/DEPTH` (défauts 0.4/0.3/0.2/0.1)
- `WeightedScorer.__init__` accepte les 4 poids en paramètres

**Bloc 8 — Action NOTIFY**
- `ActionExecutor._emit_notification()` publie sur `notifications:pending`
- Consommable par les plugins `ExporterPlugin` via IPC socket

---

## Corrections API Keys `[x]` — 2026-08-11

- **Révocation** : `DELETE /api/v1/api-keys/{id}` → `revoked=True` en base (persisté), la ligne reste pour l'audit
- **Clé révoquée inutilisable** : `verify()` retourne `None` si `revoked=True` ou ligne absente → 401
- **`list()`** : filtre `WHERE revoked=false` par défaut ; `include_revoked=true` pour afficher toutes
- **UI** : case "Afficher les révoquées" — lignes révoquées en `opacity-50`, badge "Révoquée", sans bouton action
- **Compteur** : `X actives · Y révoquées` dans le toolbar
- **`expires_at`** : masqué sur les révoquées (sans objet), stocké en `YYYY-MM-DD` dans le state (plus de conversion prématurée en ISO)
- **Création** : ajout direct au state local sans rechargement (évite les doublons)

---

## Refonte UI complète `[x]` — 2026-08-11

**Primitives :** `Badge`, `Button`, `EmptyState`, `Spinner`, `Input`, `Select` dans `components/ui/`. `lucide-react` installé. `useD3.ts` supprimé (code mort). Source unique des couleurs sévérité (`lib/severityColors.ts`).

**Layout :** Sidebar avec icônes Lucide, sections Surveillance/Réponse/Config/Admin, repliable (`w-52` ↔ `w-12`), badge alertes sur icône en mode replié. Header avec `Wifi`/`Sun`/`Moon`/`LogOut` Lucide. WebSocket déplacé dans AppShell (persistant sur toutes les pages).

**Pages refaites :** Login, Events, Alerts, Incidents, IncidentDetail, Cases, Decisions, Rules, NetworkGraph, Dashboard — 0 emoji, EmptyState avec icône, hover lignes corrigé, Spinner.

**Sub-composants extraits :** `decisions/` (PendingCard, DecisionRow, ScoreBar, CountdownBadge), `cases/NewCaseModal`, `rules/RuleDetail`, `CaseTimeline` (dot aligné + sévérité).

**Auth RBAC UI :** `authStore` décode les rôles JWT (exclus localStorage). `ProtectedRoute` accepte `requiredRole="admin"`. Sidebar section Admin conditionnelle. Boutons admin-only (Reload règles, Approuver/Rejeter décisions) conditionnels.

**Pages admin :** API Keys (création + bannière clé brute + copy clipboard), Plugins (upload .py, badge signature), Policies (détails collecteurs déroulables), Response Actions (rollback).

---

## Response Engine `[x]` — 2026-08-11

Actions de réponse autonomes sur les agents (act-then-notify) intégrées dans le `DecisionEngine` existant.

**Proto :** `AgentCommand` étendu (`command_id`, nouveaux types `BLOCK_IP/UNBLOCK_IP/QUARANTINE_FILE/RESTORE_FILE/KILL_PROCESS`). Nouveau message `ActionReport` + RPC `ReportActions`.

**Agent Go — `internal/responder/` :**
- `state.go` — table SQLite `active_actions`, persistance avant exécution
- `dedup.go` — déduplication par cible (60s TTL)
- `executor.go` — détection nftables/iptables runtime, `BlockIP/UnblockIP`, `QuarantineFile/RestoreFile`, `KillProcess` avec vérification `/proc/{pid}/comm` (anti-PID-reuse)
- `reporter.go` — stream `ReportActions` avec full-jitter backoff

**Serveur Python :**
- `action_executor.py` corrigé — publie sur `commands:{cn}` (plus `policy:push:`), `execute_after_approval()` pour kill post-approbation
- `human_queue.py` — envoie commande à l'agent après approbation humaine
- Table `response_actions` + repository + router `GET/POST rollback /api/v1/response-actions`

---

## Corrections sécurité CIA `[x]` COMPLÈTES — 2026-08-11

Audit complet des communications serveur ↔ agent. 5 findings corrigés.

| Finding | Sévérité | Statut | Description |
|---------|----------|--------|-------------|
| F-1+F-3 | CRITIQUE | `[x]` | Vérification Ed25519 désactivée en prod + mauvaise clé utilisée → séparation `OSEYE_ED25519_SIGNING_KEY` + chargement `.pub` au démarrage + dict thread-safe avec `threading.Lock` |
| F-2 | ÉLEVÉE | `[x]` | mTLS dégradé si `ca.crt` absent → `RuntimeError` au démarrage (sauf `OSEYE_GRPC_INSECURE_DEV=true`) ; `require_client_auth=True` toujours actif |
| F-5 | MOYENNE | `[x]` | Thundering herd → nouveau package `agent/internal/backoff` avec full-jitter `[0, min(delay*2, max)]` appliqué aux 3 clients Go (grpc, policy, commands) |
| F-6 | MOYENNE | `[x]` | Aucune révocation sélective → table `blocked_agents` + `AgentServiceServicer._blocked_cns` thread-safe + endpoint admin `DELETE /api/v1/agents/{cn}` avec persistance DB et effet immédiat |
| F-4 | MOYENNE | `[x]` | Version TLS non contrainte côté serveur → `GRPC_SSL_CIPHER_SUITES` forcé TLS 1.3 uniquement |

**Fichiers modifiés :**
- `agent/internal/config/config.go` — ajout `Ed25519KeyFile`
- `agent/cmd/oseye-agent/main.go` — utilise `Ed25519KeyFile` pour le signer
- `agent/internal/backoff/backoff.go` — nouveau package full-jitter
- `agent/internal/transport/grpc_client.go`, `policy/client.go`, `commands/client.go` — backoff.Next
- `server/oseye/config.py` — `agent_keys_dir`, `grpc_insecure_dev`, `default_surveillance_profile`
- `server/oseye/ingest/grpc_service.py` — locks thread-safe, blocklist, `_require_cn` avec révocation
- `server/oseye/ingest/server.py` — mTLS strict, retourne `(server, servicer)`, TLS 1.3
- `server/oseye/storage/models.py` — table `blocked_agents`
- `server/oseye/storage/repositories/blocked_agents.py` — nouveau
- `server/oseye/api/routers/agents.py` — nouveau (block/unblock/list)
- `server/oseye/main.py` — câblage complet (clés, blocklist, servicer sur app.state)

---

## Historique des commits (récents)

| Hash | Message | Date |
|------|---------|------|
| `a7da4b1` | fix(audit-final): corriger 25 findings CRITICAL/HIGH — panics Go, RuleEngine, Auth, Plugin, Decision | 2026-08-12 |
| `ce92886` | fix(audit-medium): corriger findings MEDIUM/LOW — workers, decision, storage, Go | 2026-08-12 |
| `ca31c42` | docs: mise à jour PROGRESS.md et ROADMAP_REMAINING — audits 2026-08-12 + 466 tests | 2026-08-12 |
| `52716de` | fix(audit-roadmap): corriger 12 findings CRITICAL/HIGH — ML+Decision+NOTIFY+GRPC+Rollback | 2026-08-12 |
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
