# OSEye — Suivi de progression

**Version :** 2.6
**Dernière mise à jour :** 2026-08-08
**Branche active :** `main` (`latest`)
**Phase courante :** Phase 5 — Decision Engine `[x]` COMPLÈTE

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

**Phase 5 Decision Engine COMPLÈTE — 251 tests verts.**

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
| Tests Python (unit + integration + scenarios) | **251/251** | 100% | ✅ |
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
