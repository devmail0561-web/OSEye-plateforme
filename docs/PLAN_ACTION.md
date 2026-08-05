# OSEye — Plan d'action de développement

**Version:** 1.0  
**Date:** 2026-07-28  
**Basé sur:** ARCHITECTURE.md v1.1  
**Classification:** Confidentiel — usage interne

---

## Lecture du plan

Chaque tâche est identifiée par un code `Pn.m` (Phase n, tâche m).  
**Statuts :** `[ ]` à faire · `[~]` en cours · `[x]` terminé  
**Dépendances :** une tâche ne commence pas tant que ses dépendances ne sont pas `[x]`.  
**Priorité critique** : les tâches marquées ⚠ bloquent tout le reste si non faites en premier.  
**Assignation** : `[@nom]` — développeur assigné à la tâche.

---

## Workflow collaboratif

### Contribuer au projet

1. **Choisir une tâche disponible** — lire `CONTRIBUTING.md` pour les règles de contribution
2. **S'assigner la tâche** — marquer `[~] [@votre_nom]` dans ce fichier (commit sur `main` ou commentaire GitHub Issue)
3. **Créer une branche** — `git checkout -b P<n>.<m>-<description-courte>`
4. **Implémenter selon les specs** — référence : `ARCHITECTURE.md` + fichiers contrats (Annexe)
5. **Écrire les tests** — couverture > 80% obligatoire
6. **Ouvrir une Pull Request** — template automatique avec checklist de vérification
7. **Code review** — 1 approbation senior obligatoire avant merge
8. **CI passe** — lint + tests + build sur les 3 OS
9. **Merge** — marquer `[x]` dans ce fichier

### Tâches parallélisables

Les tâches **au sein d'une même phase** peuvent être faites en parallèle SI aucune dépendance mutuelle. Exemples :

**Phase 2 :** P2.01 à P2.06 (6 nouveaux collectors) → **6 personnes en parallèle**  
**Phase 3 :** P3.07 (ruleset 30 règles) → **diviser en 6 catégories × 5 règles = 6 branches**  
**Phase 9 :** P9.05 à P9.12 (8 pages UI) → **8 personnes en parallèle**

⚠ **Phase 1 (P1.01–P1.11)** est **séquentielle** — les fichiers contrats doivent être finalisés par une seule personne ou en pair programming.

### Code review — niveaux de sévérité

| Niveau | Bloque le merge ? | Exemples |
|--------|------------------|----------|
| **BLOCKER** | ✅ Oui | Faille sécurité, fuite mémoire, perte de données, violation interface contrat |
| **CRITICAL** | ✅ Oui | Bug fonctionnel majeur, test manquant, perf inacceptable (agent > 4% CPU) |
| **MAJOR** | ❌ Non (fixable post-merge) | Code smell, duplication, manque de logs, doc absente |
| **MINOR** | ❌ Non | Typo, style, suggestion d'amélioration |

### Critères d'acceptance génériques (toutes tâches)

- [ ] Code compile/lance sans erreur
- [ ] Tests unitaires présents, couverture > 80%
- [ ] Pas de `TODO` ou `FIXME` non justifié en commentaire
- [ ] Logs structurés JSON avec trace_id (si applicable)
- [ ] Aucune dépendance externe non documentée dans `go.mod` / `pyproject.toml`
- [ ] Respect des interfaces définies dans les fichiers contrats
- [ ] CI GitHub Actions passe (lint + tests + build multi-OS)

---

## Phase 1 — Foundation `S1–S3`

> **Objectif :** Pipeline end-to-end fonctionnel : agent → server → stockage → query API.

### 1.0 — Fichiers contrats ⚠ (bloque tout)

Ces fichiers doivent être finalisés et reviewés **avant d'écrire le moindre code fonctionnel**.

- [ ] **P1.01** — `proto/event.proto` : définir `UniversalEventPB`, `IngestRequest`, `IngestResponse`, service `AgentService` (IngestEvents + ReceivePolicy + StreamCommands)
- [ ] **P1.02** — `server/oseye/core/schema.py` : modèles Pydantic `UniversalEvent`, `Alert`, `Decision`, `ForensicCase`, `Rule`, `SurveillanceProfile`, `EntityProfile`
- [ ] **P1.03** — `server/oseye/bus/interface.py` : Protocol `EventBus` (publish, subscribe, subscribe_pattern)
- [ ] **P1.04** — `agent/internal/platform/interface.go` : interface `PlatformDriver` + `PlatformCapabilities`
- [ ] **P1.05** — `agent/internal/platform/registry.go` : registre auto-enregistrement
- [ ] **P1.06** — `agent/internal/collector/interface.go` : interface `Collector` + struct `RawEvent`
- [ ] **P1.07** — `server/oseye/storage/interface.py` : Protocols `EventRepository`, `AlertRepository`, `DecisionRepository`
- [ ] **P1.08** — `server/oseye/storage/router.py` : `StorageRouter` (routage PG vs ClickHouse)
- [ ] **P1.09** — `server/oseye/config.py` : `Settings` pydantic-settings, toutes les variables d'env
- [ ] **P1.10** — `server/oseye/core/observability.py` : setup OTel + logger JSON structuré
- [ ] **P1.11** — Codegen Protobuf : `scripts/generate_proto.sh` (génère Go + Python depuis `proto/`)

### 1.1 — Infrastructure monorepo

- [ ] **P1.12** — Scaffolding monorepo : `agent/`, `server/`, `sdk/`, `ui/`, `proto/`, `rules/`, `infra/`, `scripts/`
- [ ] **P1.13** — `agent/go.mod` + `server/pyproject.toml` + `ui/package.json` initialisés
- [ ] **P1.14** — `.github/workflows/ci.yml` : lint + test + build, matrix `GOOS: [linux, windows, darwin]`
- [ ] **P1.15** — `infra/docker/docker-compose.dev.yml` (Redis + PostgreSQL + oseye-server + oseye-agent + oseye-ui)
- [ ] **P1.16** — `scripts/generate_certs.sh` : PKI dev (CA + server.crt + agent.crt)

### 1.2 — Agent Go (Linux — collecte minimale)

*Dépend de : P1.01–P1.06*

- [ ] **P1.17** — `platform/linux/driver.go` : `LinuxDriver` implémentant `PlatformDriver`, `init()` auto-register
- [ ] **P1.18** — `platform/linux/ebpf/loader.go` + programmes C : `execve.c`, `openat.c`, `connect.c`
- [ ] **P1.19** — `platform/linux/auditd/` : collecteur auditd (parsing `audit.log`)
- [ ] **P1.20** — `platform/linux/procfs/` : collecteur procfs (scan `/proc`)
- [ ] **P1.21** — `internal/chain/hasher.go` : BLAKE3 hash chain per-event
- [ ] **P1.22** — `internal/buffer/sqlite_buffer.go` : queue offline SQLite avec cursor `last_sent_id`
- [ ] **P1.23** — `internal/transport/grpc_client.go` : streaming gRPC + reconnexion automatique + backpressure
- [ ] **P1.24** — `internal/signer/ed25519.go` : signature de batch (toutes les 1000 events ou 1s)
- [ ] **P1.25** — `cmd/oseye-agent/main.go` : bootstrap — `platform.Resolve()` → `CollectorManager` → pipeline

### 1.3 — Server Python (ingestion + normalisation)

*Dépend de : P1.01–P1.11*

- [ ] **P1.26** — `bus/memory.py` : `InMemoryBus` (tests unitaires)
- [ ] **P1.27** — `bus/redis_streams.py` : `RedisBus` (multi-process dev)
- [ ] **P1.28** — `ingest/grpc_service.py` : réception gRPC, vérification CN mTLS = agent_id, validation signature batch
- [ ] **P1.29** — `ingest/validator.py` : vérification hash chain + signature Ed25519
- [ ] **P1.30** — `normalizer/engine.py` : `NormalizerEngine` + dispatch par `raw.OS` + `raw.source`
- [ ] **P1.31** — `normalizer/adapters/linux/ebpf.py` + `auditd.py` + `procfs.py`
- [ ] **P1.32** — `normalizer/secret_masker.py` : regex masking credentials dans cmdline/resource

### 1.4 — Stockage

*Dépend de : P1.07, P1.08, P1.09*

- [ ] **P1.33** — Alembic init + migration V001 : toutes les tables PostgreSQL (events, alerts, decisions, forensic_cases, agents, rules, entity_profiles, ti_cache_ip, ti_cache_hash, ti_ioc_feed, api_audit_log, organizations, rule_versions, dlq_entries)
- [ ] **P1.34** — `storage/backends/postgresql.py` : implémente les Protocols Repository
- [ ] **P1.35** — `storage/backends/sqlite.py` : même interface, substitutions de types
- [ ] **P1.36** — `storage/repositories/event_repo.py` : `insert_batch`, `get`, `query` avec filtres

### 1.5 — API REST + Auth

*Dépend de : P1.33–P1.36*

- [ ] **P1.37** — `api/auth/jwt.py` : issue/verify/refresh JWT RS256
- [ ] **P1.38** — `api/auth/rbac.py` : dépendances FastAPI pour les 4 rôles (reader, analyst, senior_analyst, admin)
- [ ] **P1.39** — `api/routers/events.py` : `GET /events`, `GET /events/{id}`, `GET /events/stats`
- [ ] **P1.40** — `api/routers/auth.py` : `POST /auth/token`, `/refresh`, `/logout`, `/me`
- [ ] **P1.41** — `api/routers/health.py` : `GET /health`, `GET /health/detailed`
- [ ] **P1.42** — `api/ws/manager.py` : `WebSocketManager` + endpoint `WS /ws/events`
- [ ] **P1.43** — `audit/middleware.py` : FastAPI middleware loggant chaque requête dans `api_audit_log`

### 1.6 — Workers dev (mode monolithe)

*Dépend de : P1.26–P1.32, P1.33–P1.36*

- [ ] **P1.44** — `workers/` : stubs des 5 workers + `core/runner.py` mode monolithe (`asyncio.gather`)
- [ ] **P1.45** — `workers/storage_writer.py` : consomme `events:normalized`, appelle `StorageRouter.insert_events`

### 1.7 — Tests Phase 1

- [ ] **P1.46** — Tests unitaires : hash chain BLAKE3, signature Ed25519, buffer SQLite (Go)
- [ ] **P1.47** — Tests unitaires : NormalizerEngine, adapters eBPF + auditd (Python)
- [ ] **P1.48** — Test d'intégration : agent → server gRPC → normalizer → PostgreSQL → `GET /events` retourne l'event
- [ ] **P1.49** — Test WebSocket : event inséré → reçu sur `WS /ws/events` en < 1s

**Livrable P1 :** Events réels de la machine hôte visibles en DB et streamés via WebSocket.

---

## Phase 2 — Full Collection `S4–S6`

> **Objectif :** 9 collectors Linux opérationnels. Agent robuste face aux pannes réseau.

*Dépend de : Phase 1 complète*

- [ ] **P2.01** — `platform/linux/fanotify/` : collecteur fanotify (accès fichiers système)
- [ ] **P2.02** — `platform/linux/inotify/` : collecteur inotify (watch paths configurables)
- [ ] **P2.03** — `platform/linux/netlink/` : collecteur netlink (connexions réseau kernel)
- [ ] **P2.04** — `platform/linux/journald/` : collecteur journald (systemd logs)
- [ ] **P2.05** — `platform/linux/udev/` : collecteur udev (events devices)
- [ ] **P2.06** — `platform/linux/syslog/` : collecteur syslog (`/dev/log` ou UDP 514)
- [ ] **P2.07** — Adapters normalizer correspondants : fanotify, inotify, netlink, journald, udev, syslog
- [ ] **P2.08** — `internal/watchdog/resource.go` : CPU/mem self-monitoring, throttle adaptatif si CPU >4%
- [ ] **P2.09** — `ingest/backpressure.py` : `BackpressureController` — calcule facteur throttle depuis lag bus, push aux agents via `StreamCommands` gRPC toutes les 10s
- [ ] **P2.10** — Buffer offline : replay automatique depuis `last_sent_id` après reconnexion + cleanup post-ACK
- [ ] **P2.11** — `api/routers/agents.py` : `GET /agents`, `GET /agents/{id}`, `GET /agents/{id}/status`, `POST /agents/enroll`, `POST /agents/{id}/renew-cert`
- [ ] **P2.12** — `scripts/generate_certs.sh` : enrollment OTP agent (génère OTP, valide CSR, signe avec intermediate CA)
- [ ] **P2.13** — DaemonSet K8s dev : déploiement sur cluster de test local
- [ ] **P2.14** — Tests : mocks kernel pour chacun des 6 nouveaux collectors, couverture > 80%
- [ ] **P2.15** — Test de résilience : déconnexion réseau 60s → reconnexion → vérifier replay sans perte d'events

**Livrable P2 :** 9 collectors actifs. L'agent survit à 60s de coupure réseau et rejoue les events bufferisés.

---

## Phase 3 — Détection `S7–S9`

> **Objectif :** Règles déclenchées, alertes créées, visibles par les analystes.

*Dépend de : Phase 2 complète*

- [ ] **P3.01** — `rule_engine/parser.py` : lecture YAML/TOML depuis `rules/builtin/` et `rules/custom/`
- [ ] **P3.02** — `rule_engine/evaluator.py` : évaluateur `asteval` — comparaisons, chaînes, regex, `in`, booléens
- [ ] **P3.03** — `rule_engine/evaluator.py` : support `count_events(filter, seconds)` avec fenêtres temporelles en mémoire
- [ ] **P3.04** — `rule_engine/engine.py` : `RuleEngine.evaluate()` + hot-reload via watchdog fichiers
- [ ] **P3.05** — `workers/rule_worker.py` : consomme `events:normalized`, publie `analysis:rules:{host}`
- [ ] **P3.06** — `storage/repositories/alert_repo.py` : CRUD alertes
- [ ] **P3.07** — Ruleset intégré : 30+ règles YAML dans `rules/builtin/` couvrant les techniques MITRE principales

| Catégorie | Règles minimum |
|-----------|---------------|
| Credential access | shadow_read, passwd_write, ssh_key_theft, dumping_memory |
| Privilege escalation | suid_execution, sudo_abuse, capabilities_add, ptrace_inject |
| Persistence | crontab_write, rc_local_modify, systemd_unit_new, bashrc_write |
| Defense evasion | log_delete, history_clear, binary_rename, timestamp_tamper |
| Lateral movement | ssh_new_host, scp_exfil, port_scan_internal |
| Discovery | whoami_burst, network_scan, shadow_read_burst |
| C2 / Exfiltration | dns_burst, large_upload, reverse_shell_port |
| Ransomware | mass_rename_extension, mass_encryption_pattern |
| Windows | registry_run_key, lsass_access, wmi_exec, powershell_encoded |
| macOS | launchd_new, tcc_bypass, dylib_hijack |

- [ ] **P3.08** — Condition `event.platform` dans l'évaluateur : règles cross-OS fonctionnelles
- [ ] **P3.09** — `api/routers/alerts.py` : `GET /alerts`, `GET /alerts/{id}`, `PATCH`, `POST .../acknowledge`, `POST .../false-positive`, `GET /alerts/stats`
- [ ] **P3.10** — `api/routers/rules.py` : CRUD complet + `POST /rules/validate` + `POST /rules/reload`
- [ ] **P3.11** — `api/ws/manager.py` : broadcast sur `WS /ws/alerts`
- [ ] **P3.12** — `api/auth/api_keys.py` : génération / révocation clés API, header `X-API-Key`
- [ ] **P3.13** — RBAC enforced sur tous les endpoints existants
- [ ] **P3.14** — Boucle feedback faux positifs → `rules.false_positive_count` incrémenté + log `rule_versions`
- [ ] **P3.15** — Tests : évaluateur (30+ cas de conditions), fenêtres temporelles, toutes les règles builtin

**Livrable P3 :** `chmod 777 /etc/shadow` sur un hôte surveillé → alerte visible sur l'API en < 500ms.

---

## Phase 4 — Intelligence `S10–S12`

> **Objectif :** Events enrichis TI, chaînes de corrélation reconstruites.

*Dépend de : Phase 3 complète*

- [ ] **P4.01** — `threat_intel/providers/abuseipdb.py` + `virustotal.py` : enrichissement IP et hash
- [ ] **P4.02** — `threat_intel/cache.py` : cache Redis (TTL 1h IP, 24h hash, 6h IOC)
- [ ] **P4.03** — `threat_intel/providers/stix_taxii.py` : ingestion feeds STIX/TAXII publics
- [ ] **P4.04** — `threat_intel/providers/misp.py` : intégration MISP
- [ ] **P4.05** — `threat_intel/scheduler.py` : refresh périodique des feeds IOC
- [ ] **P4.06** — `workers/ti_worker.py` : consomme `events:normalized`, publie `events:enriched`
- [ ] **P4.07** — Circuit breaker sur chaque provider TI (pybreaker) avec fallback `ti_tags=["provider:unavailable"]`
- [ ] **P4.08** — `correlation/graph.py` : `EventGraph` rustworkx DiGraph (noeuds=events, arêtes typées)
- [ ] **P4.09** — `correlation/linkers/pid_ppid.py` + `resource.py` + `user.py` + `temporal.py`
- [ ] **P4.10** — `correlation/engine.py` : appel des linkers à chaque event enrichi
- [ ] **P4.11** — `correlation/chain_builder.py` : extraction `IncidentChain` depuis sous-graphe connexe
- [ ] **P4.12** — `workers/correlation_worker.py` : publie `analysis:correlated`
- [ ] **P4.13** — `storage/repositories/entity_repo.py` : CRUD `EntityProfile` + mise à jour `risk_score`
- [ ] **P4.14** — `api/routers/events.py` : `GET /events/{id}/chain` + `GET /events/{id}/context`
- [ ] **P4.15** — `api/routers/entities.py` : tous les endpoints (liste, détail, events, alerts, risk history, whitelist)
- [ ] **P4.16** — DLQ : table `dlq_entries` + topic `events:dlq:*` + `GET /health/dlq`
- [ ] **P4.17** — Tests d'intégration : scénario SSH login → sudo → exfiltration → vérifier IncidentChain

**Livrable P4 :** Séquence SSH → sudo → exfil reconstruite comme incident unique corrélé.

---

## Phase 5 — Decision Engine `S13–S15`

> **Objectif :** Décisions autonomes tracées, queue approbation humaine fonctionnelle.

*Dépend de : Phase 4 complète*

- [ ] **P5.01** — `decision/weighted_scorer.py` : agrégation `(rule×0.4) + (ml×0.3) + (ti×0.2) + (correlation×0.1)`
- [ ] **P5.02** — `decision/risk_matrix.py` : mapping score → `decision_type` (IGNORE / ESCALATE / ALERT+INVESTIGATE / ALERT+ISOLATE / +REQUEST_HUMAN)
- [ ] **P5.03** — `decision/journal.py` : append-only, BLAKE3 hash chain, signé Ed25519 server key
- [ ] **P5.04** — `decision/engine.py` : orchestration — scorer → matrix → policy overrides → journal → publish
- [ ] **P5.05** — `decision/human_queue.py` : queue approbation + handler timeout (décision auto à expiration)
- [ ] **P5.06** — `decision/action_executor.py` : ALERT (déjà fait), NOTIFY (webhook), ESCALATE (email/slack), COLLECT_MORE (push profil investigation), ISOLATE (stub — log uniquement en P5)
- [ ] **P5.07** — `workers/decision_worker.py` : consomme `analysis:correlated`, publie `decisions:completed` + `decisions:pending`
- [ ] **P5.08** — `api/routers/decisions.py` : tous les endpoints (liste, détail, pending, approve, reject, `GET /decisions/journal/verify`)
- [ ] **P5.09** — `api/ws/manager.py` : broadcast `WS /ws/decisions`
- [ ] **P5.10** — Webhooks sortants : `POST /webhooks`, livraison HMAC-SHA256, retry exponentiel 5x
- [ ] **P5.11** — Trigger PostgreSQL `prevent_decision_update` : immuabilité des champs core
- [ ] **P5.12** — `core/lifecycle.py` : `GracefulWorker` — SIGTERM → drain → flush → commit offsets → exit 0
- [ ] **P5.13** — Tests : > 100 scénarios de décisions avec résultats attendus, précision > 95%, vérification intégrité journal

**Livrable P5 :** Décisions justifiées avec traçabilité complète. Humain peut approuver/rejeter ISOLATE.

---

## Phase 6 — ML Engine `S16–S19`

> **Objectif :** Baseline comportementale, scores d'anomalie augmentant la détection rule-based.

*Dépend de : Phase 5 complète*

- [ ] **P6.01** — `ml_engine/feature_extractor.py` : `EntityFeatureVector` depuis `entity_hourly_stats` ClickHouse
- [ ] **P6.02** — `ml_engine/baseline.py` : `IsolationForest` River (online learning), une instance par `entity_id`
- [ ] **P6.03** — `ml_engine/scorer.py` : `BehavioralScorer` → `ml_score ∈ [0, 100]`
- [ ] **P6.04** — `ml_engine/mitre_classifier.py` : classifier scikit-learn, dataset labellisé MITRE ATT&CK
- [ ] **P6.05** — `ml_engine/model_store.py` : versioning + persistance modèles, checkpoint toutes les 15 min
- [ ] **P6.06** — `workers/ml_worker.py` : consomme `events:normalized`, publie `analysis:ml`, checkpoint automatique
- [ ] **P6.07** — Intégration score ML dans `DecisionEngine.WeightedScorer`
- [ ] **P6.08** — Framework A/B test : déploiement parallèle nouveau modèle vs. modèle courant, comparaison métriques
- [ ] **P6.09** — Vue matérialisée ClickHouse `entity_hourly_stats` : features ML pré-calculées
- [ ] **P6.10** — Tests : FP rate < 5% sur workloads propres, recall > 80% sur scénarios d'attaque de référence

**Livrable P6 :** Exfiltration lente via DNS (non couverte par règles) → alerte ML.

---

## Phase 7 — Forensics `S20–S22`

> **Objectif :** Gestion de cas complète, exports légalement admissibles.

*Dépend de : Phase 6 complète*

- [ ] **P7.01** — Agent : `snapshot.go` — capture `procfs` + `netlink` → sérialise état complet processus + connexions
- [ ] **P7.02** — Agent : gRPC endpoint `TakeSnapshot` dans `AgentService`
- [ ] **P7.03** — `forensic/snapshot.py` : `POST /snapshots` + diff entre deux snapshots
- [ ] **P7.04** — `forensic/case_manager.py` : CRUD `ForensicCase` + custody log append-only
- [ ] **P7.05** — `forensic/timeline.py` : reconstruction chronologique triée par `timestamp_ns`
- [ ] **P7.06** — `forensic/exporter/json_export.py` + `html_report.py` + `pdf_report.py` (via WeasyPrint)
- [ ] **P7.07** — `forensic/exporter/misp_export.py` : création event MISP depuis case
- [ ] **P7.08** — `forensic/exporter/thehive_export.py` : création case TheHive depuis case OSEye
- [ ] **P7.09** — `api/routers/cases.py` : tous les endpoints (CRUD, events, alerts, notes, evidence, timeline, export, custody)
- [ ] **P7.10** — `api/routers/snapshots.py` : POST, GET, diff
- [ ] **P7.11** — Trigger PostgreSQL `prevent_custody_update` : immuabilité du custody log
- [ ] **P7.12** — Tests : immuabilité custody log, export PDF généré et lisible, diff snapshot détecte un nouveau processus

**Livrable P7 :** Analyste ouvre un cas, annote, exporte un rapport PDF défendable.

---

## Phase 8 — Policy Engine + Plugin SDK `S23–S25`

> **Objectif :** Profils de surveillance hot-swap, écosystème de plugins extensible.

*Dépend de : Phase 7 complète*

- [ ] **P8.01** — `policy/schema.py` : `SurveillanceProfile` + `CollectorConfig` (avec champ `platforms`)
- [ ] **P8.02** — `policy/engine.py` : chargement des 6 profils YAML intégrés + validation
- [ ] **P8.03** — `policy/engine.py` : push vers agents via `policy:push:{agent_id}` bus → gRPC `ReceivePolicy`
- [ ] **P8.04** — Agent : `policy/receiver.go` — reçoit `SurveillanceProfile`, filtre les collectors non disponibles sur cet OS, active/désactive en < 2s
- [ ] **P8.05** — `api/routers/policies.py` : CRUD profils + `POST .../apply`
- [ ] **P8.06** — `sdk/oseye_sdk/plugin.py` : classes de base `Plugin`, `CollectorPlugin`, `AnalyzerPlugin`, `ExporterPlugin`
- [ ] **P8.07** — `sdk/oseye_sdk/event.py` : modèle `Event` exposé aux plugins (sous-ensemble de `UniversalEvent`)
- [ ] **P8.08** — `sdk/oseye_sdk/ipc.py` : communication IPC plugin ↔ server (Unix socket)
- [ ] **P8.09** — `plugin/verifier.py` : vérification signature Ed25519 du package plugin
- [ ] **P8.10** — `plugin/sandbox.py` : isolation `subprocess` + cgroups v2 (CPU/mem limits)
- [ ] **P8.11** — `plugin/manager.py` : load/unload plugins, lifecycle
- [ ] **P8.12** — `api/routers/plugins.py` : install, enable, disable, delete
- [ ] **P8.13** — Plugins exemple : `notifier_pagerduty`, `exporter_s3`
- [ ] **P8.14** — Publication SDK sur PyPI (ou registry privé)
- [ ] **P8.15** — Tests : basculement workstation→investigation en < 2s, plugin tourne en sandbox isolé sans accès FS root

**Livrable P8 :** Switch de profil en < 2s. Plugin tiers sandboxé.

---

## Phase 9 — Dashboard UI `S26–S29`

> **Objectif :** Interface web production-grade pour tous les workflows analyste.

*Dépend de : Phase 8 complète*

- [ ] **P9.01** — Setup Vite + React 18 + TypeScript + Tailwind + Zustand + React Router
- [ ] **P9.02** — Génération client API TypeScript depuis OpenAPI (`openapi-typescript-codegen`)
- [ ] **P9.03** — `hooks/useWebSocket.ts` : connexion WS avec reconnexion automatique, dispatch vers stores
- [ ] **P9.04** — Auth flow : page Login → `POST /auth/token` → store JWT → refresh automatique avant expiration
- [ ] **P9.05** — `pages/Dashboard.tsx` : events/s temps réel, compteur alertes ouvertes, heatmap risque par entité
- [ ] **P9.06** — `pages/Events.tsx` : timeline avec filtres avancés (category, severity, hostname, process, resource, plage de temps)
- [ ] **P9.07** — `pages/Alerts.tsx` : queue alertes + workflow acknowledge / faux-positif / assign
- [ ] **P9.08** — `pages/Decisions.tsx` : journal + cartes approbation humaine avec compte à rebours
- [ ] **P9.09** — `pages/Cases.tsx` : liste, détail, vue timeline, formulaire ajout evidence, export
- [ ] **P9.10** — `pages/Entities.tsx` : profils de risque, graphe d'évolution, arbre de processus
- [ ] **P9.11** — `pages/Rules.tsx` : liste, éditeur YAML inline, enable/disable, stats FP
- [ ] **P9.12** — `pages/NetworkGraph.tsx` : force-directed D3 des events corrélés (IncidentChain)
- [ ] **P9.13** — Live updates WebSocket sur toutes les pages (alertes, decisions, events)
- [ ] **P9.14** — Responsive design + dark mode
- [ ] **P9.15** — Tests E2E Playwright : golden path dashboard, création case, approbation décision

**Livrable P9 :** Dashboard complet, toutes les pages fonctionnelles, mises à jour live.

---

## Phase 10 — Hardening + Distribution `S30–S33`

> **Objectif :** Production-grade, performance validée, packaging multi-OS.

*Dépend de : Phase 9 complète*

### 10.1 — Action ISOLATE réelle

- [ ] **P10.01** — Agent Linux : `SIGSTOP` + freeze cgroup v2 + timer rollback configurable
- [ ] **P10.02** — Agent Windows : `SuspendProcess` (Win32 API) + isolation réseau via Windows Firewall API
- [ ] **P10.03** — Agent macOS : `SIGSTOP` + pf firewall rule push
- [ ] **P10.04** — Tests : isolation effective + rollback automatique après timeout

### 10.2 — Drivers Windows et macOS

- [ ] **P10.05** — `platform/windows/driver.go` : `WindowsDriver` + `ETWCollector`, `WinLogCollector`, `RegistryCollector`, `WMICollector`, `SysmonCollector`
- [ ] **P10.06** — `platform/windows/etw/consumer.go` : provider Microsoft-Windows-Security-Auditing
- [ ] **P10.07** — `platform/darwin/driver.go` : `DarwinDriver` + `EndpointSecurityCollector`, `FSEventsCollector`, `OpenBSMCollector`, `UnifiedLogCollector`
- [ ] **P10.08** — Adapters normalizer Windows (`etw`, `winlog_security`, `registry`, `wmi`, `sysmon`)
- [ ] **P10.09** — Adapters normalizer macOS (`endpoint_security`, `fsevents`, `openbsm`, `unified_log`)
- [ ] **P10.10** — Tests intégration : rules cross-OS déclenchées sur Windows + macOS

### 10.3 — Hardening sécurité

- [ ] **P10.11** — mTLS enforced sur toute la communication agent↔server (vérification CN)
- [ ] **P10.12** — TLS 1.3 minimum sur API REST (rejet TLS < 1.3)
- [ ] **P10.13** — Rate limiting token bucket Redis (600 req/min JWT, 300 req/min API key) sur tous les endpoints
- [ ] **P10.14** — Row-Level Security PostgreSQL : politique `org_isolation` sur toutes les tables + retrait `DEFAULT org_id`
- [ ] **P10.15** — Pentest OWASP Top 10 sur l'API REST OSEye (auto-pentest)
- [ ] **P10.16** — Secrets Vault : intégration HashiCorp Vault pour clés JWT + mots de passe DB

### 10.4 — Performance

- [ ] **P10.17** — Benchmark : validation > 100 000 events/s (ClickHouse + pipeline complet)
- [ ] **P10.18** — Mesure latence P50/P95/P99 event→alerte, validation P99 < 500ms
- [ ] **P10.19** — Profiling CPU agent Linux sous charge, optimisation < 2% CPU

### 10.5 — Packaging et distribution

- [ ] **P10.20** — Packages Linux : `.deb` + `.rpm` via FPM (agent + server)
- [ ] **P10.21** — Installeur Windows : NSIS ou MSI (agent)
- [ ] **P10.22** — Package macOS : `.pkg` signé (agent)
- [ ] **P10.23** — Images Docker officielles multi-arch : `amd64` + `arm64` (agent + server + ui)
- [ ] **P10.24** — Helm chart `oseye/` : values.yaml, DaemonSet agent, Deployments server/workers/ui, HPA, NetworkPolicy, cert-manager
- [ ] **P10.25** — Playbook Ansible `infra/ansible/deploy.yml` : déploiement grande échelle sans K8s
- [ ] **P10.26** — Documentation API : export OpenAPI + site Docusaurus (`docs/api/`)
- [ ] **P10.27** — `CHANGELOG.md` + release GitHub Actions : tag → build → push images + packages

**Livrable P10 :** OSEye v1.0 distribuable sur Linux/Windows/macOS, > 100k events/s validés, pentest passé.

---

## Récapitulatif

| Phase | Semaines | Tâches | Livrable clé |
|-------|----------|--------|-------------|
| 1 — Foundation | S1–S3 | 49 | Pipeline end-to-end, events en DB |
| 2 — Full Collection | S4–S6 | 15 | 9 collectors, agent résilient |
| 3 — Détection | S7–S9 | 15 | Alerte en < 500ms sur attaque réelle |
| 4 — Intelligence | S10–S12 | 17 | Corrélation incident multi-events |
| 5 — Decision Engine | S13–S15 | 13 | Décisions traçables, approbation humaine |
| 6 — ML Engine | S16–S19 | 10 | Détection anomalies comportementales |
| 7 — Forensics | S20–S22 | 12 | Export PDF cas forensique |
| 8 — Policy + SDK | S23–S25 | 15 | Hot-swap profils, plugins sandboxés |
| 9 — Dashboard UI | S26–S29 | 15 | Interface web complète |
| 10 — Hardening | S30–S33 | 27 | v1.0 multi-OS, > 100k evt/s, distribué |
| **Total** | **33 semaines** | **188 tâches** | **OSEye v1.0** |

---

## Ordre de démarrage absolu (semaine 1)

```
Jour 1–2 : P1.01 → P1.11  (fichiers contrats + codegen proto)
Jour 3   : P1.12 → P1.16  (scaffolding monorepo + CI + docker-compose)
Jour 4–7 : P1.17 → P1.25  (agent Go Linux minimal)
           P1.26 → P1.32  (server ingest + normalizer) — en parallèle
Semaine 2 : P1.33 → P1.45 (storage + API + workers stubs)
Semaine 3 : P1.46 → P1.49 (tests + livrable P1)
```
