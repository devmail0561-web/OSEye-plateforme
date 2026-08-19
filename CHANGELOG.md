# Changelog

All notable changes to OSEye are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0-alpha.2] — 2026-08-19

### Added
- **Fan-out Redis** : `create_worker_bus()` dans `bus/factory.py` — chaque worker a son propre consumer group Redis (`oseye-storage`, `oseye-rules`, `oseye-ml`, `oseye-ti`, `oseye-correlation`, `oseye-decision`, `oseye-notify`)
- **EventMerger** : `agent/internal/merger/` — fenêtre 300ms, fusion eBPF+netlink (enrichissement `src_ip`/`src_port`) et déduplication eBPF+auditd
- **P2 Ping** : `POST /api/v1/agents/{cn}/ping` + handler agent + `oseye-server agents ping <cn>`
- **P3 Collecteurs** : `GET /api/v1/agents/{cn}/collectors` — état en temps réel des collecteurs par agent
- **P7 Règles CRUD** : `POST/PUT/DELETE /api/v1/rules/db/*`, `oseye-server rules create/edit/delete`
- **P9 Versionnement** : table `rule_change_log`, `GET /rules/db/{id}/history`, `POST /rules/db/{id}/assign-profile`
- **P10 Profils** : 6 nouveaux profils YAML (`webserver`, `database`, `dns`, `mail`, `laptop`, `desktop`)
- **P8 rule_type** : champ `anomaly | surveillance` dans `RuleDefinition`, `Rule` Go, YAML de règles — pipeline différencié dans `rule_worker.py`
- **P5 Baselines** : champs `baseline_apps`, `baseline_net_dests`, `baseline_users` dans `SurveillanceProfile` — peuplés dans les 12 profils

### Fixed
- **P1** : `disconnect_reason` persisté en DB + événement `agent:disconnected` sur le bus avec code gRPC status
- **P4** : `agent_id` retourné par `GET /agents`, UUID loggué au démarrage agent
- **P6** : `ignore_processes: [oseye-agent, oseye-config]` + `ignore_paths_prefix` dans tous les profils ; filtre `os.Getpid()` dans `controller.go`
- **source="grpc"** : normalizer loop production utilisait `source="procfs"` incorrect
- **AlertRow.rule_type** : colonne manquante — les alertes `surveillance` étaient misclassifiées `anomaly` après redémarrage
- **Shutdown buses** : les 8 buses Redis n'étaient pas fermés au shutdown (`await _b.close()`)
- **webserver.yaml** : binaires web (`nginx`, `apache2`, etc.) retirés de `ignore_processes` (conflit avec `baseline_apps`)
- **RULES-001** : `app.state.rule_repo` non assigné dans le lifespan → tous les endpoints `/rules/db/*` retournaient 503
- **MERGE-001** : drop silencieux d'événements dans `flushGroup()` → `slog.Warn` + log
- **MERGE-003** : goroutine leak `evMerger.Run()` non trackée dans `batcherWg`
- **MERGE-004** : `sourcePriority` code mort — eBPF maintenant promu correctement quand netlink arrive en premier

---

## [0.3.0-alpha.1] — 2026-08-18

### Added

**Architecture distribuée (multi-serveurs)**
- JWT blocklist → Redis (`oseye:jwt:revoked:{jti}` SETEX avec TTL) — révocations partagées entre instances
- WebSocket → Redis pub/sub (`oseye:ws:alerts`, `oseye:ws:decisions`) — fanout multi-serveurs
- Policy engine → Redis SET (`oseye:policy:connected_agents`) — `push_to_all()` touche tous les agents sur tous les serveurs
- Decision Engine → leader Redis SETNX (`oseye:decision:leader`) — un seul écrivain pour le journal BLAKE3
- Profile re-sync à la reconnexion agent — `push_default_to_agent()` déclenché à chaque `ReceivePolicy`
- `OSEYE_SERVER_ROLE=collector|worker|api|all` — démarrage sélectif des composants
- `OSEYE_ML_WORKER_ENABLED`, `OSEYE_RULE_WORKER_ENABLED`, `OSEYE_DECISION_WORKER_ENABLED`, `OSEYE_GRPC_SERVER_ENABLED`

**Mode agent-only par défaut**
- `OSEYE_MANAGEMENT_API_ENABLED=false` par défaut — seuls `/health` et `/enroll/*` exposés
- `OSEYE_UI_URL` — URL du serveur UI externe (CORS auto + redirect `GET /`)
- `OSEYE_UI_DIR` — optionnel, servir l'UI depuis ce serveur
- `oseye-server api enable/disable/status` — activer/désactiver l'API management
- `oseye-server ui url <URL>` — configurer l'URL UI

**Packaging**
- `oseye-dev` — package tout-en-un pour développeurs (agent debug + serveur + config dev)
- `nfpm-dev.yaml` + scripts pre/postinst + service systemd `oseye-dev`
- `make package-dev` — produit `oseye-dev.deb` + `.rpm`
- `install.sh` — installeur universel (installe, configure, lance)
- `.devcontainer/devcontainer.json` — VS Code Dev Containers / GitHub Codespaces

**Sécurité — users système séparés**
- `oseye-agt` — agent (accès `/etc/oseye/agent.env`, `/var/lib/oseye/agent/`)
- `oseye-srv` — serveur (accès `/etc/oseye/server.env`, certs, plugins)
- `oseye-dev` — package dev uniquement
- `server/Dockerfile` : `USER oseye-srv`

### Fixed

**Audit 2026-08-18 — 24 CRITICAL/HIGH corrigés**
- `decision/journal.py` : `broken: list[int]` — `verify_chain()` était inopérant (DE-01)
- `workers/rule_worker.py` : try/except autour de `evaluate()` — fin du crash silencieux (W-01)
- `correlation/linkers/same_host.py` : `created_at` → `updated_at` — corrélation restaurée (W-02)
- `api/routers/auth.py` : rate limit proxy-aware — brute-force protégé derrière nginx (API-01/02)
- `ingest/grpc_service.py` : `config_json` envoyait `{}` — profils et règles arrivent maintenant à l'agent
- `policy/engine.py` : topic `policy:push:{UUID}` → `policy:push:{cn}` — push profil fonctionnel
- `plugin/manager.py` : validation nom dans `install()` — `__init__.py` et modules réservés rejetés
- 9 règles YAML MITRE corrigées (seuils, entity_key, champs morts)
- Variables TLS renommées : `OSEYE_TLS_CERT_FILE`, `OSEYE_TLS_KEY_FILE`, `OSEYE_TLS_CA_*`
- `OSEYE_BUS_BACKEND` supprimée (n'existait plus dans config.py)
- `docker-compose.prod.yml` : secrets Docker via `*_FILE` pattern + entrypoint.sh
- `_task_done_callback` attaché sur les 10 workers asyncio

## [Unreleased] — 2026-08-16

### Security

**Agent Go — audit complet `agent/` (commit `2f7937b`)**  
Détails : [`docs/internal/AUDIT_AGENT_2026-08-16.md`](docs/internal/AUDIT_AGENT_2026-08-16.md)

53 findings corrigés (3 critical / 14 high / 23 medium / 13 low) :

- **[C]** `responder/reporter.go` : race condition send-on-closed-channel → panique agent corrigée
- **[C]** `policy/client.go` : borne minimale `throttle >= 0.01` — un serveur compromis ne peut plus aveugler les collecteurs
- **[H]** `cmd/oseye-config/enroll.go` : `signCSR()` valide désormais CN et signature CA (`CheckSignatureFrom`) ; PKCS#8 remplace PKCS#1 ; `io.LimitReader` sur tous les `ReadAll`
- **[H]** `responder/executor.go` : `RestoreFile` valide `originalPath` via `isAllowedPath` (même allowlist que `QuarantineFile`) ; symlinks résolus avant quarantaine ; handle nft validé numérique
- **[H]** `ebpf/loader.go` : goroutine leak `rd.Read()` bloquant corrigé (`SetDeadline` sur `ctx.Done`)
- **[H]** `fanotify/collector.go` : FD leak `meta.Fd > 0` → `>= 0` ; `Event_len < fanotifyMetadataSize` rejeté
- **[H]** `procfs/collector.go` : cmdline tronquée à 4 096 octets + redaction regexp des secrets (`-p`, `--token=`, `Bearer`, `Authorization:`)
- **[H]** `autonomy/controller.go` : `execKillProcess` ajoute `dedup.Allow` ; race `rolledBack` corrigée ; `doRollback` enveloppé avec `recover`
- **[H]** `transport/batcher.go` : erreur `sendFn` loguée (était silencieusement ignorée)
- **[H]** `transport/grpc_client.go` : chain head inclus dans `batchSignature` — empêche le replay de batch
- **[M]** `enrollment/client.go` : fingerprint CA calculé sur DER (non PEM) — compatible `openssl x509 -fingerprint`
- **[M]** `config.go` : `http://` pour `EnrollServerURL` déclenche un warning ou erreur selon `OSEYE_INSECURE`
- **[M]** `executor_darwin.go` : `isAllowedPath` converti de liste noire en liste blanche positive
- **[M]** `buffer/buffer.go` : cap à 100 000 lignes + éviction FIFO — prévient le remplissage disque
- **[M]** `buffer/buffer_cgo.go` : `cache=shared` supprimé (incompatible WAL) ; range DELETE dans `Pop` ; `PRAGMA busy_timeout=5000`
- **[M]** `autonomy/reporter.go` : `commandID` généré par `crypto/rand` ; `EventData` réduit au minimum dans le payload de décision
- **[L]** `signer/signer.go` : avertissement si permissions clé privée > 0600
- Test `TestBatchSignatureCorrectness` mis à jour pour couvrir le chain head dans le digest attendu

---

## [Unreleased] — 2026-08-15

### Performance

**Agent Go — 12 fichiers, chemin chaud**
- `engine.go` : fast path `getField` sans alloc sur champs simples (95% des cas), `strconv` vs `fmt.Sprintf`, `CompiledCondition` pré-extrait (type assertions supprimées par event), `matchIn` O(1) via set pré-construit
- `correlator.go` : two-level map `ruleID→groupValue→state` — suppression de la concaténation de clé par event
- `batcher.go` : handoff de slice au lieu de `make+copy` par flush ; timer `Reset` au lieu de `NewTimer` par batch
- `buffer.go` : `DELETE WHERE id <= ?` au lieu de N DELETE individuels par `Pop` ; slices pré-allouées
- `chain.go` : `AppendTo(*[32]byte)` zero-alloc heap (API additive)
- `collector/manager.go` : N goroutines fan-in supprimées — collectors écrivent directement dans `m.out`
- `hostprofile/profile.go` : `portsStr []string` précalculé à l'update ; `strconv.Itoa` remplace `fmt.Sprintf`
- `dedup.go` : concaténation directe remplace `fmt.Sprintf` ; `signer.go` : `PublicKey()` depuis cache
- `watchdog.go` : stack buffer `[4096]byte` remplace `bufio.NewScanner` ; `bytes.Fields` remplace `strings.Fields`
- `procfs/collector.go` : deux timers réutilisés (`pauseTimer`, `scanTimer`) remplacent `time.After` par cycle

**Serveur Python — 9 fichiers, chemin chaud**
- `evaluator.py` : `ast.parse + compile` → cache `compiled_code` au chargement des règles (élimine 35 compilations/event) ; classes `_Event`/`_SafeCallable` au niveau module ; `re.sub` précalculé
- `rule_engine/engine.py` : `model_dump()` une seule fois par event (était appelé 35× par règle) ; index immuable sans lock ; règles désactivées exclues à l'indexation ; `entity_key` lazy
- `redis_bus.py` : `publish_batch` pipeline Redis (1 RTT/batch vs N RTTs) ; `count` 10→100 dans `xreadgroup` ; SCAN topics 100ms→5s
- `bus/interface.py` + `memory_bus.py` : `publish_batch` ajouté au Protocol
- `grpc_service.py` : `asyncio.get_running_loop()` try/except et `_get_agent_key(cn)` sortis de la boucle events ; `publish_batch` utilisé
- `features.py` : `@lru_cache(maxsize=512)` sur `_stable_hash_norm` ; division `timestamp_ns` unifiée
- `correlation/engine.py` : `_min_severity_ord` et `_max_timeframe` précalculés à l'init
- `alerts.py` : suppression objet `AlertRow` throw-away dans `update()`
- `normalizer/engine.py` + `rule_worker.py` : `sys.intern` sur clés, variables locales cachées hors boucle

**Makefile**
- `DEV_ENV` : ajout `OSEYE_CHECKPOINT_HMAC_KEY` (généré via `openssl rand -hex 32`) et `OSEYE_INSECURE=true` — `make run-server` fonctionne sans intervention manuelle

### Changed

**Collecteurs — modèle delta (tous les agents)**
- `procfs` (Linux), `toolhelp32` (Windows), `ps` (macOS) : n'émettent plus un snapshot complet à chaque cycle. Premier scan = snapshot initial (tous les process comme `process_create`), scans suivants = uniquement les nouveaux PIDs (`process_create`) et les PIDs disparus (`process_exit`). Réduit de ~95% le bruit en régime stable.
- `winnetstat` (Windows) : même modèle delta pour les connexions TCP (`connection_open` / `connection_close`). Fingerprint = `local:port->remote:port@pid`.
- `etw` (Windows) : remplacement de `Get-WinEvent -MaxEvents 20` par `Get-WinEvent -FilterHashtable @{StartTime=...}`. Plus de doublons entre cycles, plus de cap d'events.

**Moteur de règles — opérateurs numériques**
- `engine.go` : ajout des opérateurs `gt`, `lt`, `gte`, `lte` pour les conditions numériques (ex. `cpu_pct > 80`, `port < 1024`). Support de `float64`, `json.Number`, `string`, `int`, `int64` comme valeur de condition.

### Security

- **CA key passphrase** (`enrollment_store.py`) : `load_pem_private_key` accepte désormais une passphrase via `OSEYE_TLS_CA_KEY_PASSWORD`. La clé CA peut être stockée chiffrée sur disque ; variable vide = clé non chiffrée (comportement antérieur inchangé). Nouveau champ `tls_ca_key_password` dans `Settings`.
- **JWT blocklist — race condition** (`api/auth/jwt.py`) : le fichier `.tmp` est créé avec `os.open(..., O_CREAT | O_TRUNC, 0o600)` au lieu d'un `write_text` + `chmod` ultérieur. Le fichier n'est plus world-readable même transitoirement. `OSEYE_DATA_DIR` est créé automatiquement au démarrage si absent.
- **Documentation secrets** : `OSEYE_SECRET_KEY` (HMAC API keys, requis), `OSEYE_DATA_DIR` (répertoire JWT blocklist, défaut `/tmp` non recommandé en prod), et `OSEYE_TLS_CA_KEY_PASSWORD` ajoutés dans `.env.example` et `packaging/config/secrets.env.example`.

### Fixed

- `procfs` : bug TOCTOU — un PID n'est ajouté à `currentPIDs` qu'après `readProcess` réussi ; un processus éphémère entre `ReadDir` et `readProcess` ne génère plus de `process_exit` orphelin.
- `procfs` : `errStopped` retourné par `scan` n'incrémentait plus `errCount` et ne polluait plus `lastErr`.
- `toolhelp32`, `ps`, `etw`, `winnetstat` : champ `running bool` remplacé par `atomic.Bool` — data race éliminée sur `Start`/`Stop`/`Health`.
- `etw` : `lastPoll` déplacé en variable locale dans `run()` (était un champ struct accessible depuis `Health()` sans synchronisation). Fenêtre temporelle revertée sur échec PowerShell.
- `etw` : erreur PowerShell loggée en `Warn` au lieu de `Debug`.
- `ps` : `listProcesses` retourne un type interne `psProcess` au lieu du type JSON `processInfo`.

## [0.2.0-alpha.1] — 2026-08-14

### Added

**Phase 2 — Full Collection (M12–M18)**
- Collectors Linux : fanotify, inotify, netlink, journald, udev, syslog
- Watchdog + throttling CPU/mémoire automatique
- Buffer replay (`Replay`/`AckUntil`) — zéro perte d'événements sur reconnexion
- `BackpressureController` — mesure lag Redis Streams, envoie `SET_THROTTLE` aux agents
- K8s DaemonSet avec capabilities eBPF, tolerations control-plane
- Normalizers Python pour les 6 nouveaux collecteurs (22 tests intégration)

**Phase 3 — Détection**
- 35 règles YAML MITRE (credential_access, defense_evasion, discovery, impact_c2, lateral_movement, persistence, privilege_escalation)
- 31 scénarios d'attaque — latence détection < 500ms

**Phase 4 — Intelligence**
- 3 nouveaux linkers de corrélation : `TemporalLinker` (60s + kill-chain), `PidLineageLinker`, `UserActivityLinker`
- `GET /events/{id}/chain` — reconstruction de chaîne d'incident
- `GET /entities` + `GET /entities/{id}` — risk score calculé depuis les alertes

**Phase 5 — Decision Engine**
- WebSocket `/ws/decisions` — stream temps réel des décisions (auth JWT/API key)
- `GET /decisions/journal/verify` — vérifie l'intégrité BLAKE3 de la chaîne de journal
- `DecisionWorker` diffuse chaque décision persistée vers les clients WebSocket

**Phase 6 — ML Engine**
- A/B test : `MLWorker` accepte `ab_session` (`ABTestSession.score_event` utilisé)
- 8 benchmarks : FP rate < 5% sur workloads propres, recall MITRE classifier, feedback négatif

**Phase 7 — Forensics**
- Collecteur de snapshots Go (`agent/internal/snapshot`) : lit `/proc/*/status`, `/proc/net/tcp[6]`
- `TAKE_SNAPSHOT` command opérationnel : Collect() + Post() mTLS TLS 1.3
- `OSEYE_API_ADDR` ajouté au config agent pour l'endpoint REST snapshot
- 8 nouveaux tests Go snapshot

### Fixed
- `BackpressureController` : stream mesuré `events:raw` → `events:normalized`
- `grpc_service.IngestEvents` : `active_cns` leak sur `context.abort()` → try/finally
- K8s : image `latest` → `v0.1.0-alpha.1`, Namespace + seccompProfile ajoutés
- Linkers : `incident.events` → `incident.timeline` (champ inexistant)
- `UserActivityLinker` : faux positif substring → word-boundary matching
- `GET /events/{id}/chain` : `EventFilter` Protocol non-instanciable → dataclass
- `GET /decisions/journal/verify` : méthode repo inexistante corrigée

### Security
- `CommandClient.handleTakeSnapshot` : cmdlines tronquées à 500 chars (fuite secrets)
- `inodeToPID` remplacé par scan `/proc/net/unix` avec cache (O(N) → O(1))
- Snapshot : limite 10 000 processus pour éviter DoS mémoire

---

## [0.1.0-alpha.1] — 2026-08-12

First experimental release.

### Added
- Agent Go with 9 collectors (eBPF, auditd, fanotify, inotify, procfs, netlink, journald, udev, syslog)
- gRPC/mTLS transport with Ed25519 batch signing and BLAKE3 hash chain
- Offline SQLite buffer with full-jitter backoff
- CLI `oseye-config` for secure agent configuration management
- Server Python (FastAPI) with normalizer, rule engine (35+ YAML rules), ML engine (River HalfSpaceTrees)
- Threat intelligence engine (AbuseIPDB, VirusTotal, MISP) with circuit breaker
- Correlation engine with auto-close incidents
- Decision Engine (8 decision types, risk matrix, immutable BLAKE3 journal)
- Response Engine (BLOCK_IP, QUARANTINE_FILE, KILL_PROCESS) with rollback
- Forensics module (case management, custody log, PDF/MISP/TheHive export)
- Plugin SDK Python (AnalyzerPlugin, ExporterPlugin, CollectorPlugin) with Ed25519 signature
- 6 surveillance profiles (workstation, server, investigation, minimal, compliance, stealth)
- Dashboard React/TypeScript with analyst + admin RBAC views
- Auto-enrollment for agents (first boot PKI provisioning)
- Resource watchdog (CPU/RAM throttling)
- .deb/.rpm packaging with systemd integration
- Docker image (multi-arch linux/amd64, linux/arm64)
- CI pipeline (lint, test, build)
- Release workflow with SHA256 checksums, GPG signing, cosign

### Security
- Config validation: strict port/path/UUID/bounds checks, critical path rejection
- Atomic config writes with file locking (flock)
- Secrets masking in CLI output
- Newline injection prevention in env file
- Permissions 0600 on all config files
- -trimpath for reproducible builds
- Digest-pinned Docker base images
