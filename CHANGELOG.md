# Changelog

All notable changes to OSEye are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
