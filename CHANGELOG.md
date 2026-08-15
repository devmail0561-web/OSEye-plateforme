# Changelog

All notable changes to OSEye are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — 2026-08-15

### Changed

**Collecteurs — modèle delta (tous les agents)**
- `procfs` (Linux), `toolhelp32` (Windows), `ps` (macOS) : n'émettent plus un snapshot complet à chaque cycle. Premier scan = snapshot initial (tous les process comme `process_create`), scans suivants = uniquement les nouveaux PIDs (`process_create`) et les PIDs disparus (`process_exit`). Réduit de ~95% le bruit en régime stable.
- `winnetstat` (Windows) : même modèle delta pour les connexions TCP (`connection_open` / `connection_close`). Fingerprint = `local:port->remote:port@pid`.
- `etw` (Windows) : remplacement de `Get-WinEvent -MaxEvents 20` par `Get-WinEvent -FilterHashtable @{StartTime=...}`. Plus de doublons entre cycles, plus de cap d'events.

**Moteur de règles — opérateurs numériques**
- `engine.go` : ajout des opérateurs `gt`, `lt`, `gte`, `lte` pour les conditions numériques (ex. `cpu_pct > 80`, `port < 1024`). Support de `float64`, `json.Number`, `string`, `int`, `int64` comme valeur de condition.

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
