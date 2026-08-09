# OSEye — Software Architecture Document

**Version:** 1.1  
**Date:** 2026-08-06  
**Statut:** Référence de développement  
**Classification:** Confidentiel — usage interne

---

## Table des matières

1. [Stack technologique](#1-stack-technologique)
2. [Structure du monorepo](#2-structure-du-monorepo)
3. [Architecture des composants](#3-architecture-des-composants)
4. [Modèles de données](#4-modèles-de-données)
5. [Architecture de sécurité](#5-architecture-de-sécurité)
6. [Schémas de stockage](#6-schémas-de-stockage)
7. [API — Catalogue complet des endpoints](#7-api--catalogue-complet-des-endpoints)
8. [Patterns de communication](#8-patterns-de-communication)
9. [Architecture de déploiement](#9-architecture-de-déploiement)
10. [Feuille de route de développement](#10-feuille-de-route-de-développement)
11. [Observabilité](#11-observabilité)
12. [Résilience et tolérance aux pannes](#12-résilience-et-tolérance-aux-pannes)
13. [Compléments architecturaux](#13-compléments-architecturaux)

---

## 1. Stack technologique

### Justification des choix

| Composant | Langage / Technologie | Justification |
|-----------|----------------------|---------------|
| **Agent** | Go 1.23 | Binaire statique, faible empreinte mémoire, compilation conditionnelle par OS via build tags (`//go:build linux\|windows\|darwin`). Un seul codebase, un binaire par plateforme. |
| **Platform drivers** | Go (build tags) | Chaque OS fournit son `PlatformDriver` : Linux (eBPF/auditd/fanotify), Windows (ETW/WinLog/Registry), macOS (EndpointSecurity/FSEvents). Compilés séparément, interface commune. |
| **eBPF programs** | C (compilé via `clang/llvm`) | Linux uniquement. Seul langage supporté par le kernel verifier. Chargé par le loader Go. |
| **Hash chain** | Go — zeebo/blake3 (asm AVX2) | 428 MB/s sur i7-8665U. **Rust/FFI non justifié** — 5× marge vs cible 500 MB/s. Zéro CGO. |
| **Signatures batch** | Go — crypto/ed25519 stdlib | 43.7 µs/sign → 22 900 signs/s. **Rust/FFI non justifié** — 11 450× marge vs cible 2 signs/s. |
| **Buffer offline** | Go — dual build : `mattn/go-sqlite3` CGO (prod) + `modernc/sqlite` pure-Go (CI) | mattn+WAL : 14 ms/1000 events. modernc : 34 ms (fallback CI cross-platform CGO_ENABLED=0). |
| **Server** | Python 3.12 | Richesse de l'écosystème ML/data, FastAPI async natif, code expressif pour les moteurs de règles |
| **API** | FastAPI + Uvicorn (asyncio) | OpenAPI auto-généré, type hints stricts, performances proches de Node.js |
| **Event Bus** | Interface interne → Redis Streams (multi-process) → Kafka (distribué) | Migration transparente grâce au pattern Adapter |
| **ML** | scikit-learn + River (online learning) | River pour le baseline online (pas de batch retraining nécessaire), scikit pour les classifiers offline |
| **Base de données events** | ClickHouse | Insertion colonaire >1M events/s, compression 10x, agrégats temps-réel |
| **Base de données relationnelle** | PostgreSQL 16 | ACID, JSONB, partitionnement natif, excellent pour alerts/cases/decisions |
| **Dev/test** | SQLite (aiosqlite async) | Zero-config, même interface repository, CI rapide |
| **Sérialisation** | Protocol Buffers v3 | Schéma strict, 5-10x plus compact que JSON, génération de code Go+Python |
| **Transport agent↔server** | gRPC + mTLS | Streaming bidirectionnel, multiplexage HTTP/2, certificats client |
| **UI** | React 18 + TypeScript + Vite | Typage fort, recharts/d3 pour les graphes, tailwindcss |
| **ORM server** | SQLAlchemy 2.0 (async) + Alembic | Repository pattern propre, migrations versionnées |
| **Validation** | Pydantic v2 | Zéro overhead, validation stricte des events à l'entrée |
| **CI/CD** | GitHub Actions | Lint → test → build → push image. Matrix build : `linux/amd64`, `linux/arm64`, `windows/amd64`, `darwin/amd64`, `darwin/arm64` |
| **Packaging** | FPM (.deb/.rpm), NSIS/MSI (Windows), pkg (macOS), Docker multi-arch, Helm | Couverture maximale des cibles de déploiement |

### Décision multi-langage (validée par benchmarks 2026-08-06)

L'architecture reste **Go + Python uniquement**. Rust et C ne sont pas intégrés dans le chemin chaud :

- **BLAKE3** : zeebo/blake3 (asm natif Go) offre 5× de marge — Rust crate serait 30% plus rapide mais ne justifie pas la complexité FFI.
- **Ed25519** : stdlib Go suffisant à 11 450× de marge. dalek (Rust) n'est pas justifié.
- **SQLite buffer** : seul point CGO — `mattn/go-sqlite3` pour le runtime prod, `modernc` pour CI. C'est le **seul franchissement de barrière CGO** dans l'agent, et il se fait par batch (non par event).
- **Règle absolue** : ne jamais traverser CGO par event (overhead ~80 ns × 500k events/s = 4% CPU). Toujours par batch.

---

## 2. Structure du monorepo

```
oseye/
├── proto/                          # Définitions Protobuf partagées
│   ├── event.proto                 # UniversalEvent — source de vérité
│   ├── agent.proto                 # Service gRPC agent↔server
│   └── decision.proto              # Decision, Alert
│
├── agent/                          # Binaire Go — déployé sur chaque machine surveillée
│   ├── cmd/oseye-agent/
│   │   └── main.go                 # Entry point unique ; plateforme résolue à l'exécution
│   ├── internal/
│   │   ├── platform/               # *** Couche d'abstraction plateforme ***
│   │   │   ├── interface.go        # PlatformDriver interface + RawEvent
│   │   │   ├── registry.go         # Registre des drivers disponibles (auto-enregistrement)
│   │   │   ├── linux/              # build tag: //go:build linux
│   │   │   │   ├── driver.go       # LinuxDriver — implémente PlatformDriver
│   │   │   │   ├── ebpf/           # eBPF loader + programs C
│   │   │   │   │   ├── loader.go
│   │   │   │   │   └── programs/
│   │   │   │   │       ├── execve.c
│   │   │   │   │       ├── openat.c
│   │   │   │   │       ├── connect.c
│   │   │   │   │       └── ...
│   │   │   │   ├── auditd/
│   │   │   │   ├── fanotify/
│   │   │   │   ├── inotify/
│   │   │   │   ├── procfs/
│   │   │   │   ├── netlink/
│   │   │   │   ├── journald/
│   │   │   │   ├── udev/
│   │   │   │   └── syslog/
│   │   │   ├── windows/            # build tag: //go:build windows
│   │   │   │   ├── driver.go       # WindowsDriver — implémente PlatformDriver
│   │   │   │   ├── etw/            # Event Tracing for Windows
│   │   │   │   │   └── consumer.go
│   │   │   │   ├── winlog/         # Windows Event Log (Security, System, Application)
│   │   │   │   │   └── reader.go
│   │   │   │   ├── registry/       # Surveillance modifications registre
│   │   │   │   │   └── watcher.go
│   │   │   │   ├── wmi/            # WMI process/network info
│   │   │   │   │   └── query.go
│   │   │   │   └── sysmon/         # Parsing events Sysmon (si installé)
│   │   │   │       └── parser.go
│   │   │   └── darwin/             # build tag: //go:build darwin
│   │   │       ├── driver.go       # DarwinDriver — implémente PlatformDriver
│   │   │       ├── endpoint_security/ # Apple EndpointSecurity framework
│   │   │       │   └── client.go
│   │   │       ├── fsevents/       # FSEvents file monitoring
│   │   │       │   └── watcher.go
│   │   │       ├── openBSM/        # OpenBSM audit trail
│   │   │       │   └── reader.go
│   │   │       └── unified_log/    # Unified Logging System (os_log)
│   │   │           └── reader.go
│   │   ├── collector/
│   │   │   ├── interface.go        # interface Collector (OS-agnostique)
│   │   │   └── manager.go          # CollectorManager — lifecycle, hot-reload profile
│   │   ├── chain/
│   │   │   ├── chain.go            # BLAKE3 hash chain (zeebo/blake3 asm AVX2)
│   │   │   └── chain_bench_test.go # Benchmarks : 428 MB/s sur 1 KB
│   │   ├── signer/
│   │   │   ├── signer.go           # Ed25519 stdlib — Sign/PublicKey/NewEphemeral
│   │   │   └── signer_bench_test.go
│   │   ├── buffer/
│   │   │   ├── buffer.go           # SQLite offline pure-Go (//go:build !cgo)
│   │   │   ├── buffer_cgo.go       # SQLite offline mattn+WAL (//go:build cgo)
│   │   │   └── buffer_bench_test.go
│   │   ├── transport/
│   │   │   └── grpc_client.go      # gRPC streaming vers server
│   │   ├── policy/
│   │   │   └── receiver.go         # Réception et application des profils
│   │   ├── watchdog/
│   │   │   └── resource.go         # CPU/mem self-monitoring, throttling adaptatif
│   │   └── config/
│   │       └── config.go
│   ├── go.mod
│   └── Dockerfile                  # Multi-stage ; ARG TARGETOS/TARGETARCH
│
├── server/                         # Service Python — traitement, corrélation, API
│   ├── oseye/
│   │   ├── core/
│   │   │   ├── schema.py           # Modèles Pydantic (UniversalEvent, Alert, Decision...)
│   │   │   ├── constants.py        # Enums, severity levels, categories
│   │   │   └── observability.py    # Setup OTel + logger structuré JSON
│   │   ├── bus/
│   │   │   ├── interface.py        # Protocol EventBus (publish/subscribe/subscribe_pattern)
│   │   │   ├── memory_bus.py       # InMemoryEventBus — asyncio.Queue, eager subscription
│   │   │   ├── redis_bus.py        # RedisEventBus — XADD/XREADGROUP Streams
│   │   │   ├── factory.py          # create_bus(settings) → EventBus
│   │   │   └── kafka.py            # KafkaBus (Phase 4+, non implémenté)
│   │   ├── ingest/
│   │   │   ├── grpc_service.py     # Réception events depuis agents (gRPC)
│   │   │   └── validator.py        # Vérification signature, hash chain
│   │   ├── normalizer/
│   │   │   ├── engine.py           # NormalizerEngine — dispatche par source
│   │   │   ├── secret_masker.py    # Regex masking de credentials
│   │   │   └── adapters/
│   │   │       ├── ebpf.py
│   │   │       ├── auditd.py
│   │   │       ├── fanotify.py
│   │   │       ├── inotify.py
│   │   │       ├── procfs.py
│   │   │       ├── netlink.py
│   │   │       ├── journald.py
│   │   │       ├── udev.py
│   │   │       └── syslog.py
│   │   ├── rule_engine/
│   │   │   ├── engine.py           # RuleEngine — évaluation, hot-reload
│   │   │   ├── parser.py           # Lecture YAML/TOML
│   │   │   ├── evaluator.py        # Évaluateur d'expressions + fenêtres temporelles
│   │   │   └── builtin_rules/      # 30+ règles YAML intégrées
│   │   ├── ml_engine/
│   │   │   ├── engine.py           # MLEngine — façade, score = 0.7×anomaly + 0.3×classifier
│   │   │   ├── features.py         # FeatureExtractor — vecteur 10-dim [0,1] depuis UniversalEvent
│   │   │   ├── anomaly.py          # EntityAnomalyDetector — HalfSpaceTrees River, LRU 10k modèles
│   │   │   └── classifier.py       # MITREClassifier — LogisticRegression online par technique
│   │   ├── threat_intel/
│   │   │   ├── engine.py           # TIEngine — enrichissement events
│   │   │   ├── cache.py            # Cache Redis/local
│   │   │   ├── scheduler.py        # Refresh périodique des feeds
│   │   │   └── providers/
│   │   │       ├── abuseipdb.py
│   │   │       ├── virustotal.py
│   │   │       ├── misp.py
│   │   │       ├── stix_taxii.py
│   │   │       └── alienvault.py
│   │   ├── correlation/
│   │   │   ├── engine.py           # CorrelationEngine
│   │   │   ├── graph.py            # Graphe d'incidents (rustworkx)
│   │   │   ├── linkers/
│   │   │   │   ├── pid_ppid.py     # Liens process parent/enfant
│   │   │   │   ├── resource.py     # Liens par ressource cible
│   │   │   │   ├── user.py         # Liens par uid/session
│   │   │   │   └── temporal.py     # Fenêtre temporelle configurable
│   │   │   └── chain_builder.py    # IncidentChain depuis le graphe
│   │   ├── decision/
│   │   │   ├── engine.py           # DecisionEngine
│   │   │   ├── risk_matrix.py      # Matrice risque×décision
│   │   │   ├── weighted_scorer.py  # Agrégation Rule+ML+TI+Correlation
│   │   │   ├── journal.py          # Journal immutable (hash chain)
│   │   │   ├── human_queue.py      # Queue d'approbation humaine + timeout
│   │   │   └── action_executor.py  # Exécution des 8 types de décisions
│   │   ├── forensic/
│   │   │   ├── engine.py           # ForensicEngine
│   │   │   ├── snapshot.py         # Capture et diff snapshots système
│   │   │   ├── case_manager.py     # CRUD cases + custody log
│   │   │   ├── timeline.py         # Reconstruction chronologique
│   │   │   └── exporter/
│   │   │       ├── json_export.py
│   │   │       ├── html_report.py
│   │   │       ├── pdf_report.py
│   │   │       ├── misp_export.py
│   │   │       └── thehive_export.py
│   │   ├── policy/
│   │   │   ├── engine.py           # PolicyEngine
│   │   │   ├── schema.py           # SurveillanceProfile dataclass
│   │   │   └── profiles/           # 6 profils YAML intégrés
│   │   │       ├── webserver.yaml
│   │   │       ├── database.yaml
│   │   │       ├── workstation.yaml
│   │   │       ├── fileserver.yaml
│   │   │       ├── container.yaml
│   │   │       └── investigation.yaml
│   │   ├── plugin/
│   │   │   ├── manager.py          # PluginManager — lifecycle, sandbox
│   │   │   ├── verifier.py         # Vérification signature ed25519
│   │   │   ├── sandbox.py          # Isolation subprocess + cgroups v2
│   │   │   └── interface.py        # Plugin ABC (on_load, on_event, on_unload)
│   │   ├── storage/
│   │   │   ├── interface.py        # Repository Protocols + Page[T] + EventFilter
│   │   │   ├── models.py           # ORM SQLAlchemy déclaratif (8 tables)
│   │   │   ├── router.py           # StorageRouter : PG relations, CH events volumétrie
│   │   │   ├── migrations/
│   │   │   │   └── __init__.py     # run_migrations() + triggers immuabilité PG (SEC-0002)
│   │   │   ├── backends/
│   │   │   │   ├── sqlite.py       # SQLiteBackend async (aiosqlite)
│   │   │   │   ├── postgresql.py   # (Phase 2+)
│   │   │   │   └── clickhouse.py   # (Phase 4+)
│   │   │   └── repositories/
│   │   │       ├── events.py       # SQLEventRepository — insert_batch, query, count
│   │   │       ├── alerts.py       # SQLAlertRepository
│   │   │       ├── decisions.py    # SQLDecisionRepository — append-only
│   │   │       ├── cases.py        # SQLCaseRepository — custody append-only
│   │   │       ├── rule_repo.py    # (Phase 3+)
│   │   │       └── entity_repo.py  # (Phase 6+)
│   │   ├── audit/
│   │   │   ├── logger.py           # AuditLogger — append-only, structuré JSON
│   │   │   └── middleware.py       # FastAPI middleware : log chaque requête API
│   │   ├── api/
│   │   │   ├── app.py              # FastAPI app factory
│   │   │   ├── auth/
│   │   │   │   ├── jwt.py          # JWT RS256 issue/verify/refresh
│   │   │   │   ├── api_keys.py     # API key hashing + lookup
│   │   │   │   └── rbac.py         # Dépendances FastAPI par rôle
│   │   │   ├── ws/
│   │   │   │   └── manager.py      # WebSocketManager — broadcast
│   │   │   └── routers/
│   │   │       ├── auth.py
│   │   │       ├── events.py
│   │   │       ├── alerts.py
│   │   │       ├── rules.py
│   │   │       ├── decisions.py
│   │   │       ├── cases.py
│   │   │       ├── snapshots.py
│   │   │       ├── entities.py
│   │   │       ├── policies.py
│   │   │       ├── agents.py
│   │   │       ├── plugins.py
│   │   │       └── health.py
│   │   └── config.py               # Settings (pydantic-settings, env vars)
│   ├── workers/
│   │   ├── rule_worker.py          # Entry point : python -m oseye.workers.rule_worker
│   │   ├── ml_worker.py            # Entry point : python -m oseye.workers.ml_worker
│   │   ├── ti_worker.py            # Entry point : python -m oseye.workers.ti_worker
│   │   ├── correlation_worker.py   # Entry point : python -m oseye.workers.correlation_worker
│   │   └── decision_worker.py      # Entry point : python -m oseye.workers.decision_worker
│   ├── tests/
│   │   ├── unit/
│   │   │   ├── test_schema_completeness.py  # 15 tests Pydantic
│   │   │   ├── test_bus.py                  # 9 tests InMemoryEventBus
│   │   │   └── test_storage.py              # 16 tests repositories SQLite :memory:
│   │   ├── benchmarks/
│   │   │   └── bench_storage.py             # insert_batch, event↔row conversion
│   │   ├── integration/
│   │   └── scenarios/              # Scénarios d'attaques de référence (Phase 3+)
│   ├── pyproject.toml
│   └── Dockerfile
│
├── sdk/                            # Plugin SDK — publié sur PyPI
│   ├── oseye_sdk/
│   │   ├── plugin.py               # Classes de base Plugin, Collector, Analyzer...
│   │   ├── event.py                # Modèle Event exposé aux plugins
│   │   └── ipc.py                  # Communication IPC plugin↔server
│   └── pyproject.toml
│
├── ui/                             # Dashboard React + TypeScript
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Events.tsx
│   │   │   ├── Alerts.tsx
│   │   │   ├── Decisions.tsx       # Journal + queue approbation humaine
│   │   │   ├── Cases.tsx
│   │   │   ├── Entities.tsx
│   │   │   ├── Rules.tsx
│   │   │   └── NetworkGraph.tsx    # Graphe de corrélation D3
│   │   ├── components/
│   │   ├── hooks/
│   │   │   └── useWebSocket.ts
│   │   ├── api/
│   │   │   └── client.ts           # API client typé (généré depuis OpenAPI)
│   │   └── stores/                 # Zustand stores
│   ├── package.json
│   └── Dockerfile
│
├── rules/                          # Règles de détection (versionnées dans git)
│   ├── builtin/
│   │   ├── ransomware.yaml
│   │   ├── privilege_escalation.yaml
│   │   ├── lateral_movement.yaml
│   │   └── ...
│   └── custom/                     # Règles ajoutées par l'opérateur
│
├── infra/
│   ├── docker/
│   │   ├── docker-compose.dev.yml
│   │   └── docker-compose.prod.yml
│   ├── k8s/
│   │   ├── agent/
│   │   │   └── daemonset.yaml
│   │   ├── server/
│   │   │   ├── deployment.yaml
│   │   │   └── hpa.yaml
│   │   ├── ui/
│   │   │   └── deployment.yaml
│   │   └── common/
│   │       ├── networkpolicy.yaml
│   │       └── certmanager.yaml
│   ├── helm/
│   │   └── oseye/
│   └── ansible/
│       └── deploy.yml
│
├── scripts/
│   ├── generate_proto.sh           # Génère Go+Python depuis proto/
│   ├── generate_certs.sh           # PKI interne dev (CA + server + agent)
│   └── benchmark.sh
│
├── docs/
│   └── openapi/                    # Export OpenAPI auto-généré
│
└── .github/
    └── workflows/
        ├── ci.yml                  # lint + test + build
        └── release.yml             # tag → push Docker images + packages
```

---

## 3. Architecture des composants

### 3.1 Agent (Go)

Le cœur de l'agent est **OS-agnostique**. Toute la logique de collecte spécifique à un OS est encapsulée dans un `PlatformDriver`, sélectionné automatiquement à la compilation via build tags Go.

```
main.go
 └── platform.Registry.Resolve()   ← sélectionne LinuxDriver | WindowsDriver | DarwinDriver
          ↓
     PlatformDriver.Collectors()   ← retourne la liste des Collector disponibles sur cet OS
          ↓
CollectorManager
 ├── [Collector interface]
 │     Linux   : eBPFCollector, AuditdCollector, FanotifyCollector, InotifyCollector,
 │               ProcfsCollector, NetlinkCollector, JournaildCollector, UdevCollector, SyslogCollector
 │     Windows : ETWCollector, WinLogCollector, RegistryCollector, WMICollector, SysmonCollector
 │     macOS   : EndpointSecurityCollector, FSEventsCollector, OpenBSMCollector, UnifiedLogCollector
 │
 │           ↓ chan RawEvent  (format identique quel que soit l'OS)
HashChainer (BLAKE3, per-event)
 │           ↓ chan RawEvent (avec hash_chain)
LocalBuffer (SQLite — queue offline)
 │           ↓ batch de N events
BatchSigner (Ed25519 — toutes les 1000 events ou 1s)
 │           ↓ IngestRequest (Protobuf)
GRPCClient ──→ server:50051 (mTLS)
 │
ResourceWatchdog ──→ throttle les collectors si CPU >4%
PolicyReceiver ──→ reçoit SurveillanceProfile, active/désactive collectors
```

**Interface PlatformDriver (Go) :**

```go
// agent/internal/platform/interface.go

// PlatformDriver est le point d'entrée OS-spécifique.
// Chaque OS implémente cette interface dans son sous-package.
type PlatformDriver interface {
    // Name retourne l'identifiant de la plateforme ("linux", "windows", "darwin").
    Name() string

    // Collectors instancie et retourne tous les collectors disponibles sur cette plateforme.
    // Le CollectorManager ne connaît que cette liste — pas les types concrets.
    Collectors(cfg *config.Config) ([]collector.Collector, error)

    // Capabilities décrit ce que ce driver peut faire (pour le SurveillanceProfile).
    Capabilities() PlatformCapabilities
}

type PlatformCapabilities struct {
    HasKernelTracing  bool   // eBPF (Linux), ETW (Windows), EndpointSecurity (macOS)
    HasFileAudit      bool
    HasNetworkAudit   bool
    HasRegistryAudit  bool   // Windows uniquement
    HasContainerAware bool   // si le driver sait lire les namespaces/cgroups
    MaxCollectors     int
}
```

**Interface Collector (Go) — inchangée, OS-agnostique :**

```go
// agent/internal/collector/interface.go
type Collector interface {
    Name() string
    Start(ctx context.Context, out chan<- RawEvent) error
    Stop() error
    SetThrottle(factor float64) // 0.0 = stop, 1.0 = full speed
    Health() CollectorHealth
}

type RawEvent struct {
    Source    string
    Timestamp int64  // nanoseconds monotonic
    Raw       []byte // payload brut (JSON ou binaire selon collector)
    OS        string // "linux" | "windows" | "darwin" — positionné par le driver
}
```

**Registre des drivers (auto-enregistrement via `init()`) :**

```go
// agent/internal/platform/registry.go
var registry = map[string]PlatformDriver{}

func Register(d PlatformDriver) { registry[d.Name()] = d }

func Resolve() (PlatformDriver, error) {
    d, ok := registry[runtime.GOOS]
    if !ok {
        return nil, fmt.Errorf("no platform driver for %s", runtime.GOOS)
    }
    return d, nil
}

// agent/internal/platform/linux/driver.go
// //go:build linux
func init() { platform.Register(&LinuxDriver{}) }

// agent/internal/platform/windows/driver.go
// //go:build windows
func init() { platform.Register(&WindowsDriver{}) }
```

### 3.2 Normalizer (Python)

```python
# server/oseye/normalizer/engine.py
class NormalizerEngine:
    adapters: dict[str, BaseAdapter]  # source -> adapter

    async def process(self, raw: RawEvent) -> UniversalEvent:
        adapter = self.adapters[raw.source]
        event = adapter.parse(raw)
        event = self.secret_masker.mask(event)
        event.event_id = uuid7()
        return event
```

Chaque `BaseAdapter` implémente `parse(raw: RawEvent) -> UniversalEvent`.

**Améliorations Phase 6 (2026-08-09) :**

- **`register_package(package_path)`** — découverte automatique des adapters dans un package Python (scan du répertoire, import dynamique) ; permet d'enregistrer les adapters Windows/macOS sans les lister explicitement
- **Dead-letter queue** — en cas d'échec `publish()`, l'event est envoyé sur le topic `events:dead_letter` plutôt que silencieusement ignoré
- **Validation des champs** — `timestamp_ns` doit être >0, `bytes_sent`/`bytes_recv` doivent être ≥0, les ports doivent être dans [0, 65535] ; les events invalides sont rejetés avec un log structuré

Le champ `raw.OS` détermine quelle famille d'adapters est utilisée :

```
NormalizerEngine.adapters:
  Linux   : ebpf, auditd, fanotify, inotify, procfs, netlink, journald, udev, syslog
  Windows : etw, winlog_security, winlog_system, registry, wmi, sysmon
  macOS   : endpoint_security, fsevents, openbsm, unified_log
```

Les adapters Windows et macOS sont livrés dans des packages optionnels (`server/oseye/normalizer/adapters/windows/`, `darwin/`) et enregistrés dynamiquement au démarrage selon les sources présentes dans le flux entrant.

### 3.3 Event Bus

```python
# server/oseye/bus/interface.py
from typing import Protocol, AsyncGenerator

class EventBus(Protocol):
    async def publish(self, topic: str, message: bytes) -> None: ...
    async def subscribe(self, topic: str) -> AsyncGenerator[bytes, None]: ...
    async def subscribe_pattern(self, pattern: str) -> AsyncGenerator[tuple[str, bytes], None]: ...
```

**Topics utilisés :**

| Topic | Producteur | Consommateurs |
|-------|-----------|---------------|
| `events:raw:{agent_id}` | gRPC service | Normalizer |
| `events:normalized` | Normalizer | Rule Engine, ML Engine, TI Engine, Storage Writer |
| `events:enriched` | TI Engine | Correlation Engine |
| `analysis:rules:{host}` | Rule Engine | Correlation Engine |
| `analysis:ml` | ML Engine | Correlation Engine |
| `analysis:correlated` | Correlation Engine | Decision Engine |
| `decisions:completed` | Decision Engine | Action Executor, WS Manager |
| `decisions:pending` | Decision Engine | Human Queue, WS Manager |
| `policy:push:{agent_id}` | Policy Engine | Agent (via gRPC reverse stream) |

### 3.4 Rule Engine

```python
class RuleEngine:
    rules: list[Rule]           # hot-reloadées via watchdog fichier
    temporal_store: dict        # fenêtres temporelles en mémoire
    _dispatch_index: dict       # index par catégorie → O(règles_catégorie) au lieu de O(total)

    async def evaluate(self, event: UniversalEvent) -> list[RuleMatch]:
        ...
```

**Améliorations Phase 6 (2026-08-09) :**

- **Hot-reload watchdog** : inotify avec fallback polling — rechargement des règles sans redémarrage
- **Index de dispatch par `categories`** : chaque règle déclare ses catégories d'intérêt ; l'évaluation ne parcourt que les règles pertinentes — O(règles_catégorie) au lieu de O(total)
- **Persistance fenêtres temporelles** : `save_temporal_state()` / `load_temporal_state()` — JSON atomique via `os.replace`, pas pickle (sécurité RCE). Redémarrage sans perte des fenêtres glissantes.
- **`entity_key` stable** : `hostname:session_id:pid` ou `hostname:ppid:pid` comme fallback (PID reuse guard) — les règles temporelles ne confondent plus deux processus différents ayant eu le même PID
- **Nouveau champ `categories`** dans `RuleDefinition` et le parser YAML

**Format de règle YAML :**

```yaml
id: "rule_shadow_read"
name: "Lecture de /etc/shadow"
severity: critical
tags: [privilege_escalation, credential_access]
mitre: [T1003.008]
condition: |
  event.category == "file"
  and event.type == "read"
  and event.resource == "/etc/shadow"
  and event.uid != 0
timeframe: null
actions: [ALERT, INVESTIGATE]
explanation: "Tentative de lecture du fichier shadow hors root — vol de credentials probable"
```

### 3.5 ML Engine

**Architecture (Phase 6, 2026-08-09) :**

```
ml_engine/features.py — FeatureExtractor
 ↓  vecteur 10 dimensions [0,1] depuis UniversalEvent
    (ratio catégories, bytes réseau normalisés, uid==0, heure du jour, etc.)

ml_engine/anomaly.py — EntityAnomalyDetector
 ├── HalfSpaceTrees (River, online learning) — par hostname×category
 ├── LRU cap : max_models=10 000 (_LRUStore) — borne mémoire
 ├── window_size_by_category : override de la fenêtre par catégorie d'événement
 ├── Decaying-max normalisation (decay 0.1%/event) — scores toujours en [0,1]
 └── save() / load() pickle — persistance des baselines entre redémarrages

ml_engine/classifier.py — MITREClassifier
 ├── LogisticRegression online (River) — un modèle par technique MITRE
 ├── Entraîné sur alertes confirmées (feedback loop)
 └── Prédit les techniques les plus probables pour un vecteur de features

ml_engine/engine.py — MLEngine (façade)
 └── ml_score = 0.7 × anomaly_score + 0.3 × classifier_score
```

**Câblage avec le Decision Engine :**

- `DecisionEngine.__init__()` accepte un paramètre optionnel `ml_engine: MLEngine`
- `DecisionEngine.decide()` accepte un paramètre `trigger_event: UniversalEvent | None`
- Si `ml_engine` et `trigger_event` sont fournis, le score ML est calculé à la volée depuis l'event déclencheur
- `DecisionWorker` charge le `trigger_event` depuis `event_repo` avant d'appeler `decide()`

**35 tests dans `tests/unit/test_ml_engine.py`.**

### 3.6 Threat Intelligence Engine

```
TIEngine.enrich(event) → EnrichedEvent
 ├── IPReputation (AbuseIPDB, GreyNoise) — si event.category == "network"
 ├── HashReputation (VirusTotal, MalwareBazaar) — si event.category == "file" et hash présent
 └── IOCMatcher (base locale STIX/TAXII + MISP) — tous events

Cache Redis : TTL 1h pour IPs, 24h pour hashes, 6h pour IOCs
```

### 3.7 Correlation Engine

```
CorrelationEngine
 ├── EventGraph (rustworkx DiGraph)
 │    Noeuds : events (event_id)
 │    Arêtes : liens typés (PARENT_PROCESS, SAME_RESOURCE, SAME_USER, TEMPORAL)
 ├── Linkers (appelés à chaque event enrichi)
 │    ├── PidPpidLinker   — relie event au parent process
 │    ├── ResourceLinker  — relie events sur même resource (fenêtre 60s)
 │    ├── UserLinker      — relie events du même uid/session
 │    └── TemporalLinker  — relie events proches dans le temps (configurable)
 └── ChainBuilder
      → extrait IncidentChain (sous-graphe connexe) depuis un event racine
```

**Améliorations Phase 6 (2026-08-09) :**

- **Score-based linker** : chaque linker expose une méthode `score() → float [0,1]`. Le moteur retient l'incident avec le meilleur score (remplace le comportement "premier gagnant"). `SameHostLinker.score()` intègre un bonus en cas de chevauchement MITRE entre l'alerte et l'incident.
- **Multi-incident par host** : `find_open_incidents_for_host()` retourne désormais plusieurs incidents ouverts pour un même hôte — une alerte peut être corrélée à l'incident le plus pertinent plutôt qu'au premier trouvé.
- **Auto-close des incidents** : `close_stale_incidents()` ferme automatiquement les incidents sans activité depuis `auto_close_after_seconds` (configurable). Appelé périodiquement par le CorrelationWorker.
- **Guard linkers vides** : `CorrelationEngine.__init__()` lève `ValueError` si `linkers=[]` — évite une erreur silencieuse à l'évaluation.
- **`alert_ids.append()`** : lors du linkage d'une alerte à un incident existant, l'`alert_id` est correctement ajouté à `incident.alert_ids` (F-08 corrigé).

### 3.8 Decision Engine

```
DecisionEngine(ml_engine: MLEngine | None = None)

DecisionEngine.decide(
    correlated: CorrelatedIncident,
    trigger_event: UniversalEvent | None = None
) → Decision
 │
 ├── MLEngine (si fourni + trigger_event disponible)
 │    ml_score calculé à la volée depuis l'event déclencheur
 │    ml_score = 0.7 × anomaly_score + 0.3 × classifier_score
 │
 ├── WeightedScorer
 │    score = (rule_score × 0.4) + (ml_score × 0.3) + (ti_score × 0.2) + (correlation_depth × 0.1)
 │
 ├── RiskMatrix
 │    0–20  → IGNORE
 │    21–40 → ESCALATE
 │    41–60 → ALERT + INVESTIGATE
 │    61–80 → ALERT + ISOLATE
 │    81–100 → ALERT + ISOLATE + REQUEST_HUMAN
 │
 ├── PolicyOverrides  — whitelist, exceptions opérateur
 │
└── DecisionJournal  — append-only, hash chain BLAKE3, signé Ed25519
```

Le `DecisionWorker` charge le `trigger_event` depuis `event_repo` (via `trigger_alert.trigger_event_id`) avant d'appeler `decide()`, afin que le score ML soit calculé sur l'événement réel et non estimé.

### 3.9 Storage — Repository Pattern

```python
# server/oseye/storage/interface.py
class EventRepository(Protocol):
    async def insert_batch(self, events: list[UniversalEvent]) -> None: ...
    async def get(self, event_id: UUID) -> UniversalEvent | None: ...
    async def query(self, filters: EventFilter, pagination: Pagination) -> Page[UniversalEvent]: ...
    async def count(self, filters: EventFilter) -> int: ...
```

Chaque backend (SQLite, PostgreSQL, ClickHouse) implémente ce Protocol. Aucun composant métier n'importe jamais directement un backend.

### 3.10 StorageRouter — routage des écritures

Deux backends coexistent en production. Le `StorageRouter` détermine où écrire :

| Donnée | Backend | Raison |
|--------|---------|--------|
| `UniversalEvent` (volume) | ClickHouse | Insertion colonaire >1M/s, TTL natif, agrégats temps-réel |
| `UniversalEvent` (query par ID) | PostgreSQL | Clé primaire UUID, lookup O(1) |
| `Alert`, `Decision`, `ForensicCase` | PostgreSQL uniquement | ACID, relations, FK, triggers immuabilité |
| `EntityProfile`, `Rule`, `Agent` | PostgreSQL uniquement | Données relationnelles, faible volume |
| `TI cache` | Redis (TTL) puis PostgreSQL (persistence) | Lecture ultra-rapide, durée de vie contrôlée |

```python
# server/oseye/storage/router.py
class StorageRouter:
    def __init__(self, pg: EventRepository, ch: EventRepository | None):
        self._pg = pg
        self._ch = ch  # None en mode SQLite/dev

    async def insert_events(self, events: list[UniversalEvent]) -> None:
        if self._ch:
            await self._ch.insert_batch(events)   # écriture primaire haute volumétrie
        await self._pg.insert_batch(events)        # copie pour lookup par ID
```

En mode dev (`OSEYE_DB_BACKEND=sqlite`), seul le backend SQLite est actif — `_ch` est `None`.

### 3.11 Workers — entry points séparés

Chaque worker est un processus Python indépendant, lancé via `python -m oseye.workers.<name>`.  
Ils partagent le même code source mais sont **stateless** (sauf `ml_worker` et `decision_worker`).

```
oseye-worker-rule       subscribe events:normalized → publie analysis:rules:{host}
oseye-worker-ml         subscribe events:normalized → publie analysis:ml        [stateful: modèles River]
oseye-worker-ti         subscribe events:normalized → publie events:enriched
oseye-worker-correlation subscribe analysis:* + events:enriched → publie analysis:correlated
oseye-worker-decision   subscribe analysis:correlated → publie decisions:*      [stateful: journal hash]
```

En dev (`docker-compose.dev.yml`), tous les workers tournent dans le même conteneur `oseye-server` via `asyncio.gather`. En prod (K8s), chaque worker est un `Deployment` séparé avec son propre HPA.

Démarrage dev :
```python
# server/oseye/core/runner.py — mode monolithe (dev uniquement)
async def run_all():
    await asyncio.gather(
        run_api_server(),
        run_grpc_server(),
        RuleWorker().run(),
        MLWorker().run(),
        TIWorker().run(),
        CorrelationWorker().run(),
        DecisionWorker().run(),
    )
```

---

## 4. Modèles de données

### 4.1 Universal Event Schema

```python
# server/oseye/core/schema.py

class UniversalEvent(BaseModel):
    # Identité
    event_id: UUID          # UUID v7 (monotone, ordonnable par temps)
    timestamp_ns: int       # Horloge monotone nanoseconde
    hostname: str
    agent_id: UUID

    # Classification
    category: Literal["file", "process", "network", "user", "device"]
    type: str               # ex: "exec", "open", "connect", "login"
    severity: Literal["info", "low", "medium", "high", "critical"]
    collector: str          # "ebpf" | "auditd" | "fanotify" | ...

    # Identité du sujet
    uid: int
    gid: int
    pid: int
    ppid: int
    process_name: str
    executable: str
    cmdline: str
    cwd: str
    session_id: int | None

    # Ressource cible
    resource: str           # chemin, adresse IP:port, device path...
    result: str             # "success" | "denied" | "error"

    # Hashes (fichiers)
    file_hash_before: str | None    # SHA-256
    file_hash_after: str | None     # SHA-256

    # Réseau
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    bytes_sent: int | None
    bytes_recv: int | None

    # Intégrité
    hash_chain: str         # BLAKE3 du contenu + hash précédent
    signature: str | None   # Ed25519 (sur batches)

    # Enrichissements (ajoutés par server)
    ml_score: float | None           # 0–100
    risk_score: float | None         # 0–100
    rule_match_ids: list[str]
    mitre_techniques: list[str]
    ti_tags: list[str]               # ex: ["ip:malicious", "hash:malware"]
    incident_chain_id: UUID | None

    # Extra
    extra: dict = {}
```

### 4.2 Alert

```python
class Alert(BaseModel):
    alert_id: UUID
    created_at: datetime
    updated_at: datetime

    severity: Literal["low", "medium", "high", "critical"]
    status: Literal["open", "acknowledged", "investigating", "resolved", "false_positive"]

    rule_id: str | None
    ml_triggered: bool
    ti_triggered: bool

    entity_id: str          # "process:{hostname}:{pid}" | "user:{uid}" | ...
    hostname: str

    trigger_event_id: UUID
    related_event_ids: list[UUID]
    incident_chain_id: UUID | None

    title: str
    description: str
    mitre_techniques: list[str]

    assigned_to: str | None
    notes: list[AlertNote]

    false_positive_count: int    # feedback loop règles
```

### 4.3 Decision

```python
class Decision(BaseModel):
    decision_id: UUID
    created_at: datetime

    decision_type: Literal[
        "ALERT", "IGNORE", "ESCALATE", "INVESTIGATE",
        "ISOLATE", "REQUEST_HUMAN", "COLLECT_MORE", "NOTIFY"
    ]

    # Signaux d'entrée
    rule_score: float
    ml_score: float
    ti_score: float
    correlation_depth: int
    final_score: float       # score agrégé [0–100]

    # Contexte
    entity_id: str
    trigger_alert_id: UUID | None
    incident_chain_id: UUID | None
    related_event_ids: list[UUID]

    # Politique appliquée
    policy_version: str
    explanation: str          # justification lisible par l'humain

    # Approbation humaine
    requires_human: bool
    human_decision: Literal["approved", "rejected"] | None
    human_operator: str | None
    human_note: str | None
    approved_at: datetime | None
    timeout_at: datetime | None

    # Journal immutable
    prev_journal_hash: str    # BLAKE3 de la décision précédente
    journal_hash: str         # BLAKE3 de cette entrée complète
```

### 4.4 ForensicCase

```python
class ForensicCase(BaseModel):
    case_id: UUID
    created_at: datetime
    updated_at: datetime

    title: str
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    status: Literal["open", "in_progress", "resolved", "archived"]
    tags: list[str]

    assigned_to: str | None
    created_by: str

    event_ids: list[UUID]
    alert_ids: list[UUID]
    evidence: list[EvidenceItem]
    notes: list[CaseNote]
    custody_log: list[CustodyEntry]   # immuable, append-only

class CustodyEntry(BaseModel):
    timestamp: datetime
    operator: str
    action: str             # "case_created", "event_added", "evidence_tagged"...
    detail: str
    hash: str               # BLAKE3 de l'entrée pour intégrité

class EvidenceItem(BaseModel):
    evidence_id: UUID
    type: Literal["event", "file_hash", "screenshot", "note", "external"]
    content: str
    description: str | None
    added_by: str
    added_at: datetime
    marked_as_evidence_at: datetime
```

### 4.5 Rule

```python
class Rule(BaseModel):
    id: str                  # ex: "rule_shadow_read"
    name: str
    enabled: bool
    severity: Literal["info", "low", "medium", "high", "critical"]
    condition_yaml: str      # expression évaluée sur UniversalEvent
    timeframe: int | None    # secondes pour règles temporelles
    actions: list[str]       # ["ALERT", "INVESTIGATE"]
    tags: list[str]
    mitre: list[str]         # ["T1003.008"]
    explanation: str

    # Statistiques (calculées)
    match_count: int
    last_matched: datetime | None
    false_positive_count: int
    source: Literal["builtin", "custom", "imported"]
```

### 4.6 EntityProfile

```python
class EntityProfile(BaseModel):
    entity_id: str           # "process:{hostname}:{name}" | "user:{hostname}:{uid}"
    entity_type: Literal["process", "user", "connection", "file"]
    hostname: str

    risk_score: float        # 0–100, mis à jour en temps réel
    baseline_score: float    # score ML baseline
    alert_count: int
    last_seen: datetime
    whitelisted: bool
    whitelist_expires_at: datetime | None

    risk_history: list[tuple[datetime, float]]  # pour le graphe d'évolution
```

### 4.7 SurveillanceProfile

```python
class CollectorConfig(BaseModel):
    enabled: bool = True
    throttle: float = 1.0           # 0.0 = inactif, 1.0 = pleine vitesse
    params: dict = {}               # paramètres spécifiques au collector

class SurveillanceProfile(BaseModel):
    name: str                       # ex: "webserver", "investigation"
    description: str
    version: int                    # incrémenté à chaque modification

    # Plateformes supportées par ce profil (vide = toutes)
    platforms: list[Literal["linux", "windows", "darwin"]] = []

    # Configuration par collector (clé = nom du collector)
    # Les collectors non disponibles sur l'OS courant sont ignorés silencieusement
    collectors: dict[str, CollectorConfig]

    # Filtres de réduction du bruit
    ignore_uids: list[int] = []         # ex: [0] pour ignorer root en mode silencieux
    ignore_paths_prefix: list[str] = [] # ex: ["/proc", "/sys"]
    ignore_processes: list[str] = []    # ex: ["kworker", "kswapd"]

    # Seuils de verbosité
    min_severity: Literal["info", "low", "medium", "high", "critical"] = "low"

    # Push config
    push_interval_s: int = 60          # fréquence de re-push vers les agents
    created_at: datetime
    updated_at: datetime
```

**Exemple `investigation.yaml` (profil haute verbosité) :**

```yaml
name: investigation
description: "Collecte maximale pour investigation d'incident actif"
version: 3
collectors:
  ebpf:     { enabled: true,  throttle: 1.0, params: { programs: [execve, openat, connect, unlink, rename] } }
  auditd:   { enabled: true,  throttle: 1.0 }
  fanotify: { enabled: true,  throttle: 1.0, params: { watch_paths: ["/", "/home", "/tmp", "/var"] } }
  inotify:  { enabled: true,  throttle: 1.0 }
  procfs:   { enabled: true,  throttle: 1.0, params: { interval_ms: 500 } }
  netlink:  { enabled: true,  throttle: 1.0 }
  journald: { enabled: true,  throttle: 1.0 }
  udev:     { enabled: true,  throttle: 0.5 }
  syslog:   { enabled: true,  throttle: 0.5 }
ignore_uids: []
ignore_paths_prefix: []
min_severity: info
```

**Exemple `workstation.yaml` (profil standard) :**

```yaml
name: workstation
description: "Surveillance équilibrée poste de travail"
version: 1
collectors:
  ebpf:     { enabled: true,  throttle: 1.0, params: { programs: [execve, connect] } }
  auditd:   { enabled: true,  throttle: 0.5 }
  fanotify: { enabled: false }
  inotify:  { enabled: true,  throttle: 0.3, params: { watch_paths: ["/etc", "/usr/bin"] } }
  procfs:   { enabled: true,  throttle: 0.5, params: { interval_ms: 2000 } }
  netlink:  { enabled: true,  throttle: 1.0 }
  journald: { enabled: true,  throttle: 0.5 }
  udev:     { enabled: false }
  syslog:   { enabled: false }
ignore_paths_prefix: ["/proc", "/sys", "/dev"]
min_severity: low
```

### 4.8 Syntaxe des conditions de règles

L'évaluateur supporte un sous-ensemble de Python safe-eval (via `asteval`) sur un objet `event: UniversalEvent`.

**Opérateurs disponibles :**

```yaml
# Comparaison
event.uid == 0
event.severity in ["high", "critical"]
event.category != "network"

# Chaînes
event.resource.startswith("/etc/")
event.process_name.endswith("sh")
event.cmdline contains "base64"
re.match(r".*\.(py|sh|rb)$", event.executable)

# Numérique
event.bytes_sent > 10_000_000
event.dst_port in [4444, 1337, 31337]

# Booléens combinés
event.category == "file" and event.type == "write" and event.uid != 0

# Règles temporelles (fenêtre glissante)
# Syntaxe : count_events(filter_expr, seconds) > threshold
count_events("event.category == 'network'", 60) > 100   # > 100 connexions en 60s
count_events("event.dst_ip == self.dst_ip", 10) > 5     # même IP, 5x en 10s
```

**Variables disponibles dans `condition` :**
- `event` — l'événement courant (`UniversalEvent`)
- `self` — alias de `event`
- `re` — module `re` Python (read-only)
- `count_events(filter, seconds)` — compte les events récents de la même entité matchant le filtre
- `event.platform` — `"linux"` | `"windows"` | `"darwin"` — permet d'écrire des règles cross-OS

**Règles ciblant un OS spécifique :**

```yaml
# Règle Linux uniquement
condition: |
  event.platform == "linux"
  and event.category == "file"
  and event.resource == "/etc/shadow"

# Règle Windows uniquement (registre de persistance)
condition: |
  event.platform == "windows"
  and event.category == "registry"
  and event.resource.startswith("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")

# Règle cross-OS (credential dumping)
condition: |
  event.category == "process"
  and (
    (event.platform == "linux" and event.executable contains "mimipenguin")
    or (event.platform == "windows" and event.process_name == "lsass.exe" and event.type == "memory_read")
    or (event.platform == "darwin" and event.executable contains "chainbreaker")
  )
```

---

## 5. Architecture de sécurité

### 5.1 PKI interne

```
Root CA (offline, air-gapped)
 └── Intermediate CA (oseye-ca)
      ├── server.crt        — API REST + gRPC (SAN: oseye-server, localhost)
      ├── agent-{id}.crt    — un certificat par agent (CN = agent_id)
      └── worker-*.crt      — workers internes

Durée de vie :
  Intermediate CA : 5 ans
  Server cert     : 1 an (rotation via cert-manager en K8s)
  Agent cert      : 90 jours (renouvellement automatique à 80% de la durée)

Enrollment agent :
  1. Admin génère un OTP à usage unique (valable 15 min)
  2. Agent génère une paire de clés Ed25519 + un CSR
  3. Agent POST /api/v1/agents/enroll { csr_pem, otp }
  4. Server valide l'OTP, signe le CSR avec l'intermediate CA
  5. Server retourne { cert_pem, ca_cert_pem }
  6. Toutes les connexions gRPC suivantes utilisent mTLS (CN vérifié = agent_id)
```

### 5.2 Authentification API

```
Flux JWT :
  POST /auth/token { username, password }
    → access_token (RS256, exp: 15min) + refresh_token (HttpOnly cookie, exp: 7j)
  POST /auth/refresh (cookie)
    → nouveau access_token
  
  Stockage :
    Access token : mémoire client uniquement (pas localStorage)
    Refresh token : HttpOnly Secure SameSite=Strict cookie

API Keys :
  Format : oseye_{random_32_bytes_hex}
  Stockage : BLAKE3(raw_key) en base, jamais la clé brute
  Usage : header X-API-Key pour accès automatisé (CI/CD, webhooks entrants)
  Révocation : immédiate (lookup en base à chaque requête)
```

### 5.3 RBAC

| Rôle | Périmètre |
|------|-----------|
| `reader` | Lecture events, alerts, decisions, cases (tout en GET) |
| `analyst` | + Acknowledge/annoter alerts, ajouter notes cases |
| `senior_analyst` | + Créer/modifier règles, approuver/rejeter décisions humaines, whitelist entités |
| `admin` | + Tout (agents, plugins, politiques, suppressions, rotate certs) |

### 5.4 Intégrité des événements

```
Hash chain BLAKE3 (calculé dans l'agent) :
  event.hash_chain = BLAKE3(
      event_content_bytes || previous_event.hash_chain
  )
  Premier event : BLAKE3(event_content_bytes || agent_id_bytes)

Signature des batches (Ed25519) :
  batch_signature = Ed25519Sign(
      private_key = agent_key,
      message = BLAKE3(event_1.hash_chain || ... || event_N.hash_chain)
  )

Vérification côté server :
  1. Vérifier signature Ed25519 avec la clé publique de l'agent (depuis son certificat)
  2. Recalculer hash_chain pour chaque event et vérifier la chaîne
  → Toute rupture = alerte "agent_tampered"

Journal des décisions : même mécanisme, hash_chain BLAKE3,
  signé avec la clé du server. Endpoint de vérification : GET /decisions/journal/verify
```

### 5.5 Chiffrement

- TLS 1.3 minimum sur toutes les interfaces (API REST, WebSocket, gRPC)
- Chiffrement au repos : PostgreSQL tablespace chiffré (pgcrypto / LUKS au niveau OS)
- ClickHouse : chiffrement natif activé
- Secrets (clés JWT, mots de passe DB) : montés depuis Kubernetes Secrets ou HashiCorp Vault

### 5.6 Audit Log API

Chaque requête authentifiée vers l'API REST est tracée dans une table dédiée **append-only**. Le middleware FastAPI capture ces données avant que la réponse soit envoyée.

```sql
CREATE TABLE api_audit_log (
    log_id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID            NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    timestamp       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    user_id         VARCHAR(100),   -- NULL si auth API key
    api_key_id      UUID,           -- NULL si auth JWT
    role            VARCHAR(20),
    method          VARCHAR(10)     NOT NULL,
    path            TEXT            NOT NULL,
    query_params    TEXT,
    status_code     INTEGER         NOT NULL,
    duration_ms     INTEGER,
    ip_address      INET,
    user_agent      TEXT,
    request_id      UUID            NOT NULL,  -- X-Request-ID propagé dans les logs
    error           TEXT            -- message si status >= 400
);

-- Immutabilité : INSERT only, jamais UPDATE/DELETE
CREATE RULE no_update_audit AS ON UPDATE TO api_audit_log DO INSTEAD NOTHING;
CREATE RULE no_delete_audit AS ON DELETE TO api_audit_log DO INSTEAD NOTHING;

CREATE INDEX idx_audit_user_ts  ON api_audit_log (user_id, timestamp DESC);
CREATE INDEX idx_audit_org_ts   ON api_audit_log (org_id, timestamp DESC);
CREATE INDEX idx_audit_request  ON api_audit_log (request_id);
```

Rétention : 90 jours en ligne, archivage S3/objet pour conformité GDPR/SOC 2.

---

## 6. Schémas de stockage

### PostgreSQL (prod standard)

```sql
-- Extension UUID v7
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Events (partitionnée par jour)
CREATE TABLE events (
    event_id        UUID            PRIMARY KEY,
    timestamp_ns    BIGINT          NOT NULL,
    org_id          UUID            NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    hostname        VARCHAR(255)    NOT NULL,
    agent_id        UUID            NOT NULL,
    category        VARCHAR(20)     NOT NULL,
    type            VARCHAR(50)     NOT NULL,
    severity        VARCHAR(10)     NOT NULL,
    uid             INTEGER,
    gid             INTEGER,
    pid             INTEGER,
    ppid            INTEGER,
    process_name    VARCHAR(255),
    executable      TEXT,
    cmdline         TEXT,
    cwd             TEXT,
    resource        TEXT,
    result          VARCHAR(20),
    src_ip          INET,
    dst_ip          INET,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        VARCHAR(10),
    bytes_sent      BIGINT,
    bytes_recv      BIGINT,
    file_hash_before CHAR(64),
    file_hash_after  CHAR(64),
    hash_chain      CHAR(64)        NOT NULL,
    signature       TEXT,
    collector       VARCHAR(20)     NOT NULL,
    ml_score        REAL,
    risk_score      REAL,
    rule_match_ids  TEXT[]          DEFAULT '{}',
    mitre_techniques TEXT[]         DEFAULT '{}',
    ti_tags         TEXT[]          DEFAULT '{}',
    incident_chain_id UUID,
    extra           JSONB           DEFAULT '{}'
) PARTITION BY RANGE (timestamp_ns);

CREATE INDEX idx_events_org_ts    ON events (org_id, timestamp_ns DESC);
CREATE INDEX idx_events_hostname_ts ON events (hostname, timestamp_ns DESC);
CREATE INDEX idx_events_pid ON events (pid, hostname);
CREATE INDEX idx_events_resource ON events (resource);
CREATE INDEX idx_events_chain ON events (incident_chain_id) WHERE incident_chain_id IS NOT NULL;

-- Alerts
CREATE TABLE alerts (
    alert_id        UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID            NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    severity        VARCHAR(10)     NOT NULL,
    status          VARCHAR(20)     NOT NULL DEFAULT 'open',
    rule_id         VARCHAR(100),
    ml_triggered    BOOLEAN         NOT NULL DEFAULT FALSE,
    ti_triggered    BOOLEAN         NOT NULL DEFAULT FALSE,
    entity_id       TEXT            NOT NULL,
    hostname        VARCHAR(255)    NOT NULL,
    trigger_event_id UUID           NOT NULL,
    related_event_ids UUID[]        DEFAULT '{}',
    incident_chain_id UUID,
    title           TEXT            NOT NULL,
    description     TEXT,
    mitre_techniques TEXT[]         DEFAULT '{}',
    assigned_to     VARCHAR(100),
    false_positive_count INTEGER    DEFAULT 0
);

CREATE INDEX idx_alerts_status ON alerts (status);
CREATE INDEX idx_alerts_entity ON alerts (entity_id);
CREATE INDEX idx_alerts_created ON alerts (created_at DESC);

-- Decisions (immuables après insertion)
CREATE TABLE decisions (
    decision_id     UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID            NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    decision_type   VARCHAR(20)     NOT NULL,
    rule_score      REAL            NOT NULL,
    ml_score        REAL            NOT NULL,
    ti_score        REAL            NOT NULL,
    correlation_depth INTEGER       NOT NULL,
    final_score     REAL            NOT NULL,
    entity_id       TEXT            NOT NULL,
    trigger_alert_id UUID,
    incident_chain_id UUID,
    related_event_ids UUID[]        DEFAULT '{}',
    policy_version  VARCHAR(20)     NOT NULL,
    explanation     TEXT            NOT NULL,
    requires_human  BOOLEAN         NOT NULL DEFAULT FALSE,
    human_decision  VARCHAR(10),
    human_operator  VARCHAR(100),
    human_note      TEXT,
    approved_at     TIMESTAMPTZ,
    timeout_at      TIMESTAMPTZ,
    prev_journal_hash CHAR(64)      NOT NULL,
    journal_hash    CHAR(64)        NOT NULL UNIQUE
);

-- Trigger d'immuabilité
CREATE OR REPLACE FUNCTION prevent_decision_update()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.human_decision IS NOT NULL THEN
        RAISE EXCEPTION 'Decision already resolved — record is immutable';
    END IF;
    -- Seuls les champs d'approbation humaine sont modifiables
    IF OLD.decision_type != NEW.decision_type OR OLD.final_score != NEW.final_score THEN
        RAISE EXCEPTION 'Core decision fields are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER decisions_immutability
    BEFORE UPDATE ON decisions
    FOR EACH ROW EXECUTE FUNCTION prevent_decision_update();

-- Cases
CREATE TABLE forensic_cases (
    case_id         UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID            NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    title           TEXT            NOT NULL,
    description     TEXT,
    severity        VARCHAR(10)     NOT NULL,
    status          VARCHAR(20)     NOT NULL DEFAULT 'open',
    tags            TEXT[]          DEFAULT '{}',
    assigned_to     VARCHAR(100),
    created_by      VARCHAR(100)    NOT NULL,
    event_ids       UUID[]          DEFAULT '{}',
    alert_ids       UUID[]          DEFAULT '{}'
);

CREATE TABLE case_notes (
    note_id         UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID            NOT NULL REFERENCES forensic_cases(case_id),
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ,
    author          VARCHAR(100)    NOT NULL,
    content         TEXT            NOT NULL
);

CREATE TABLE case_evidence (
    evidence_id     UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID            NOT NULL REFERENCES forensic_cases(case_id),
    type            VARCHAR(20)     NOT NULL,
    content         TEXT            NOT NULL,
    description     TEXT,
    added_by        VARCHAR(100)    NOT NULL,
    added_at        TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE TABLE case_custody (
    entry_id        UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID            NOT NULL REFERENCES forensic_cases(case_id),
    timestamp       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    operator        VARCHAR(100)    NOT NULL,
    action          VARCHAR(50)     NOT NULL,
    detail          TEXT,
    hash            CHAR(64)        NOT NULL
);

-- Trigger immuabilité custody
CREATE OR REPLACE FUNCTION prevent_custody_update()
RETURNS TRIGGER AS $$
BEGIN RAISE EXCEPTION 'Custody log is immutable'; END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER custody_immutability
    BEFORE UPDATE OR DELETE ON case_custody
    FOR EACH ROW EXECUTE FUNCTION prevent_custody_update();

-- Agents
CREATE TABLE agents (
    agent_id        UUID            PRIMARY KEY,
    hostname        VARCHAR(255)    NOT NULL,
    enrolled_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ,
    cert_serial     VARCHAR(50),
    cert_expires_at TIMESTAMPTZ,
    active_profile  VARCHAR(50)     DEFAULT 'workstation',
    revoked         BOOLEAN         NOT NULL DEFAULT FALSE
);

-- Rules
CREATE TABLE rules (
    id              VARCHAR(100)    PRIMARY KEY,
    name            TEXT            NOT NULL,
    enabled         BOOLEAN         NOT NULL DEFAULT TRUE,
    severity        VARCHAR(10)     NOT NULL,
    condition_yaml  TEXT            NOT NULL,
    timeframe_s     INTEGER,
    actions         TEXT[]          NOT NULL,
    tags            TEXT[]          DEFAULT '{}',
    mitre           TEXT[]          DEFAULT '{}',
    explanation     TEXT,
    source          VARCHAR(20)     NOT NULL DEFAULT 'custom',
    match_count     BIGINT          NOT NULL DEFAULT 0,
    last_matched    TIMESTAMPTZ,
    false_positive_count INTEGER    DEFAULT 0,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Entities
CREATE TABLE entity_profiles (
    entity_id       TEXT            PRIMARY KEY,
    entity_type     VARCHAR(20)     NOT NULL,
    hostname        VARCHAR(255)    NOT NULL,
    risk_score      REAL            NOT NULL DEFAULT 0,
    baseline_score  REAL            NOT NULL DEFAULT 0,
    alert_count     INTEGER         NOT NULL DEFAULT 0,
    last_seen       TIMESTAMPTZ,
    whitelisted     BOOLEAN         NOT NULL DEFAULT FALSE,
    whitelist_expires_at TIMESTAMPTZ
);

-- TI cache
CREATE TABLE ti_cache_ip (
    ip              INET            PRIMARY KEY,
    malicious       BOOLEAN         NOT NULL,
    confidence      INTEGER,
    source          VARCHAR(50),
    cached_at       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ     NOT NULL
);

CREATE TABLE ti_cache_hash (
    sha256          CHAR(64)        PRIMARY KEY,
    malicious       BOOLEAN         NOT NULL,
    engine_hits     INTEGER,
    source          VARCHAR(50),
    cached_at       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ     NOT NULL
);

CREATE TABLE ti_ioc_feed (
    ioc_id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    type            VARCHAR(20)     NOT NULL,   -- ip | domain | hash | url
    value           TEXT            NOT NULL,
    source          VARCHAR(100),
    tags            TEXT[]          DEFAULT '{}',
    confidence      REAL,
    valid_from      TIMESTAMPTZ,
    valid_until     TIMESTAMPTZ,
    imported_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    UNIQUE (type, value, source)
);
CREATE INDEX idx_ioc_value ON ti_ioc_feed (value);
```

### ClickHouse (haute volumétrie)

```sql
CREATE TABLE events (
    event_id            UUID,
    timestamp_ns        UInt64,
    org_id              UUID,
    date                Date        MATERIALIZED toDate(fromUnixTimestamp64Nano(timestamp_ns)),
    category            LowCardinality(String),
    type                LowCardinality(String),
    severity            LowCardinality(String),
    uid                 Int32,
    gid                 Int32,
    pid                 Int32,
    ppid                Int32,
    process_name        String,
    executable          String,
    cmdline             String,
    hostname            LowCardinality(String),
    agent_id            UUID,
    resource            String,
    result              LowCardinality(String),
    collector           LowCardinality(String),
    ml_score            Float32,
    risk_score          Float32,
    rule_match_ids      Array(String),
    mitre_techniques    Array(String),
    hash_chain          FixedString(64),
    extra               String      DEFAULT '{}'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(date)
ORDER BY (hostname, timestamp_ns)
TTL date + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Vue matérialisée : stats horaires par entité (features ML)
CREATE MATERIALIZED VIEW entity_hourly_stats
ENGINE = SummingMergeTree()
ORDER BY (hostname, process_name, uid, hour)
AS SELECT
    hostname,
    process_name,
    uid,
    toStartOfHour(fromUnixTimestamp64Nano(timestamp_ns)) AS hour,
    countIf(category = 'file')    AS file_events,
    countIf(category = 'network') AS network_events,
    countIf(category = 'process') AS process_events,
    count() AS total_events
FROM events
GROUP BY hostname, process_name, uid, hour;
```

### SQLite (dev / déploiement léger)

Même DDL que PostgreSQL avec les substitutions :
- `UUID` → `TEXT` (hex string)
- `JSONB` → `TEXT` (JSON string)
- `INET` → `TEXT`
- `TIMESTAMPTZ` → `TEXT` (ISO-8601)
- `TEXT[]` → `TEXT` (JSON array)
- Partitionnement → non supporté ; rétention gérée par `DELETE WHERE timestamp_ns < ?` schedulé

---

## 7. API — Catalogue complet des endpoints

Base URL : `/api/v1`. Auth : `Authorization: Bearer <jwt>` ou `X-API-Key: oseye_<key>`.

### Authentification

```
POST   /auth/token                  → { access_token, token_type, expires_in }
POST   /auth/refresh                → { access_token, expires_in }
POST   /auth/logout                 → 204
GET    /auth/me                     → { user_id, username, role, last_login }
POST   /auth/api-keys               → { key_id, raw_key, role }  [clé affichée une seule fois]
GET    /auth/api-keys               → [ { key_id, name, role, last_used, expires_at } ]
DELETE /auth/api-keys/{key_id}      → 204
```

### Events

```
GET    /events                      → Page<UniversalEvent>
       Query: hostname, category, type, severity, uid, pid, process_name,
              resource, rule_id, mitre_technique, from_ts, to_ts, limit, offset, sort

GET    /events/{event_id}           → UniversalEvent (enrichi)
GET    /events/{event_id}/chain     → { incident_chain, graph_nodes, graph_edges }
GET    /events/{event_id}/context   → { before: [...], event, after: [...] }  (±30s)
GET    /events/stats                → { buckets: [{ key, count }] }
       Query: from_ts, to_ts, hostname, group_by=category|severity|type
```

### Alerts

```
GET    /alerts                      → Page<Alert>
       Query: status, severity, entity_id, hostname, rule_id, assigned_to, from_ts, to_ts

GET    /alerts/{alert_id}           → Alert (avec contexte events)
PATCH  /alerts/{alert_id}           → Alert  { status?, assigned_to?, note? }
POST   /alerts/{alert_id}/acknowledge → Alert
POST   /alerts/{alert_id}/false-positive → Alert  { reason }  [feedback règles]
GET    /alerts/stats                → { by_severity, by_status, trend }
```

### Rules

```
GET    /rules                       → Page<Rule>
GET    /rules/{rule_id}             → Rule (avec stats)
POST   /rules                       → Rule              [senior_analyst+]
PUT    /rules/{rule_id}             → Rule              [senior_analyst+]
PATCH  /rules/{rule_id}/enable      → 204               [senior_analyst+]
PATCH  /rules/{rule_id}/disable     → 204               [senior_analyst+]
DELETE /rules/{rule_id}             → 204               [admin]
POST   /rules/validate              → { valid, errors }
POST   /rules/reload                → { reloaded, errors }  [admin]
```

### Decisions

```
GET    /decisions                   → Page<Decision>
GET    /decisions/{decision_id}     → Decision
GET    /decisions/pending           → [ Decision ]  (attente approbation humaine)
POST   /decisions/{decision_id}/approve → Decision  [senior_analyst+]
POST   /decisions/{decision_id}/reject  → Decision  [senior_analyst+]  { reason, alternative? }
GET    /decisions/journal/verify    → { valid, last_verified, violations }  [admin]
```

### Forensic Cases

```
GET    /cases                       → Page<ForensicCase>
POST   /cases                       → ForensicCase
GET    /cases/{case_id}             → ForensicCase (avec custody_log)
PATCH  /cases/{case_id}             → ForensicCase
POST   /cases/{case_id}/events      → 204  { event_ids }
DELETE /cases/{case_id}/events/{event_id} → 204
POST   /cases/{case_id}/alerts      → 204  { alert_ids }
POST   /cases/{case_id}/notes       → CaseNote
PUT    /cases/{case_id}/notes/{note_id}   → CaseNote
POST   /cases/{case_id}/evidence    → EvidenceItem
GET    /cases/{case_id}/timeline    → { events sorted by timestamp_ns }
GET    /cases/{case_id}/export      → File  Query: format=json|html|pdf
POST   /cases/{case_id}/export/misp → { misp_event_id }
POST   /cases/{case_id}/export/thehive → { thehive_case_id }
GET    /cases/{case_id}/custody     → [ CustodyEntry ]
DELETE /cases/{case_id}             → 204  [admin, status=archived uniquement]
```

### Snapshots

```
POST   /snapshots                   → { snapshot_id, status: "pending" }  { hostname, note? }
GET    /snapshots                   → [ SystemSnapshot ]  Query: hostname, from_ts, to_ts
GET    /snapshots/{snapshot_id}     → SystemSnapshot
GET    /snapshots/diff              → { processes: {added, removed}, connections: ... }
       Query: snapshot_id_a, snapshot_id_b
```

### Entities

```
GET    /entities                    → [ EntityProfile ]  Query: type, hostname, min_risk, max_risk
GET    /entities/{entity_id}        → EntityProfile
GET    /entities/{entity_id}/events → Page<UniversalEvent>
GET    /entities/{entity_id}/alerts → [ Alert ]
GET    /entities/{entity_id}/risk/history → { timeline: [{ ts, score }] }
POST   /entities/{entity_id}/whitelist → 204  [senior_analyst+]  { reason, expires_at? }
```

### Policies

```
GET    /policies                    → [ SurveillanceProfile ]
POST   /policies                    → SurveillanceProfile  [admin]
PUT    /policies/{profile_name}     → SurveillanceProfile  [admin]
DELETE /policies/{profile_name}     → 204  [admin]
POST   /policies/{profile_name}/apply → { applied_to: [...] }  [admin]  { hostnames }
```

### Agents

```
GET    /agents                      → [ AgentInfo ]
GET    /agents/{agent_id}           → AgentInfo
GET    /agents/{agent_id}/status    → { online, last_seen, cpu_pct, mem_mb, events_per_sec }
POST   /agents/enroll               → { cert_pem, ca_cert_pem }  { csr_pem, otp }
POST   /agents/{agent_id}/renew-cert → { cert_pem }  (mTLS requis)
DELETE /agents/{agent_id}           → 204  [admin]
```

### Plugins

```
GET    /plugins                     → [ PluginInfo ]
POST   /plugins/install             → { plugin_id, status }  [admin]
GET    /plugins/{plugin_id}         → PluginInfo
PATCH  /plugins/{plugin_id}/enable  → 204  [admin]
PATCH  /plugins/{plugin_id}/disable → 204  [admin]
DELETE /plugins/{plugin_id}         → 204  [admin]
```

### Health & Metrics

```
GET    /health                      → { status, version, uptime_s }  (pas d'auth)
GET    /health/detailed             → { bus, components, agents, events_per_sec, latency_p99 }
GET    /metrics                     → Prometheus exposition format (interface interne)
```

### WebSocket

```
WS /ws/events       → stream UniversalEvent en temps réel
WS /ws/alerts       → stream Alert (new + updated)
WS /ws/decisions    → stream Decision + decisions:pending_approval
WS /ws/dashboard    → stats agrégées toutes les secondes (events/s, alert count, top entities)
```

### Webhooks sortants

```
POST   /webhooks                    → { webhook_id, secret }
       Body: { url, secret, events: ["alert.new", "decision.alert", "decision.isolate"] }
DELETE /webhooks/{webhook_id}       → 204
```

Livraison webhook : `POST` vers l'URL configurée avec header `X-OSEye-Signature: HMAC-SHA256(body, secret)`, retry exponentiel (5 tentatives max).

---

## 8. Patterns de communication

### Format des messages sur le bus

Tous les messages sont sérialisés en **Protocol Buffers v3**. Header 16 octets :

```
[ 4 bytes magic: 0x4F534559 ("OSEY") ]
[ 1 byte version: 0x01               ]
[ 1 byte message type                ]
[ 2 bytes flags                      ]
[ 8 bytes timestamp_ns               ]
[ N bytes payload Protobuf           ]
```

Sur Redis Streams : bytes Protobuf sous le champ `pb` de l'entrée stream.  
Sur Kafka : key = `hostname:pid`, value = payload Protobuf.

### Flux de traitement complet

```
[Agent Go]
  BLAKE3 hash chain calculé par event
  Ed25519 batch-sign toutes les 1000 events ou toutes les 1s
  gRPC stream : IngestEvents(stream UniversalEventPB) → IngestResponse
        ↓
[Server gRPC service: agent_service.py]
  Valide CN du cert mTLS = agent_id
  Vérifie signature du batch
  Publie sur events:raw:{agent_id}
        ↓
[Normalizer]  subscribe events:raw:*
  Publie sur events:normalized
        ↓
  ┌──────────────────┬───────────────────┬──────────────────┐
  ↓                  ↓                   ↓                  ↓
[Rule Engine]  [ML Engine]       [TI Engine]         [Storage Writer]
analysis:       analysis:ml       events:enriched      batch insert
rules:{host}                      (events + ti_tags)   toutes les 500ms
  └──────────────────┴───────────────────┘
                      ↓
             [Correlation Engine]
             subscribe analysis:* + events:enriched
             construit le graphe, publie analysis:correlated
                      ↓
             [Decision Engine]
             subscribe analysis:correlated
             publie decisions:completed ou decisions:pending
                      ↓
               [Action Executor]  +  [WS Manager]
```

### Protobuf — schémas principaux

```protobuf
// proto/event.proto
syntax = "proto3";
package oseye.v1;

message UniversalEventPB {
    bytes   event_id        = 1;   // UUID v7 bytes
    int64   timestamp_ns    = 2;
    string  hostname        = 3;
    bytes   agent_id        = 4;
    string  category        = 5;
    string  type            = 6;
    string  severity        = 7;
    int32   uid             = 8;
    int32   pid             = 9;
    int32   ppid            = 10;
    string  process_name    = 11;
    string  executable      = 12;
    string  cmdline         = 13;
    string  resource        = 14;
    string  result          = 15;
    bytes   hash_chain      = 16;  // 32 bytes BLAKE3
    string  collector       = 17;
    bytes   extra_json      = 18;  // JSON bytes pour champs additionnels
}

message IngestRequest {
    bytes   batch_signature = 1;   // Ed25519, 64 bytes
    repeated UniversalEventPB events = 2;
}

message IngestResponse {
    int32   accepted = 1;
    int32   rejected = 2;
    repeated string errors = 3;
}

// Service gRPC agent↔server
service AgentService {
    rpc IngestEvents(stream IngestRequest) returns (IngestResponse);
    rpc ReceivePolicy(PolicyRequest) returns (stream SurveillanceProfilePB);
    rpc StreamCommands(CommandRequest) returns (stream AgentCommand);
}
```

---

## 9. Architecture de déploiement

### Docker Compose (dev / single node)

```yaml
# infra/docker/docker-compose.dev.yml
version: "3.9"

services:
  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
    command: redis-server --appendonly yes
    volumes: [redis_data:/data]
    healthcheck:
      test: [CMD, redis-cli, ping]
      interval: 5s

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: oseye
      POSTGRES_USER: oseye
      POSTGRES_PASSWORD_FILE: /run/secrets/pg_password
    secrets: [pg_password]
    volumes: [pg_data:/var/lib/postgresql/data]
    healthcheck:
      test: [CMD-SHELL, "pg_isready -U oseye"]
      interval: 5s

  oseye-server:
    build:
      context: ../../server
      target: development
    environment:
      OSEYE_ENV: development
      OSEYE_BUS_BACKEND: redis
      OSEYE_BUS_REDIS_URL: redis://redis:6379
      OSEYE_DB_BACKEND: postgresql
      OSEYE_DB_URL: postgresql+asyncpg://oseye:dev@postgres:5432/oseye
      OSEYE_JWT_PRIVATE_KEY_PATH: /secrets/jwt_rs256.pem
      OSEYE_TLS_CERT: /certs/server.crt
      OSEYE_TLS_KEY: /certs/server.key
      OSEYE_CA_CERT: /certs/ca.crt
    ports:
      - "8000:8000"     # REST API + WebSocket
      - "50051:50051"   # gRPC (ingestion agents)
    volumes:
      - ../../server:/app        # Hot reload dev
      - ../../rules:/app/rules
      - ./certs:/certs:ro
      - ./secrets:/secrets:ro
    depends_on:
      redis: { condition: service_healthy }
      postgres: { condition: service_healthy }

  oseye-agent:
    build:
      context: ../../agent
    environment:
      OSEYE_SERVER_URL: oseye-server:50051
      OSEYE_AGENT_CERT: /certs/agent.crt
      OSEYE_AGENT_KEY: /certs/agent.key
      OSEYE_CA_CERT: /certs/ca.crt
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /dev/kmsg:/dev/kmsg:ro
      - ./certs:/certs:ro
    privileged: true     # eBPF + fanotify
    pid: "host"
    depends_on: [oseye-server]

  oseye-ui:
    build:
      context: ../../ui
      target: development
    environment:
      VITE_API_URL: http://localhost:8000
      VITE_WS_URL: ws://localhost:8000
    ports: ["3000:3000"]
    volumes:
      - ../../ui/src:/app/src

volumes:
  redis_data:
  pg_data:

secrets:
  pg_password:
    file: ./secrets/pg_password.txt
```

### Kubernetes (production)

```
namespace: oseye-system
├── DaemonSet:  oseye-agent              1 pod par nœud, privileged
├── Deployment: oseye-server             3 replicas, HPA 2→10
├── Deployment: oseye-ui                 2 replicas
├── Deployment: oseye-worker-rule        2 replicas
├── Deployment: oseye-worker-ml          1 replica (stateful)
├── Deployment: oseye-worker-ti          2 replicas
└── Deployment: oseye-worker-decision    1 replica (stateful, journal)

Services externes (namespaces séparés ou managed) :
├── Redis Cluster (ou ElastiCache / Memorystore)
├── PostgreSQL    (ou RDS / CloudSQL)
└── ClickHouse    (optionnel, ou ClickHouse Cloud)
```

**DaemonSet agent :**

```yaml
# infra/k8s/agent/daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: oseye-agent
  namespace: oseye-system
spec:
  selector:
    matchLabels: { app: oseye-agent }
  template:
    spec:
      hostPID: true
      tolerations:
        - operator: Exists    # Tous les nœuds y compris masters
      containers:
        - name: agent
          image: ghcr.io/oseye/agent:latest
          securityContext:
            privileged: true
            capabilities:
              add: [SYS_ADMIN, SYS_PTRACE, NET_ADMIN, DAC_READ_SEARCH]
          volumeMounts:
            - { name: host-proc, mountPath: /host/proc, readOnly: true }
            - { name: host-sys,  mountPath: /host/sys,  readOnly: true }
            - { name: host-dev,  mountPath: /host/dev }
            - { name: agent-certs, mountPath: /etc/oseye/certs, readOnly: true }
          env:
            - name: OSEYE_SERVER_URL
              value: "oseye-server.oseye-system.svc.cluster.local:50051"
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          resources:
            requests: { cpu: "20m", memory: "64Mi" }
            limits:   { cpu: "100m", memory: "256Mi" }
      volumes:
        - { name: host-proc, hostPath: { path: /proc } }
        - { name: host-sys,  hostPath: { path: /sys  } }
        - { name: host-dev,  hostPath: { path: /dev  } }
        - name: agent-certs
          secret: { secretName: oseye-agent-certs }
```

**HPA server :**

```yaml
# infra/k8s/server/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: oseye-server-hpa
  namespace: oseye-system
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: oseye-server
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target: { type: Utilization, averageUtilization: 60 }
    - type: External
      external:
        metric:
          name: redis_stream_lag
          selector:
            matchLabels: { stream: events.normalized }
        target: { type: AverageValue, averageValue: "10000" }
```

**Network Policy (zero-trust) :**

```yaml
# Agent ne peut parler qu'au server sur port gRPC
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: oseye-agent-egress
  namespace: oseye-system
spec:
  podSelector:
    matchLabels: { app: oseye-agent }
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels: { app: oseye-server }
      ports:
        - { protocol: TCP, port: 50051 }
```

cert-manager gère la rotation automatique de tous les certificats via le `ClusterIssuer` pointant sur l'intermediate CA OSEye.

---

## 10. Feuille de route de développement

Chaque phase produit un artefact fonctionnel et testable avant de passer à la suivante.

### Phase 1 — Foundation (Semaines 1–3)
**Objectif :** Pipeline end-to-end : ingestion → normalisation → stockage → query.

- Scaffolding monorepo, CI/CD (GitHub Actions : lint + test + build)
- `proto/event.proto` + codegen Go et Python
- `UniversalEvent` Pydantic + struct Go
- `EventBus` in-memory et Redis Streams
- Agent Go : collectors eBPF (execve, openat, connect), auditd, procfs
- Agent Go : hash chain BLAKE3, gRPC transport, buffer SQLite local
- Normalizer Python : adapters eBPF et auditd
- Backends PostgreSQL + SQLite (Alembic migrations, repository pattern)
- FastAPI : `GET /events` + WebSocket `/ws/events`
- Auth JWT basique + user admin initial
- `docker-compose.dev.yml`

**Livrable :** Events réels de la machine hôte visibles en DB et streamés via WebSocket.

---

### Phase 2 — Full Collection (Semaines 4–6)
**Objectif :** 9 collectors opérationnels, agent robuste.

- Collectors Go restants : fanotify, inotify, netlink, journald, udev, syslog
- Adapters normalizer pour chaque collector
- Pipeline de masquage des secrets
- Agent : CPU watchdog + throttling adaptatif
- Agent : buffer offline + reconnexion automatique + replay
- API : `/events`, `/agents`, `/health` complète
- Déploiement DaemonSet sur cluster dev K8s
- Tests unitaires tous collectors (mocks kernel), couverture > 80%

**Livrable :** 9 types de collectors actifs. L'agent survit à une déconnexion et rejoue les events bufferisés.

---

### Phase 3 — Détection (Semaines 7–9)
**Objectif :** Règles déclenchées, alertes créées, visibles par les analystes.

- Rule engine : parser YAML/TOML, évaluateur d'expressions, fenêtres temporelles
- Ruleset intégré (30+ règles couvrant les principales techniques MITRE)
- Hot-reload via watchdog fichiers
- Création et stockage des alertes
- API complète : `/alerts`, `/rules` (CRUD + validate + reload)
- WebSocket `/ws/alerts`
- Middleware RBAC (4 rôles enforced)
- Support API keys
- Boucle de feedback faux positifs → stats règles
- Tests : évaluateur, fenêtres temporelles, toutes les 30 règles

**Livrable :** `chmod 777 /etc/shadow` sur un hôte surveillé → alerte visible sur l'API en < 500ms.

---

### Phase 4 — Intelligence (Semaines 10–12)
**Objectif :** Events enrichis TI, chaînes de corrélation reconstruites.

- Threat Intelligence : providers AbuseIPDB + VirusTotal, cache Redis
- Ingestion STIX/TAXII depuis feeds publics
- Intégration MISP
- Scheduler refresh des feeds IOC
- Correlation engine : graphe events (rustworkx), linkers PID/PPID + ressource + user + temporal
- API reconstruction chaîne : `GET /events/{id}/chain`
- Risk score par entité + API `/entities`
- Tests d'intégration : simuler mouvement latéral, vérifier la chaîne de corrélation

**Livrable :** Séquence SSH login → sudo → exfiltration fichier reconstruite comme incident unique corrélé.

---

### Phase 5 — Decision Engine (Semaines 13–15)
**Objectif :** Décisions autonomes tracées, queue approbation humaine fonctionnelle.

- Decision engine : matrice risque, scoring pondéré, 8 types de décisions
- Journal immutable avec hash chain + vérification
- Queue approbation humaine + handler timeout
- Action executor : ALERT (déjà fait), NOTIFY (webhook), ESCALATE, COLLECT_MORE
- ISOLATE en mode stub (log l'intention, n'isole pas encore — sécurité Phase 5)
- WebSocket `/ws/decisions`
- API complète `/decisions` (approve/reject)
- Endpoint vérification intégrité journal
- Tests : > 100 scénarios de décisions avec résultats attendus, précision > 95%

**Livrable :** Décisions justifiées avec traçabilité complète. L'humain peut approuver/rejeter ISOLATE via API.

---

### Phase 6 — ML Engine (Semaines 16–19) `[~]` EN COURS
**Objectif :** Baseline comportementale + scores d'anomalie augmentant la détection rule-based.

**Livré (2026-08-09) :**
- Pipeline d'extraction de features — vecteur 10-dim [0,1] (`features.py`)
- HalfSpaceTrees online (River) — baseline par entité hostname×category, LRU 10k modèles (`anomaly.py`)
- MITREClassifier — LogisticRegression online par technique, entraîné sur alertes confirmées (`classifier.py`)
- MLEngine façade — `ml_score = 0.7×anomaly + 0.3×classifier` (`engine.py`)
- Câblage Decision Engine — paramètre `ml_engine` + `trigger_event`
- 35 tests unitaires (`tests/unit/test_ml_engine.py`)

**Restant :**
- Versioning des modèles + stockage DB
- Checkpoint périodique (toutes les 15 minutes)
- Framework A/B test (nouveau modèle vs. modèle courant)
- Benchmarks : taux de FP sur workloads propres, recall sur scénarios d'attaque

**Livrable :** Exfiltration lente de données via DNS (non couverte par règles) → alerte ML.

---

### Phase 7 — Forensics (Semaines 20–22)
**Objectif :** Gestion de cas complète, exports légalement admissibles.

- Capture de snapshot système côté agent (procfs + netlink)
- Calcul de diff entre snapshots
- CRUD cases + custody log complet
- Moteur de reconstruction de timeline
- Export : bundle JSON, rapport HTML, rapport PDF
- Export MISP et TheHive
- API `/cases`, `/snapshots` (tous les endpoints)
- Tests d'immuabilité du custody log

**Livrable :** Analyste ouvre un cas, ajoute des events corrélés, annote et exporte un rapport PDF défendable.

---

### Phase 8 — Policy Engine + Plugin SDK (Semaines 23–25)
**Objectif :** Profils de surveillance hot-swap, écosystème de plugins extensible.

- Policy engine : `SurveillanceProfile`, schéma YAML
- 6 profils intégrés (webserver, database, workstation, fileserver, container, investigation)
- Push de profil vers agents via event bus
- Agent : réception profil → activation/désactivation réelle des collectors
- SDK (package `sdk/`) publié sur PyPI
- Plugin manager : load/unload, vérification signature, isolation subprocess
- Limites de ressources plugins via cgroups v2
- Plugins exemple : notifier PagerDuty, exporteur S3
- CLI : `oseye plugin install <name>`

**Livrable :** Basculer de `workstation` à `investigation` double la verbosité de collecte en < 2 secondes. Plugin tiers tourne en sandbox isolé.

---

### Phase 9 — Dashboard UI (Semaines 26–29)
**Objectif :** Interface web production-grade pour tous les workflows analyste.

- Flux auth : login, refresh JWT, logout
- Page Dashboard : taux d'events en temps réel, compteur alertes, heatmap de risque
- Page Events : timeline searchable avec filtres avancés
- Page Alerts : queue avec workflow acknowledge/faux-positif
- Page Decisions : journal + cartes d'approbation humaine avec compte à rebours
- Page Cases : liste, détail, vue timeline, export
- Page Entities : profils de risque, visualisation arbre de processus
- Page Rules : liste, éditeur YAML create/edit, enable/disable
- Graphe de corrélation : force-directed D3 des events liés
- Intégration WebSocket pour mises à jour live sur toutes les pages

---

### Phase 10 — Hardening + Distribution (Semaines 30–33)
**Objectif :** Packaging production-grade, validation des performances.

- Action ISOLATE réelle : SIGSTOP / cgroup freeze avec timer de rollback configurable
- Enforcement mTLS sur toute la communication agent↔server
- Enforcement TLS 1.3 sur l'API REST
- Rate limiting (token bucket par API key / utilisateur)
- Isolation multi-tenant (partitionnement des données par organisation)
- Benchmark de performance : validation > 100 000 events/s
- Validation latence de détection : mesure P50/P95/P99 event→alerte
- Profiling CPU agent sous charge, optimisation < 2%
- Packaging `.deb` et `.rpm` (build FPM-based)
- Images Docker officielles (multi-arch : amd64 + arm64)
- Helm chart
- Playbook Ansible déploiement grande échelle
- Documentation API complète (export OpenAPI + site Docusaurus)
- Pentest OSEye (OWASP Top 10 sur sa propre API REST)

---

## 11. Observabilité

### 11.1 Métriques Prometheus

Toutes les métriques sont exposées sur `GET /metrics` (format Prometheus text). En K8s, scrappées par Prometheus via `ServiceMonitor`.

**Métriques agent (exposées via gRPC metadata) :**

| Métrique | Type | Labels | Description |
|----------|------|--------|-------------|
| `oseye_agent_events_total` | Counter | `collector`, `category` | Events produits par collector |
| `oseye_agent_events_dropped_total` | Counter | `collector`, `reason` | Events perdus (buffer plein, throttle) |
| `oseye_agent_buffer_size` | Gauge | — | Events en attente dans SQLite local |
| `oseye_agent_cpu_usage_pct` | Gauge | — | CPU utilisé par l'agent |
| `oseye_agent_grpc_reconnects_total` | Counter | — | Reconnexions gRPC |

**Métriques server :**

| Métrique | Type | Labels | Description |
|----------|------|--------|-------------|
| `oseye_events_ingested_total` | Counter | `agent_id`, `org_id` | Events reçus par le gRPC service |
| `oseye_events_normalized_total` | Counter | `collector` | Events normalisés |
| `oseye_bus_lag` | Gauge | `topic`, `consumer` | Lag consommateur sur le bus |
| `oseye_rules_evaluated_total` | Counter | `rule_id`, `matched` | Évaluations de règles |
| `oseye_alerts_created_total` | Counter | `severity`, `rule_id` | Alertes créées |
| `oseye_decisions_total` | Counter | `decision_type`, `org_id` | Décisions prises |
| `oseye_detection_latency_seconds` | Histogram | `path` (rule\|ml\|ti) | Latence event → alerte |
| `oseye_ml_anomaly_score` | Histogram | `entity_type` | Distribution des scores ML |
| `oseye_ti_cache_hits_total` | Counter | `type` (ip\|hash\|ioc) | Cache hits TI |
| `oseye_storage_insert_duration_seconds` | Histogram | `backend` | Durée insertions |
| `oseye_http_requests_total` | Counter | `method`, `path`, `status` | Requêtes API REST |
| `oseye_http_request_duration_seconds` | Histogram | `method`, `path` | Latence API |
| `oseye_websocket_connections` | Gauge | `channel` | Connexions WS actives |

**Alerting Prometheus (règles critiques) :**

```yaml
# infra/prometheus/alerts.yaml
groups:
  - name: oseye
    rules:
      - alert: OSEyeDetectionLatencyHigh
        expr: histogram_quantile(0.99, oseye_detection_latency_seconds_bucket) > 0.5
        for: 2m
        labels: { severity: warning }
        annotations:
          summary: "Latence détection P99 > 500ms"

      - alert: OSEyeBusLagCritical
        expr: oseye_bus_lag{topic="events:normalized"} > 50000
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Lag bus events:normalized > 50k — workers en retard"

      - alert: OSEyeAgentDown
        expr: time() - oseye_agent_last_seen_timestamp > 120
        for: 1m
        labels: { severity: warning }
        annotations:
          summary: "Agent {{ $labels.agent_id }} silencieux depuis > 2 minutes"
```

### 11.2 Traces distribuées (OpenTelemetry)

Chaque event traversant le pipeline porte un `trace_id` et un `span_id` propagés de bout en bout.

```
[Agent Go]                         [Server Python]
  gRPC IngestEvents                  grpc_service.py
   trace_id: abc123                    span: ingest
   span_id: 001                          │
                                         ├─ span: normalize
                                         ├─ span: rule_eval      (rule_worker)
                                         ├─ span: ml_score       (ml_worker)
                                         ├─ span: ti_enrich      (ti_worker)
                                         ├─ span: correlate      (correlation_worker)
                                         └─ span: decide         (decision_worker)
```

Configuration :
```python
# server/oseye/core/observability.py
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

def setup_tracing(service_name: str, otlp_endpoint: str):
    provider = TracerProvider()
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint))
    )
    trace.set_tracer_provider(provider)
```

Exporter par défaut : Jaeger (dev via docker-compose) ou OTLP → Tempo (prod).

### 11.3 Logs structurés JSON

Tous les composants écrivent des logs JSON sur stdout. Pas de logs fichiers — collectés par Fluentd/Loki en K8s.

**Format :**
```json
{
  "timestamp": "2026-07-28T10:42:00.123456Z",
  "level": "INFO",
  "service": "oseye-worker-rule",
  "trace_id": "abc123",
  "request_id": "req-456",
  "org_id": "00000000-0000-0000-0000-000000000001",
  "agent_id": "agent-789",
  "event": "rule_matched",
  "rule_id": "rule_shadow_read",
  "severity": "critical",
  "entity_id": "process:host1:bash",
  "duration_ms": 1.2
}
```

Niveaux : `DEBUG` (dev only), `INFO` (events métier normaux), `WARNING` (dégradation), `ERROR` (perte de données), `CRITICAL` (composant inopérant).

---

## 12. Résilience et tolérance aux pannes

### 12.1 Dead-Letter Queue (DLQ)

Tout message qui échoue le traitement après 3 tentatives est envoyé dans une DLQ dédiée au lieu d'être perdu.

```
Topic normal          → worker → 3 échecs → DLQ topic
events:normalized     → rule_worker    → events:dlq:rule
events:normalized     → ml_worker      → events:dlq:ml
events:enriched       → correlation    → events:dlq:correlation
analysis:correlated   → decision       → events:dlq:decision
```

**Schéma d'entrée DLQ :**
```python
class DLQEntry(BaseModel):
    original_topic: str
    original_message: bytes     # payload Protobuf original
    error: str                  # exception + traceback
    attempts: int
    first_failed_at: datetime
    last_failed_at: datetime
    worker: str
```

Les entrées DLQ sont stockées dans Redis (TTL 24h) et dans PostgreSQL (`dlq_entries` table) pour analyse. Un endpoint `GET /health/dlq` expose le count par worker.

### 12.2 Circuit Breakers

Les appels vers les services externes (TI providers, DB) sont protégés par des circuit breakers (pattern `pybreaker`).

| Service | Threshold | Timeout reset | Fallback |
|---------|-----------|---------------|----------|
| AbuseIPDB | 5 erreurs / 30s | 60s | `ti_tags=["provider:unavailable"]`, utiliser cache local |
| VirusTotal | 3 erreurs / 60s | 120s | Idem |
| MISP | 5 erreurs / 60s | 300s | Skip enrichissement IOC |
| PostgreSQL | 10 erreurs / 10s | 30s | Retry avec backoff exponentiel, alerte opérateur |
| ClickHouse | 5 erreurs / 10s | 60s | Accumulation en mémoire tampon (max 50k events), flush dès reconnexion |
| Redis | 5 erreurs / 5s | 15s | Bascule bus in-memory (mode dégradé, pas de multi-process) |

Le statut de chaque circuit breaker est exposé dans `GET /health/detailed`.

### 12.3 Backpressure

Si un worker consomme plus lentement qu'il ne reçoit, le lag bus augmente. Stratégie par couche :

```
Producteur          Bus              Consommateur
[Agent]  →→→  [events:normalized]  →→→  [rule_worker]
                    ↑
              lag monitoring
              Si lag > 100k :
                → throttle ingest (gRPC flow control)
                → ResourceWatchdog réduit throttle collectors
```

Implémentation :
```python
# server/oseye/ingest/backpressure.py
class BackpressureController:
    async def check(self) -> float:
        """Retourne un facteur throttle [0.0, 1.0] à envoyer aux agents."""
        lag = await self.bus.get_lag("events:normalized")
        if lag > 200_000: return 0.2
        if lag > 100_000: return 0.5
        if lag > 50_000:  return 0.8
        return 1.0
```

Le facteur est envoyé à tous les agents via `StreamCommands` gRPC toutes les 10 secondes.

### 12.4 Graceful Shutdown

Chaque worker et le serveur gRPC/HTTP implémentent un shutdown propre sur `SIGTERM` :

```
SIGTERM reçu
  1. Stop accepting new connections / messages
  2. Drain : traite les messages déjà reçus (max 30s)
  3. Flush : écrit les batches en attente vers le storage
  4. Commit offsets Redis/Kafka
  5. Close DB connections
  6. Exit 0
```

```python
# server/oseye/core/lifecycle.py
class GracefulWorker:
    async def run(self):
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGTERM, self._shutdown_event.set)
        try:
            await self._process_loop()
        finally:
            await self._flush_pending()
            await self._close_connections()
```

Probe K8s `preStop` hook ajoute un délai de 5s pour que Kubernetes retire le pod de l'Endpoints avant d'envoyer SIGTERM.

### 12.5 Offline Agent — buffer et replay

Si le serveur est inaccessible, l'agent Go bufferise dans SQLite local sans perte :

```
Connexion gRPC perdue
  → LocalBuffer.Enqueue(event)        # écriture SQLite
  → Reconnexion toutes les 5s (backoff exponentiel, max 5min)
  → Dès reconnexion : replay depuis cursor last_sent_id
  → Cleanup SQLite une fois ACK reçu du serveur
  → Capacité max buffer : 1M events (configurable OSEYE_BUFFER_MAX_EVENTS)
  → Si buffer plein : drop les plus anciens (politique LRU), métrique oseye_agent_events_dropped_total
```

---

## 13. Compléments architecturaux

### 13.1 Table `organizations` — réservation multi-tenant

La multi-tenancy est activée en Phase 10, mais toutes les tables portent déjà `org_id` avec un défaut pointant sur l'organisation unique (single-tenant). Migration Phase 10 = retirer le DEFAULT et ajouter la FK.

```sql
CREATE TABLE organizations (
    org_id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255)    NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    active          BOOLEAN         NOT NULL DEFAULT TRUE,
    settings        JSONB           DEFAULT '{}'
);

-- Organisation unique par défaut (single-tenant)
INSERT INTO organizations (org_id, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'default');
```

Toutes les queries de production filtreront par `org_id` via Row-Level Security PostgreSQL (Phase 10) :
```sql
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON events USING (org_id = current_setting('app.org_id')::uuid);
```

### 13.2 Schéma `UniversalEvent` — champs à ajouter (v1.1)

Champs manquants identifiés lors de la finalisation de l'architecture :

```python
class UniversalEvent(BaseModel):
    # ... champs existants ...

    # Contexte container/K8s (ajout v1.1)
    container_id: str | None         # ex: "a1b2c3d4e5f6"
    container_name: str | None       # ex: "nginx"
    pod_name: str | None             # ex: "nginx-7d4b9c-xk2p1"
    namespace: str | None            # ex: "production"

    # Observabilité
    trace_id: str | None             # OTel trace_id propagé
    request_id: str | None           # X-Request-ID de la requête API originante

    # Qualité du signal
    collector_version: str           # ex: "1.2.0" — pour détecter régressions collecte
    dedup_key: str | None            # hash pour déduplication events identiques en burst
```

### 13.3 Règles — table `rule_versions` pour historique

```sql
CREATE TABLE rule_versions (
    version_id      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         VARCHAR(100)    NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    version_num     INTEGER         NOT NULL,
    condition_yaml  TEXT            NOT NULL,
    changed_by      VARCHAR(100)    NOT NULL,
    changed_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    change_note     TEXT,
    UNIQUE (rule_id, version_num)
);
```

Chaque `PUT /rules/{id}` incrémente `version_num` et insère une entrée. Permet de rejouer les détections sur un historique d'events avec une version antérieure d'une règle.

### 13.4 Rate limiting

Implémenté en FastAPI middleware via token bucket par identité (API key ou user_id).

| Limite | Scope | Valeur par défaut |
|--------|-------|-------------------|
| Requests/minute | par user JWT | 600 req/min |
| Requests/minute | par API key | 300 req/min |
| Burst max | tous | 50 requêtes instantanées |
| `GET /events` avec gros `limit` | par user | 10 req/min |
| Export PDF/ZIP | par user | 5 req/min |

Dépassement → `HTTP 429 Too Many Requests` + header `Retry-After: <seconds>`.

Le compteur est stocké dans Redis (`INCR` + `EXPIRE`) pour être partagé entre les réplicas du server.

### 13.5 Environnements et variables de configuration

Toutes les variables d'environnement sont validées au démarrage via `pydantic-settings`.

```python
# server/oseye/config.py
class Settings(BaseSettings):
    # Runtime
    OSEYE_ENV: Literal["development", "staging", "production"] = "development"

    # Bus
    OSEYE_BUS_BACKEND: Literal["memory", "redis", "kafka"] = "memory"
    OSEYE_BUS_REDIS_URL: str = "redis://localhost:6379"
    OSEYE_BUS_KAFKA_BROKERS: str = "localhost:9092"

    # Storage
    OSEYE_DB_BACKEND: Literal["sqlite", "postgresql"] = "sqlite"
    OSEYE_DB_URL: str = "sqlite+aiosqlite:///./oseye_dev.db"
    OSEYE_DB_CLICKHOUSE_URL: str | None = None  # None = pas de ClickHouse

    # Auth
    OSEYE_JWT_PRIVATE_KEY_PATH: str
    OSEYE_JWT_PUBLIC_KEY_PATH: str
    OSEYE_JWT_ACCESS_TTL_S: int = 900      # 15 min
    OSEYE_JWT_REFRESH_TTL_S: int = 604800  # 7 jours

    # TLS / gRPC
    OSEYE_TLS_CERT: str
    OSEYE_TLS_KEY: str
    OSEYE_CA_CERT: str
    OSEYE_GRPC_PORT: int = 50051

    # Observabilité
    OSEYE_OTEL_ENDPOINT: str | None = None    # None = traces désactivées
    OSEYE_LOG_LEVEL: str = "INFO"

    # TI providers
    OSEYE_ABUSEIPDB_KEY: str | None = None
    OSEYE_VIRUSTOTAL_KEY: str | None = None
    OSEYE_MISP_URL: str | None = None
    OSEYE_MISP_KEY: str | None = None

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
```

### 13.6 Platform Driver — guide d'ajout d'un nouvel OS

Pour ajouter le support d'un nouvel OS (ex : FreeBSD, OpenBSD, Solaris), il suffit de :

**Côté agent (Go) :**

1. Créer `agent/internal/platform/freebsd/driver.go` avec build tag `//go:build freebsd`
2. Implémenter `PlatformDriver` (interface §3.1) et enregistrer via `init()`
3. Créer les collectors dans `agent/internal/platform/freebsd/` (dtrace/, auditpipe/, kqueue/...)
4. Ajouter `freebsd` dans la matrice CI : `.github/workflows/ci.yml` `GOOS: [linux, windows, darwin, freebsd]`

```go
// agent/internal/platform/freebsd/driver.go
//go:build freebsd

package freebsd

import (
    "github.com/oseye/agent/internal/platform"
    "github.com/oseye/agent/internal/collector"
    "github.com/oseye/agent/internal/config"
)

type FreeBSDDriver struct{}

func (d *FreeBSDDriver) Name() string { return "freebsd" }

func (d *FreeBSDDriver) Collectors(cfg *config.Config) ([]collector.Collector, error) {
    return []collector.Collector{
        dtrace.NewCollector(cfg),
        auditpipe.NewCollector(cfg),
        kqueue.NewCollector(cfg),
    }, nil
}

func (d *FreeBSDDriver) Capabilities() platform.PlatformCapabilities {
    return platform.PlatformCapabilities{
        HasKernelTracing: true,   // DTrace
        HasFileAudit:     true,   // auditpipe
        HasNetworkAudit:  true,
    }
}

func init() { platform.Register(&FreeBSDDriver{}) }
```

**Côté server (Python) :**

1. Créer `server/oseye/normalizer/adapters/freebsd/` avec les adapters pour chaque source
2. Enregistrer dans `NormalizerEngine` : `adapters["dtrace"] = DTraceAdapter()`
3. Ajouter les profils de surveillance dans `rules/profiles/freebsd_*.yaml` si besoin

**Matrice de couverture collectors par OS :**

| Capacité | Linux | Windows | macOS | FreeBSD* |
|----------|-------|---------|-------|---------|
| Kernel syscall tracing | eBPF | ETW | EndpointSecurity | DTrace |
| File audit | fanotify + inotify | — | FSEvents | kqueue |
| Process audit | procfs + auditd | WMI + WinLog | OpenBSM | procstat |
| Network audit | netlink | WinLog (5156/5157) | pktap | ipfw/pf logs |
| Log system | journald + syslog | Event Log | Unified Log | syslog |
| Registry | — | Registry watcher | — | — |
| Privilege escalation | auditd | WinLog 4672 | OpenBSM | auditpipe |

*FreeBSD : driver non livré en v1.0, interface prête.

---

## Annexe — Fichiers critiques à créer en premier

Ces 5 fichiers sont des contrats dont tout le reste dépend. Ils doivent être finalisés avant d'écrire tout autre code fonctionnel.

| Fichier | Rôle |
|---------|------|
| `proto/event.proto` | Définition canonique de `UniversalEvent` — codegen Go+Python depuis ce fichier |
| `server/oseye/core/schema.py` | Modèles Pydantic (`UniversalEvent`, `Alert`, `Decision`, `ForensicCase`, `Rule`, `SurveillanceProfile`) — importés par tous les composants server |
| `server/oseye/bus/interface.py` | Protocol `EventBus` — aucun composant n'importe jamais un backend directement |
| `agent/internal/platform/interface.go` | Interface `PlatformDriver` + `PlatformCapabilities` — tout driver OS doit l'implémenter |
| `agent/internal/platform/registry.go` | Registre des drivers (auto-enregistrement via `init()`) — résout le bon driver selon `runtime.GOOS` |
| `agent/internal/collector/interface.go` | Interface `Collector` Go — contrat pour tous les collectors, tous OS confondus |
| `server/oseye/storage/interface.py` | Protocols Repository — détermine le contrat storage avant d'écrire le moindre backend |
| `server/oseye/storage/router.py` | `StorageRouter` — règle de routage PG vs ClickHouse, doit exister avant tout `insert_batch` |
| `server/oseye/config.py` | `Settings` pydantic-settings — toutes les variables d'env validées au démarrage |
| `server/oseye/core/observability.py` | Setup OTel + logger JSON structuré — initialisé avant tout autre composant |
