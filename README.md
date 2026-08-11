# OSEye

**OSEye** est une plateforme EDR/SIEM Linux open-core — légère, modulaire et intelligente.

Elle collecte les événements système en temps réel (eBPF, auditd, procfs, réseau), les normalise, les analyse via un moteur de règles et un moteur ML, corrèle les incidents, prend des décisions autonomes avec réponse active, et les présente dans un dashboard web.

## Fonctionnalités clés

- **9 collecteurs Linux** — eBPF, auditd, fanotify, inotify, procfs, netlink, journald, udev, syslog
- **Détection rule-based** — 35+ règles YAML MITRE ATT&CK, hot-reload, timeframes
- **ML comportemental** — HalfSpaceTrees online (River), baseline par entité, classifieur MITRE online, checkpoint automatique
- **Threat Intelligence** — AbuseIPDB, VirusTotal, MISP, circuit breaker par provider
- **Corrélation** — reconstruction d'incidents multi-events, auto-clôture
- **Decision Engine** — 8 types de décisions, matrice risque, journal immutable BLAKE3
- **Response Engine** — blocage IP (nftables/iptables), quarantaine fichier, kill processus — act-then-notify avec rollback admin
- **Forensics** — gestion de cas, custody log, exports PDF/MISP/TheHive
- **Plugin SDK** — extensions Python sandboxées (AnalyzerPlugin, ExporterPlugin, CollectorPlugin), signature Ed25519 requise en prod, upload depuis le dashboard
- **6 profils de surveillance** — workstation, server, investigation, minimal, compliance, stealth — hot-swap via dashboard
- **Dashboard UI** — React 18 TypeScript, sidebar repliable, pages analyste + pages admin RBAC

## Architecture

```
[Agent Go]  ──gRPC/mTLS TLS1.3──►  [Server Python]
  eBPF                                Normalizer
  auditd                              Rule Engine (35 règles, hot-reload)
  procfs           ◄──commands──      ML Engine (online, checkpoint 5min)
  responder                           TI Engine (3 providers)
  (BLOCK_IP                           Correlation Engine
   QUARANTINE_FILE                    Decision Engine → Response Engine
   KILL_PROCESS)                      Policy Engine (6 profils)
                                      Plugin System (IPC Unix socket)
                                      FastAPI REST + WebSocket
                                           │
                                      [SQLite / PostgreSQL / ClickHouse]
```

Voir [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) pour la documentation complète.

## Démarrage rapide

```bash
# Prérequis : Go 1.23+, Python 3.12+, make
git clone https://github.com/your-org/oseye.git
cd oseye

# Générer certificats dev + stubs Protobuf
./scripts/generate_certs.sh
./scripts/generate_proto.sh

# Lancer le serveur (SQLite + InMemoryBus)
make run-server

# Lancer l'UI (port 5173)
make ui-dev

# Vérifier
curl http://localhost:8000/api/v1/health
```

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| Agent | Go 1.23, eBPF (cilium/ebpf), gRPC, backoff full-jitter |
| Server | Python 3.12, FastAPI, SQLAlchemy 2.0, asyncio |
| ML | River (HalfSpaceTrees + LogisticRegression online), checkpoint pickle |
| Bus | InMemoryBus (dev) / Redis Streams (prod) / Kafka (distribué) |
| Stockage | SQLite (dev) / PostgreSQL + ClickHouse (prod) |
| UI | React 18, TypeScript, Vite, Tailwind, Lucide, Recharts, D3 |
| Déploiement | Docker, Helm (K8s), Ansible, .deb/.rpm |

## Sécurité des communications

| Principe | Mécanisme |
|----------|-----------|
| **Confidentialité** | mTLS strict (TLS 1.3 uniquement, `GRPC_SSL_CIPHER_SUITES`) — refus démarrage si certs absents |
| **Intégrité** | Hash chain BLAKE3 par event + signature Ed25519 par batch (clé dédiée `OSEYE_ED25519_SIGNING_KEY`) |
| **Disponibilité** | Buffer SQLite offline, backoff full-jitter, révocation agent persistée (`DELETE /api/v1/agents/{cn}`) |

## Plugin SDK

```bash
pip install -e sdk/
```

```python
from oseye_sdk.plugin import ExporterPlugin
from oseye_sdk.event import Event

class SlackNotifier(ExporterPlugin):
    name = "notifier_slack"

    def on_start(self) -> None: ...
    def on_stop(self) -> None: ...

    def export(self, event: Event) -> None:
        if event.severity == "critical":
            # envoyer vers Slack
            pass
```

Upload depuis le dashboard admin → `/api/v1/plugins/upload`. Signature Ed25519 vérifiée si `OSEYE_PLUGIN_REQUIRE_SIGNATURE=true`.

## Qualité

**293 tests Python** (unit + integration + scénarios), **20+ packages Go** — tout vert.

## Variables d'environnement clés

| Variable | Défaut dev | Description |
|----------|-----------|-------------|
| `OSEYE_SECRET_KEY` | — | Requis |
| `OSEYE_GRPC_INSECURE_DEV` | `false` | Autoriser gRPC sans TLS (dev uniquement) |
| `OSEYE_PLUGIN_REQUIRE_SIGNATURE` | `false` | Exiger signature Ed25519 pour les plugins |
| `OSEYE_DEFAULT_SURVEILLANCE_PROFILE` | `workstation` | Profil poussé aux agents à la connexion |
| `OSEYE_ML_CHECKPOINT_PATH` | `/var/lib/oseye/ml_checkpoint.pkl` | Persistance modèles ML |
| `OSEYE_ED25519_SIGNING_KEY` | `/etc/oseye/certs/agent.ed25519.key` | Clé signature batches agent |

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Architecture complète — stack, interfaces, API, sécurité |
| [`docs/PROGRESS.md`](docs/PROGRESS.md) | Suivi de progression — phases, modules, correctifs |
| [`SECURITY.md`](SECURITY.md) | Politique de sécurité — signalement, mécanismes CIA |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Workflow de contribution |
| [`sdk/README.md`](sdk/README.md) | Documentation du Plugin SDK |

## Licence

Apache 2.0 — voir [`LICENSE`](LICENSE).
