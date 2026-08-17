<div align="center">

<h1>
  <img src="https://img.shields.io/badge/OSEye-0d1117?style=flat-square&labelColor=0d1117&color=0d1117" alt="" />
  <br/>
  OSEye
</h1>

<p><em>La plateforme EDR/SIEM Linux qui voit tout — légère, modulaire et intelligente</em></p>

<br/>

[![Licence](https://img.shields.io/badge/Licence-Apache_2.0-0078d4?style=flat-square)](LICENSE)
[![Agent](https://img.shields.io/badge/Agent-Go_1.23-00ADD8?style=flat-square&logo=go&logoColor=white)](agent/)
[![Server](https://img.shields.io/badge/Server-Python_3.12-3776AB?style=flat-square&logo=python&logoColor=white)](server/)
[![eBPF](https://img.shields.io/badge/Collecteur-eBPF-f97316?style=flat-square)](agent/internal/platform/linux/ebpf/)
[![ML](https://img.shields.io/badge/ML-River_online-8b5cf6?style=flat-square)](server/oseye/ml_engine/)
[![UI](https://img.shields.io/badge/UI-React_18-61DAFB?style=flat-square&logo=react&logoColor=black)](ui/)
[![Transport](https://img.shields.io/badge/Transport-mTLS_TLS_1.3-22c55e?style=flat-square)](SECURITY.md)
[![Tests](https://img.shields.io/badge/Tests-293_Python_%7C_20%2B_Go-16a34a?style=flat-square)](#qualité)

<br/>

</div>

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

Voir la [documentation complète](https://devmail0561-web.github.io/OSEye-plateforme/) pour les détails techniques.

## Démarrage rapide

```bash
# Prérequis : Go 1.23+, Python 3.12+, make
git clone https://github.com/devmail0561-web/OSEye-plateforme.git
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
| Agent | Go 1.23, eBPF (cilium/ebpf), gRPC, backoff full-jitter, `oseye-config` CLI |
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

## Configuration agent

L'agent se configure via variables d'environnement (fichier `/etc/oseye/agent.env` chargé par systemd). L'outil CLI `oseye-config` permet de gérer la configuration en toute sécurité :

```bash
# Afficher la config effective
oseye-config show

# Valider la configuration courante
oseye-config validate

# Modifier une valeur (validation + écriture atomique)
oseye-config set OSEYE_GRPC_ADDR=server.prod:50051

# Vérifier que les certificats existent
oseye-config check-files
```

Toutes les valeurs sont validées strictement au démarrage (ports numériques, paths absolus, UUID v4, bounds CPU/RAM/batch).

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
| [Site officiel](https://devmail0561-web.github.io/OSEye-plateforme/) | Documentation complète — installation, configuration, déploiement |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | **Guide de déploiement production** — Docker, PKI, secrets, scaling |
| [`docs/AGENT_CLI.md`](docs/AGENT_CLI.md) | **Guide CLI agent** — `oseye-agent` vs `oseye-config`, enrollment, configuration |
| [`docs/SERVER_CLI.md`](docs/SERVER_CLI.md) | **Guide CLI serveur** — init, setup, validation, variables d'environnement |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | **Dépannage** — 10 problèmes courants avec solutions |
| [`docs/DESCRIPTION.md`](docs/DESCRIPTION.md) | Description fonctionnelle du projet |
| [`SECURITY.md`](SECURITY.md) | Politique de sécurité — signalement, mécanismes CIA |
| [`CHANGELOG.md`](CHANGELOG.md) | Historique des versions |
| [`sdk/README.md`](sdk/README.md) | Documentation du Plugin SDK |

## Licence

Apache 2.0 — voir [`LICENSE`](LICENSE).

---

Copyright 2026 M. Tendeng — voir [`NOTICE.md`](NOTICE.md).
