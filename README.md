# OSEye

**OSEye** est une plateforme EDR/SIEM Linux open-core — légère, modulaire et intelligente.

Elle collecte les événements système en temps réel (eBPF, auditd, procfs, réseau), les normalise, les analyse via un moteur de règles et un moteur ML, corrèle les incidents, prend des décisions autonomes et les présente dans un dashboard web.

## Fonctionnalités clés

- **9 collecteurs Linux** — eBPF, auditd, fanotify, inotify, procfs, netlink, journald, udev, syslog
- **Détection rule-based** — 30+ règles YAML MITRE ATT&CK, hot-reload, timeframes
- **ML comportemental** — IsolationForest online (River), baseline par entité
- **Threat Intelligence** — AbuseIPDB, VirusTotal, MISP, STIX/TAXII
- **Corrélation** — reconstruction de chaînes d'incidents multi-events
- **Decision Engine** — 8 types de décisions, matrice risque, journal immutable
- **Forensics** — gestion de cas, custody log, exports PDF/MISP/TheHive
- **Plugin SDK** — extensions Python sandboxées, signées Ed25519
- **Multi-OS** — agent Go compilé pour Linux, Windows, macOS

## Architecture

```
[Agent Go]  ──gRPC/mTLS──►  [Server Python]
  eBPF                         Normalizer
  auditd                       Rule Engine
  procfs                  ──►  ML Engine
  ...                          TI Engine
                               Correlation
                               Decision Engine
                               FastAPI REST + WebSocket
                                    │
                               [SQLite / PostgreSQL / ClickHouse]
```

Voir [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) pour la documentation complète.

## Démarrage rapide

```bash
# Prérequis : Docker, Docker Compose
git clone https://github.com/your-org/oseye.git
cd oseye

# Générer les certificats dev et le code Protobuf
./scripts/generate_certs.sh
./scripts/generate_proto.sh

# Lancer l'environnement complet
docker compose -f infra/docker/docker-compose.dev.yml up -d

# Vérifier que le server répond
curl http://localhost:8000/api/v1/health
```

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| Agent | Go 1.23, eBPF (cilium/ebpf), gRPC |
| Server | Python 3.12, FastAPI, SQLAlchemy 2.0 |
| ML | River (online learning), scikit-learn |
| Bus | Redis Streams (dev) / Kafka (prod) |
| Stockage | SQLite (dev) / PostgreSQL + ClickHouse (prod) |
| UI | React 18, TypeScript, Vite, Tailwind |
| Déploiement | Docker, Helm (K8s), Ansible |

## Cibles de performance

- CPU agent : **< 2%** en mode standard
- Latence détection : **< 500ms** event → alerte
- Débit : **> 100 000 events/s**
- Faux positifs : **< 5%**

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Architecture complète — stack, interfaces, API, schémas DB |
| [`docs/PLAN_ACTION.md`](docs/PLAN_ACTION.md) | 188 tâches, phases de développement, statuts |
| [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md) | Plan modulaire Phase 1 — branches, modules, critères |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Comment contribuer — workflow, conventions, reviews |
| [`SECURITY.md`](SECURITY.md) | Politique de sécurité — signalement de vulnérabilités |

## Contribuer

Lire [`CONTRIBUTING.md`](CONTRIBUTING.md). Les contributions sont bienvenues — voir [`docs/PLAN_ACTION.md`](docs/PLAN_ACTION.md) pour les tâches disponibles.

## Licence

Apache 2.0 — voir [`LICENSE`](LICENSE).
