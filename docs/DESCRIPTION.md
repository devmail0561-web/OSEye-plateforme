# OSEye — Description du Projet

**Version:** 1.0  
**Date:** 2026-08-06  
**Classification:** Confidentiel — usage interne

---

## Vue d'ensemble

**OSEye** est une plateforme EDR (Endpoint Detection and Response) / SIEM (Security Information and Event Management) open-core conçue pour Linux, Windows et macOS. Elle vise à égaler les solutions commerciales (CrowdStrike, SentinelOne, Wazuh) tout en restant légère, modulaire, extensible et accessible.

### Mission

Fournir une solution de détection, d'analyse comportementale et de réponse aux incidents qui :
- Collecte les événements système en temps réel à la source (kernel, logs, réseau)
- Détecte les menaces via des règles MITRE ATT&CK et du machine learning
- Corrèle les événements pour reconstruire les chaînes d'attaque
- Prend des décisions autonomes (alertes, blocages, isolement)
- Offre une interface web intuitive pour l'investigation forensique

### Statut actuel

**Phase 1 complétée** (août 2026) :
- Pipeline ingestion → stockage → query opérationnel
- Agent Go avec collecteur eBPF Linux fonctionnel
- Serveur Python avec API REST + gRPC
- Tests de charge validés (100k events/s)
- Communication agent↔server sécurisée (mTLS)

**Prochaine étape :** Phase 2 — complétion des 9 collecteurs Linux et robustesse agent

---

## Objectifs techniques

### Cibles de performance

| Métrique | Cible | Justification |
|----------|-------|---------------|
| **CPU agent** | < 2% | Ne pas impacter les applications métier |
| **Mémoire agent** | < 150 MB | Déployable sur VMs contraintes |
| **Latence détection** | < 500 ms | De l'événement kernel à l'alerte |
| **Débit** | > 100k events/s | Clusters haute charge (CI/CD, HPC) |
| **Faux positifs** | < 5% | Éviter la fatigue d'alerte des SOC |
| **Couverture tests** | > 80% | Fiabilité production |

### Compatibilité

- **Linux** : RHEL 8+, Ubuntu 20.04+, Debian 11+, SUSE SLES 15+ (kernel 5.4+)
- **Windows** : Server 2019+, 10/11 (build 1809+)
- **macOS** : 12 Monterey+
- **Architectures** : amd64, arm64

---

## Architecture fonctionnelle

### Composants principaux

```
┌─────────────────────────────────────────────────────────────┐
│                        OSEye Agent                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Platform Drivers (eBPF, auditd, ETW, EndpointSec)  │   │
│  └────────────────┬─────────────────────────────────────┘   │
│                   │ RawEvent                                │
│  ┌────────────────▼─────────────────────────────────────┐   │
│  │  Normalizer → UniversalEvent (Protobuf)             │   │
│  └────────────────┬─────────────────────────────────────┘   │
│                   │                                         │
│  ┌────────────────▼─────────────────────────────────────┐   │
│  │  Enricher (hash, size, user lookup, geo)            │   │
│  └────────────────┬─────────────────────────────────────┘   │
│                   │                                         │
│  ┌────────────────▼─────────────────────────────────────┐   │
│  │  Hash Chain + Tamper Detection                       │   │
│  └────────────────┬─────────────────────────────────────┘   │
│                   │ gRPC/mTLS                               │
└───────────────────┼─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                      OSEye Server                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  gRPC Ingestion Service (auth, rate limit)          │   │
│  └────────────────┬─────────────────────────────────────┘   │
│                   │                                         │
│  ┌────────────────▼─────────────────────────────────────┐   │
│  │  Event Bus (Redis Streams / Kafka)                  │   │
│  └────┬───────────┬───────────┬───────────┬─────────────┘   │
│       │           │           │           │                 │
│   ┌───▼────┐  ┌──▼─────┐ ┌───▼─────┐ ┌───▼──────┐          │
│   │  Rule  │  │   ML   │ │  Threat │ │Correlation│          │
│   │ Engine │  │ Engine │ │  Intel  │ │  Engine   │          │
│   └───┬────┘  └──┬─────┘ └───┬─────┘ └───┬──────┘          │
│       │          │           │           │                 │
│       └──────────┴───────────┴───────────┘                 │
│                   │                                         │
│  ┌────────────────▼─────────────────────────────────────┐   │
│  │  Decision Engine (8 décisions, matrice risque)      │   │
│  └────────────────┬─────────────────────────────────────┘   │
│                   │                                         │
│  ┌────────────────▼─────────────────────────────────────┐   │
│  │  Storage (ClickHouse + PostgreSQL)                  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  FastAPI REST + WebSocket                           │   │
│  └────────────────┬─────────────────────────────────────┘   │
└───────────────────┼─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                        OSEye UI                             │
│  Dashboard · Timeline · Alerts · Cases · Reports · Plugins  │
└─────────────────────────────────────────────────────────────┘
```

### Collecteurs (9 sources Linux)

1. **eBPF** — Hooks kernel (syscalls, TCP, DNS) sans overhead
2. **auditd** — Audit framework Linux (syscalls, fichiers sensibles)
3. **fanotify** — Surveillance fichiers temps réel (accès, modification)
4. **inotify** — Surveillance répertoires (create, delete, move)
5. **procfs** — Snapshot processus (/proc scan périodique)
6. **netlink** — Événements kernel réseau (connexions, interfaces)
7. **journald** — Logs systemd centralisés
8. **udev** — Périphériques USB/HID branchés/débranchés
9. **syslog** — Logs applicatifs traditionnels

**Windows** : ETW (Event Tracing for Windows), Windows Event Log, Registry, Sysmon  
**macOS** : EndpointSecurity, FSEvents, Unified Logging

---

## Moteurs de détection

### 1. Rule Engine (détection statique)

- **30+ règles YAML/TOML** couvrant MITRE ATT&CK :
  - Credential Access (shadow file, hashdump, keychain)
  - Privilege Escalation (sudo abuse, SUID binaries)
  - Persistence (cron, systemd services, startup items)
  - Defense Evasion (log clearing, rootkits)
  - Lateral Movement (SSH brute-force, RDP)
- **Hot-reload** sans redémarrage
- **Timeframes** : détection de patterns temporels (5 failed SSH en 60s)
- **Sévérité** : LOW, MEDIUM, HIGH, CRITICAL
- **Actions** : LOG, ALERT, BLOCK, ISOLATE

### 2. ML Engine (détection comportementale)

- **Baseline comportemental par entité** :
  - Utilisateur (commandes habituelles, horaires, IPs sources)
  - Processus (parents normaux, fichiers accédés, réseau)
  - Hôte (charge CPU/réseau, processus démarrés)
- **Algorithmes** :
  - `IsolationForest` online (River) pour détection d'anomalies
  - Classifier MITRE ATT&CK (phases : Recon → Exploit → Lateral → Exfil)
- **Features** : 23 dimensions (CPU, network bytes, rare commands, rare IPs, time-of-day, ...)
- **Retraining** : incrémental toutes les 24h (pas de batch lourd)

### 3. Threat Intelligence

- **Enrichissement IP/domaine/hash** via APIs externes :
  - AbuseIPDB (réputation IP)
  - VirusTotal (hash fichiers)
  - MISP (IOCs partagés)
  - STIX/TAXII (standards CTI)
- **Cache local Redis** (TTL 7 jours) pour limiter les requêtes API
- **Score agrégé** : CLEAN, SUSPICIOUS, MALICIOUS

### 4. Correlation Engine

- **Reconstruction de chaînes d'attaque** :
  - Process tree (parent → enfant)
  - File access chain (qui a modifié quoi)
  - Network flow (IP source → dest, ports)
- **Graphes temporels** : timeline unifiée multi-events
- **Hypothèses d'incidents** : cluster d'événements anormaux groupés

---

## Decision Engine (nouveau dans v4)

### 8 types de décisions autonomes

| Décision | Description | Exemple |
|----------|-------------|---------|
| **LOG** | Enregistrer sans alerter | Commande shell standard |
| **ALERT** | Notifier SOC | SSH brute-force détecté |
| **BLOCK_PROCESS** | Kill le processus | Cryptominer lancé |
| **BLOCK_NETWORK** | Bloquer IP via iptables/nftables | C2 callback détecté |
| **ISOLATE_HOST** | Couper réseau (firewall) | Ransomware actif |
| **QUARANTINE_FILE** | Déplacer fichier en zone isolée | Malware téléchargé |
| **TRIGGER_FORENSIC** | Snapshot disque/mémoire | Incident critique |
| **INVOKE_PLUGIN** | Exécuter plugin custom | Remédiation automatique |

### Matrice de décision

Combinaison de :
- **Sévérité règle** : LOW/MEDIUM/HIGH/CRITICAL
- **Score TI** : CLEAN/SUSPICIOUS/MALICIOUS
- **Score ML** : anomalie_score [0-1]
- **Contexte** : criticité hôte (prod/dev), horaire (working hours), user privilege

**Exemple** :
```
IF severity=CRITICAL AND ti_score=MALICIOUS AND host_criticality=PROD
  THEN decision=ISOLATE_HOST + TRIGGER_FORENSIC
ELSE IF severity=HIGH AND ml_anomaly_score > 0.8
  THEN decision=ALERT + BLOCK_PROCESS
```

### Journal de décisions immutable

- **Hash chain** : chaque décision référence le hash de la précédente
- **Signatures Ed25519** : intégrité prouvée en cas d'audit légal
- **Exports** : PDF, MISP, TheHive

---

## Plugin SDK (extensibilité)

### Caractéristiques

- **Langage** : Python 3.12+ (sandboxé via `RestrictedPython`)
- **Cycle de vie** :
  1. Développement : template SDK fourni
  2. Signature : `ed25519` keypair (privée gardée secrète)
  3. Upload : UI OSEye ou API REST
  4. Validation : vérification signature avant exécution
  5. Activation : règles peuvent invoquer le plugin
- **API disponible** :
  - `context.event` : événement courant
  - `context.get_related_events(time_window)` : contexte temporel
  - `context.execute(command)` : remédiation (sandboxée)
  - `context.notify(channel, message)` : alertes Slack/email

### Cas d'usage

- **Auto-remediation** : kill processus + delete fichiers malveillants
- **Enrichissement custom** : lookup interne d'asset (CMDB)
- **Notification** : webhook vers SOAR (TheHive, Cortex)
- **Forensics** : dump mémoire processus suspect

---

## Forensics & Case Management

### Cas d'investigation

- **Création manuelle** ou **automatique** (règle → case)
- **Custody log** : toute action sur un cas est tracée (qui, quand, quoi)
- **Evidence attachée** :
  - Événements liés (filtres sauvegardés)
  - Fichiers récupérés (binaires suspects)
  - Dumps mémoire/disque
  - Logs externes

### Exports conformes

- **PDF** : rapport exécutif avec timeline, IOCs, décisions
- **MISP** : publication d'IOCs vers communauté
- **TheHive/Cortex** : intégration SOAR
- **STIX 2.1** : standard CTI interopérable

---

## Déploiement

### Modes supportés

| Mode | Cible | Déploiement |
|------|-------|-------------|
| **Dev/test** | Laptop, VM | SQLite + Redis in-memory |
| **Standalone** | Serveur unique | PostgreSQL + Redis Streams |
| **Clustered** | 3-5 nœuds | PostgreSQL HA + Kafka |
| **Scale-out** | > 100 agents | ClickHouse + Kafka multi-brokers |
| **Kubernetes** | Cloud-native | Helm chart + StatefulSets |

### Packages disponibles

- **Linux** : `.deb` (Debian/Ubuntu), `.rpm` (RHEL/CentOS/Fedora)
- **Windows** : `.msi` (GUI installer), `.exe` (silent install)
- **macOS** : `.pkg` (Apple Installer)
- **Docker** : `ghcr.io/oseye/agent`, `ghcr.io/oseye/server`, `ghcr.io/oseye/ui`
- **Kubernetes** : Helm chart (`helm install oseye oseye/oseye`)

### Automation

- **Ansible** : playbook fourni (`infra/ansible/`)
- **Terraform** : modules AWS/GCP/Azure (`infra/terraform/`)
- **Puppet/Chef** : manifests fournis

---

## Sécurité

### Principe "Secure by Design"

1. **Authentification mutuelle** : agent ↔ server via mTLS (certificats client)
2. **Chiffrement end-to-end** : gRPC/TLS 1.3, cipher suites modernes
3. **Intégrité événements** : hash chain BLAKE3 + signatures Ed25519
4. **Secrets management** : HashiCorp Vault en production
5. **RBAC** : 4 rôles (Admin, Analyst, Viewer, Plugin Developer)
6. **Audit log** : toute action admin tracée (immutable)
7. **Plugin sandbox** : `RestrictedPython`, pas d'accès filesystem/network direct

### Conformité

- **RGPD** : anonymisation PII possible (regex sur champs sensibles)
- **ISO 27001** : logs d'audit centralisés, custody chain
- **SOC 2 Type II** : métriques SLA, disponibilité >99.5%

---

## Observabilité (plateforme elle-même)

### Métriques exposées

- **Prometheus** : `/metrics` endpoint sur server
  - `oseye_events_ingested_total` (counter)
  - `oseye_rules_evaluated_duration_seconds` (histogram)
  - `oseye_alerts_generated_total` (counter par severity)
  - `oseye_decisions_taken_total` (counter par type)
- **Grafana** : dashboards pré-configurés fournis

### Logs structurés

- **Format** : JSON avec champs standard (timestamp, level, service, event_id, ...)
- **Sortie** : stdout (capturé par systemd/Docker), ou syslog, ou fichier
- **Niveaux** : DEBUG (dev), INFO (prod), WARN, ERROR, CRITICAL

### Tracing distribué (roadmap Phase 11)

- **OpenTelemetry** : span par événement (agent → server → engines → storage)
- **Jaeger** : visualisation latence end-to-end

---

## Modèle économique (open-core)

### Open Source (Apache 2.0)

- **Core engine** : collecteurs, rule engine, API, storage, UI basique
- **Règles MITRE** : 30+ règles baseline
- **Documentation** : complète, publique
- **Communauté** : GitHub, Discord, forums

### Enterprise (licence commerciale)

- **ML avancé** : deep learning (transformers pour NLP sur logs)
- **TI premium** : feeds commerciaux supplémentaires
- **Plugin marketplace** : plugins certifiés payants
- **Support SLA** : 24/7, hotline, onboarding
- **Formations** : certifications SOC analyst, threat hunter
- **Features** : multi-tenancy, SAML/SSO, audit report generator

---

## Roadmap

### 2026 (v1.x)

- **Q3** : Phase 1-3 — pipeline complet + détection rule-based
- **Q4** : Phase 4-6 — TI + ML + Decision Engine

### 2027 (v2.x)

- **Q1** : Phase 7-8 — Forensics + Plugin SDK
- **Q2** : Phase 9-10 — UI finale + hardening
- **Q3** : v2.0 GA — production-ready
- **Q4** : Phase 11 — scaling (multi-region, ClickHouse clustering)

### 2028+ (v3.x)

- **Cloud SaaS** : OSEye Cloud (agents → cloud-hosted server)
- **Managed agents** : agent as a service (pas d'install local)
- **AI Threat Hunter** : LLM pour investigation automatique (GPT-4 fine-tuned)
- **Deception tech** : honeypots intégrés
- **Zero-trust integration** : push verdicts vers firewalls (Palo Alto, Fortinet)

---

## Références

| Document | Description |
|----------|-------------|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Architecture logicielle complète — stack, interfaces, API, DB |
| [`PLAN_ACTION.md`](PLAN_ACTION.md) | 188 tâches détaillées, phases, dépendances |
| [`DEVELOPMENT_PLAN.md`](DEVELOPMENT_PLAN.md) | Plan de développement Phase 1 |
| [`PROGRESS.md`](PROGRESS.md) | Suivi hebdomadaire de l'avancement |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Guide de contribution |
| [`SECURITY.md`](../SECURITY.md) | Politique de sécurité |

---

**Auteur :** @virus-one  
**Dernière mise à jour :** 2026-08-06  
**Statut :** Vivant — mis à jour à chaque phase
