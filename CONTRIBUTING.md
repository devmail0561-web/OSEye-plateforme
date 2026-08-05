# Guide de contribution — OSEye

**Version :** 1.0  
**Date :** 2026-07-28

---

## Bienvenue

OSEye est un projet EDR/SIEM open-core pour Linux/Windows/macOS. Ce guide explique comment contribuer du code, tester, et faire reviewer son travail.

---

## 1. Avant de commencer

### 1.1 Prérequis techniques

| Composant | Version minimum |
|-----------|----------------|
| Go | 1.23+ |
| Python | 3.12+ |
| Node.js | 20+ |
| Docker | 24+ |
| Git | 2.40+ |

### 1.2 Lire la documentation

Avant de coder :
1. **`docs/ARCHITECTURE.md`** — architecture complète, interfaces contrats, patterns
2. **`docs/PLAN_ACTION.md`** — 188 tâches, statuts, dépendances
3. **`.github/PULL_REQUEST_TEMPLATE.md`** — checklist de vérification avant PR

### 1.3 Setup environnement local

```bash
# Cloner le repo
git clone https://github.com/your-org/oseye.git
cd oseye

# Générer les certificats dev
./scripts/generate_certs.sh

# Générer le code Protobuf
./scripts/generate_proto.sh

# Lancer l'environnement de dev complet
docker-compose -f infra/docker/docker-compose.dev.yml up -d

# Tests
cd agent && go test ./...
cd ../server && pytest
cd ../ui && npm test
```

---

## 2. Choisir une tâche

### 2.1 Parcourir le plan d'action

Ouvrir `docs/PLAN_ACTION.md` et chercher :
- Tâches `[ ]` (disponibles)
- Dont toutes les dépendances sont `[x]`
- Préférer les tâches de votre zone d'expertise :
  - **Go / eBPF** → Phase 1–2 (collectors agent)
  - **Python / FastAPI** → Phase 3–5 (rule engine, API, workers)
  - **ML / data science** → Phase 6 (ML engine)
  - **React / TypeScript** → Phase 9 (dashboard UI)
  - **DevOps / K8s** → Phase 10 (hardening, packaging)

### 2.2 S'assigner

**Option 1 — Direct (contributeurs réguliers) :**
Modifier `PLAN_ACTION.md`, changer `[ ]` en `[~] [@votre_nom]`, commit sur `main` :
```bash
git checkout main
# Éditer PLAN_ACTION.md
git commit -am "Assign P2.03 to @alice"
git push
```

**Option 2 — Via Issue GitHub (nouveaux contributeurs) :**
Commenter sur l'issue de la Phase : "Je prends P2.03 — collecteur netlink".

### 2.3 Créer une branche

```bash
git checkout -b P2.03-netlink-collector
```

Format : `P<n>.<m>-<description-kebab-case>`

---

## 3. Implémenter la tâche

### 3.1 Référence architecture

Chaque tâche référence une section de `ARCHITECTURE.md`. Lire **avant** d'écrire du code :
- Section du composant (§3.X)
- Interface(s) concernée(s) (Annexe — fichiers contrats)
- Modèles de données (§4)

### 3.2 Conventions de code

#### Go (agent)

```go
// Toujours un build tag en première ligne si OS-spécifique
//go:build linux

package netlink

import (
    "context"
    "log/slog"  // logger structuré
)

// Interface satisfaite implicitement — vérifier à la compilation
var _ collector.Collector = (*NetlinkCollector)(nil)

// Toute goroutine démarre avec un context ou stopCh
func (c *NetlinkCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
    go c.worker(ctx, out)  // ctx propagé
    <-ctx.Done()
    return nil
}
```

**Lint obligatoire :** `golangci-lint run ./...` (config : `.golangci.yml`)

#### Python (server)

```python
"""Docstring : une ligne décrivant le module."""
from typing import AsyncIterator
import logging

from oseye.core.schema import UniversalEvent  # imports depuis oseye.*
from oseye.core.observability import get_logger

logger = get_logger(__name__)


async def process_events(bus: EventBus) -> AsyncIterator[UniversalEvent]:
    """Type hints stricts sur toutes les fonctions publiques."""
    async for topic, raw in bus.subscribe_pattern("events:*"):
        event = UniversalEvent.model_validate_json(raw)  # Pydantic v2
        logger.info("event_received", event_id=str(event.event_id))  # logs structurés
        yield event
```

**Lint obligatoire :** `ruff check .` + `mypy server/` (config : `pyproject.toml`)

#### TypeScript (UI)

```typescript
// Hooks React customs préfixés `use`
import { useState, useEffect } from 'react';
import { UniversalEvent } from '@/api/types';  // types générés depuis OpenAPI

export function useWebSocket(channel: string) {
  const [events, setEvents] = useState<UniversalEvent[]>([]);
  // ... implémentation
  return events;
}

// Composants préfixés majuscule
export function EventTimeline({ events }: { events: UniversalEvent[] }) {
  return <div>{/* ... */}</div>;
}
```

**Lint obligatoire :** `npm run lint` (ESLint + Prettier, config : `.eslintrc.json`)

### 3.3 Logs structurés JSON

**Go :**
```go
slog.Info("collector_started",
    slog.String("collector", c.Name()),
    slog.Int("throttle_pct", int(factor*100)),
)
```

**Python :**
```python
logger.info("rule_matched",
    rule_id=rule.id,
    event_id=str(event.event_id),
    severity=rule.severity,
)
```

Format final : `{"timestamp": "...", "level": "INFO", "service": "...", "rule_id": "...", ...}`

### 3.4 Pas de secrets en dur

Jamais de :
- Clés API dans le code (`VIRUSTOTAL_KEY = "abc123"`)
- Mots de passe dans les tests (`password="admin"`)
- URLs de prod hardcodées (`https://oseye.prod.internal`)

Utiliser :
- Variables d'environnement via `Settings` pydantic-settings (Python) ou `config.Config` (Go)
- Secrets Vault en prod (HashiCorp Vault)

---

## 4. Tests

### 4.1 Couverture obligatoire

**Minimum : 80%**. Vérifier avant de pousser :
```bash
# Go
go test -cover ./...

# Python
pytest --cov=oseye --cov-report=term-missing

# TypeScript
npm run test:coverage
```

### 4.2 Types de tests

| Type | Quand | Exemple |
|------|-------|---------|
| **Unitaire** | Fonction pure, parser, validator | `test_parse_ebpf_event` |
| **Intégration** | Interaction entre 2+ composants | `test_agent_to_server_grpc` |
| **E2E** | Scénario utilisateur complet | `test_attack_scenario_ssh_bruteforce` |

### 4.3 Nommage des tests

```
test_<ce_qui_est_testé>_<condition>_<résultat_attendu>
```

Exemples :
- `test_rule_engine_evaluate_shadow_read_returns_alert`
- `test_grpc_client_reconnect_after_network_loss_replays_buffer`
- `test_decision_journal_verify_detects_tampered_hash`

### 4.4 Pas de mocks pour la DB

Utiliser SQLite in-memory en test :
```python
@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
```

Mocks autorisés uniquement pour :
- Services externes (AbuseIPDB, VirusTotal, MISP)
- gRPC server (agent ↔ server)

---

## 5. Pull Request

### 5.1 Avant d'ouvrir la PR

Checklist locale :
```bash
# 1. Lint passe
golangci-lint run ./...         # Go
ruff check . && mypy server/    # Python
npm run lint                    # TypeScript

# 2. Tests passent
go test ./...
pytest
npm test

# 3. Build passe
go build ./agent/cmd/oseye-agent
docker build -t oseye-server:test ./server

# 4. Commit signé (GPG)
git commit -S -m "P2.03: Add netlink collector"
```

### 5.2 Format du commit message

```
P<n>.<m>: <Description impérative courte> (<50 chars)

<Corps optionnel détaillant le WHY, pas le WHAT.
Le code montre le WHAT.>

Refs: #<issue_number>
```

Exemples :
```
P1.18: Implement eBPF loader for execve/openat/connect

Loads compiled .o programs from embedded FS, attaches to tracepoints,
reads events from perf buffer. Handles verifier errors gracefully.

Refs: #42
```

### 5.3 Ouvrir la PR

```bash
git push origin P2.03-netlink-collector
```

Aller sur GitHub, cliquer "Compare & pull request".

**Template auto-rempli** : `.github/PULL_REQUEST_TEMPLATE.md` — remplir tous les `[ ]`.

### 5.4 Titre de la PR

```
[P<n>.<m>] <Description courte>
```

Exemples :
- `[P2.03] Add netlink collector for Linux network events`
- `[P3.07] Add 30 builtin detection rules (credential access, privesc, persistence)`

### 5.5 Description de la PR

La template contient :
- [ ] Lien vers la tâche du plan (`docs/PLAN_ACTION.md` ligne XX)
- [ ] Changements principaux (bullet points)
- [ ] Tests ajoutés (unitaires / intégration / E2E)
- [ ] Références architecture (ex: §3.1, §4.7)
- [ ] Breaking changes ? (Oui/Non)
- [ ] Screenshots (si UI)
- [ ] Plan de test manuel (si applicable)

---

## 6. Code Review

### 6.1 Qui review ?

**1 approbation obligatoire** d'un senior reviewer :
- **@virus-one** (lead, architecture)
- **@senior-dev-1** (Go/eBPF)
- **@senior-dev-2** (Python/ML)

### 6.2 Critères de revue

Le reviewer vérifie (checklist automatique via GitHub Actions) :

#### BLOCKER (bloque le merge)
- [ ] Faille de sécurité (injection SQL, XSS, commande OS non escapée)
- [ ] Fuite mémoire / goroutine leak
- [ ] Perte de données (événements droppés sans log)
- [ ] Violation d'une interface contrat (Annexe ARCHITECTURE.md)
- [ ] Tests < 80% de couverture

#### CRITICAL (bloque le merge)
- [ ] Bug fonctionnel majeur
- [ ] Performance inacceptable (agent > 4% CPU sur workload standard)
- [ ] Logs critiques absents (erreurs silencieuses)
- [ ] Documentation manquante pour API publique

#### MAJOR (à fixer post-merge acceptable)
- [ ] Code smell (duplication, complexité cyclomatique > 15)
- [ ] Manque de logs non-critiques
- [ ] Docstring/comments absents
- [ ] Imports non triés

#### MINOR (suggestions, non-bloquant)
- [ ] Typo dans les commentaires
- [ ] Style (préférer `if err != nil` plutôt que `if nil != err`)
- [ ] Suggestion d'amélioration

### 6.3 Répondre aux commentaires

- **BLOCKER/CRITICAL** → **obligatoire** de fixer avant merge
- **MAJOR** → fixer ou justifier pourquoi reporter
- **MINOR** → optionnel, fixer si rapide

Marquer les conversations résolues après avoir poussé le fix.

### 6.4 CI doit passer

GitHub Actions exécute :
```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - golangci-lint (Go)
      - ruff + mypy (Python)
      - eslint (TypeScript)

  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        go: [1.23]
        python: [3.12]
    steps:
      - go test -race -cover ./...
      - pytest --cov=oseye
      - npm test

  build:
    runs-on: ubuntu-latest
    steps:
      - docker build agent
      - docker build server
      - docker build ui
```

Si CI échoue → fixer avant demander une review.

---

## 7. Merge et post-merge

### 7.1 Stratégie de merge

**Squash and merge** (par défaut) :
- Tous les commits de la branche sont squashés en 1
- Message de commit final = titre de la PR
- Branche automatiquement supprimée après merge

### 7.2 Marquer la tâche terminée

Après merge, éditer `docs/PLAN_ACTION.md` :
```diff
- [~] [@alice] **P2.03** — `platform/linux/netlink/` : collecteur netlink
+ [x] **P2.03** — `platform/linux/netlink/` : collecteur netlink
```

Commit direct sur `main` autorisé pour ce fichier uniquement.

### 7.3 Déploiement

**Dev :** merge sur `main` → CI push automatiquement l'image Docker `ghcr.io/oseye/<composant>:latest`  
**Staging :** tag `vX.Y.Z-rc.N` → CI push `ghcr.io/oseye/<composant>:X.Y.Z-rc.N`  
**Prod :** tag `vX.Y.Z` → release GitHub + packages `.deb`/`.rpm`/`.msi`/`.pkg`

---

## 8. Communication

### 8.1 Channels

- **GitHub Issues** — bugs, feature requests, discussions techniques
- **GitHub Discussions** — questions générales, annonces
- **Slack #oseye-dev** (si configuré) — sync quotidien, questions rapides

### 8.2 Daily sync (async)

Chaque contributeur actif poste dans #oseye-dev ou commente sur son issue :
- Ce que j'ai fait hier
- Ce que je fais aujourd'hui
- Blocages éventuels

### 8.3 Demander de l'aide

Si bloqué > 2h, ouvrir une discussion GitHub :
- Titre : `[HELP] P2.03 — Netlink collector : verifier rejette le programme eBPF`
- Tag : `help wanted`
- Mentionner un senior reviewer

---

## 9. Code de conduite

### 9.1 Principes

- **Respect** — zéro tolérance pour harcèlement, discrimination, comportement toxique
- **Constructif** — reviews basées sur des faits techniques, pas des opinions personnelles
- **Inclusif** — accueil des nouveaux contributeurs, pas de gatekeeping
- **Transparent** — toute décision technique majeure documentée publiquement (GitHub Discussions)

### 9.2 Résolution de conflit

En cas de désaccord technique :
1. Discussion dans la PR (commentaires)
2. Si pas de consensus → escalade vers le lead (@virus-one)
3. Décision finale documentée dans `docs/DECISIONS.md` (ADR — Architecture Decision Record)

---

## 10. Ressources

| Document | URL |
|----------|-----|
| Architecture complète | `docs/ARCHITECTURE.md` |
| Plan d'action | `docs/PLAN_ACTION.md` |
| Skills Claude Code | `.claude/skills/oseye-*.md` |
| Template PR | `.github/PULL_REQUEST_TEMPLATE.md` |
| Template issue | `.github/ISSUE_TEMPLATE/` |
| CI workflows | `.github/workflows/ci.yml` |

---

**Merci de contribuer à OSEye !**
