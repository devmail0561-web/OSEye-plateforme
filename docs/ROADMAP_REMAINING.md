# OSEye — Plan de développement : travaux restants

**Date :** 2026-08-11  
**Base :** Post-Phase 10 + extensions (UI refonte, sécurité CIA, Response Engine, Plugin/ML/Policy câblés)

---

## Contexte

Les 10 phases de la roadmap sont complètes. Ce plan couvre les **gaps fonctionnels** identifiés après audit complet du codebase — des composants implémentés mais non câblés, des boucles manquantes, et des fonctionnalités partiellement livrées.

---

## Bloc 1 — Câblage ML (CRITIQUE)

### Problème
Le `ml_engine` n'est pas passé au `DecisionEngine` dans `main.py`. Conséquence : `ml_score = 0.0` sur toutes les décisions. Le poids `ml×0.3` est mort en production malgré l'infrastructure complète.

Deux causes indépendantes à corriger toutes les deux :
1. `DecisionEngine(...)` ne reçoit pas `ml_engine=ml_engine`
2. `DecisionWorker(...)` ne reçoit pas `event_repo=repo` → `trigger_event=None` → `ml_score=0.0`

### Fichier : `server/oseye/main.py`

```python
# Passer ml_engine au DecisionEngine (après instanciation de ml_engine)
decision_engine = DecisionEngine(
    journal=journal,
    policy_overrides=PolicyOverrides(),
    human_timeout_secs=...,
    policy_version=...,
    ml_engine=ml_engine,           # ← AJOUTER
)

# Passer event_repo au DecisionWorker
decision_worker = DecisionWorker(
    bus=bus,
    engine=decision_engine,
    decision_repo=decision_repo,
    incident_repo=incident_repo,
    alert_repo=alert_repo,
    action_executor=action_executor,
    event_repo=repo,               # ← AJOUTER
    stop_event=stop,
)
```

**Ordre :** créer `ml_engine` avant `decision_engine` dans le lifespan (actuellement ml_engine est créé après — à déplacer).

---

## Bloc 2 — Boucle de feedback ML

### Problème
`MLEngine.learn_from_alert()` existe mais n'est jamais appelé. Le classifieur MITRE ne s'améliore jamais en production. Le marquage `false_positive` dans le router alertes est une île isolée.

### Fichier : `server/oseye/workers/rule_worker.py`

Après création d'une alerte, appeler `ml_engine.learn_from_alert(trigger_event, mitre_techniques)` si un `ml_engine` est disponible sur `app.state` (ou passé en injection).

### Fichier : `server/oseye/api/routers/alerts.py`

Dans l'endpoint `POST /alerts/{id}/false-positive` : quand une alerte est marquée faux positif, appeler `ml_engine.learn_false_positive(trigger_event)` en sens inverse (update négatif sur les techniques MITRE associées à cette alerte).

`ml_engine` est déjà exposé sur `app.state.ml_engine`.

---

## Bloc 3 — Consommation de `analysis:ml`

### Problème
`MLWorker` publie le score ML sur le topic `analysis:ml` mais personne ne le consomme. Le champ `ml_score` dans `EventRow` reste `None`.

### Fichier : `server/oseye/workers/storage_writer.py` ou nouveau worker

S'abonner à `analysis:ml` et mettre à jour le `ml_score` dans l'`EventRow` correspondant via `event_repo.update_ml_score(event_id, score)`.

Ajouter `update_ml_score` dans `server/oseye/storage/repositories/events.py`.

---

## Bloc 4 — Tâches périodiques manquantes

### 4a — `close_stale_incidents()`
`CorrelationEngine.close_stale_incidents()` existe et est documentée mais jamais appelée. Les incidents restent ouverts indéfiniment.

**Fichier : `server/oseye/workers/correlation_worker.py`**

Ajouter une boucle asyncio dans `run()` qui appelle `close_stale_incidents()` toutes les 5 minutes en parallèle du traitement des alertes.

### 4b — `purge_stale_windows()`
`RuleEngine.purge_stale_windows()` (fenêtres temporelles des règles) n'est jamais appelée. État en mémoire croît indéfiniment.

**Fichier : `server/oseye/workers/rule_worker.py`**

Même pattern : appel périodique toutes les 10 minutes dans la boucle `run()`.

---

## Bloc 5 — Table agents + API agents

### Problème
Pas de table `agents` dédiée. Impossible d'afficher la liste des agents actifs, leur dernière connexion, leur version, leur profil actif.

### Fichier : `server/oseye/storage/models.py`

```python
class AgentRow(Base):
    __tablename__ = "agents"
    cn:              Mapped[str]           # CN du certificat mTLS (PK)
    first_seen:      Mapped[datetime]
    last_seen:       Mapped[datetime]
    version:         Mapped[str | None]    # version de l'agent Go
    active_profile:  Mapped[str]           # dernier profil appliqué
    ip_address:      Mapped[str | None]
    online:          Mapped[bool]          # True si stream gRPC actif
```

### Fichier : `server/oseye/ingest/grpc_service.py`

Mettre à jour `last_seen` et `online=True` à chaque `IngestEvents`. Mettre `online=False` à la déconnexion du stream.

### Fichier : `server/oseye/api/routers/agents.py`

Ajouter :
- `GET /api/v1/agents` — liste des agents (analyst+)
- `GET /api/v1/agents/{cn}` — détail

### UI : `ui/src/pages/admin/`

Nouvelle page `Agents.tsx` accessible aux analystes et admins (pas uniquement admin) — liste avec CN, statut online/offline, profil actif, dernière connexion.

---

## Bloc 6 — Poids WeightedScorer configurables

### Problème
Les poids `0.4/0.3/0.2/0.1` sont des constantes de classe non modifiables sans redéploiement.

### Fichier : `server/oseye/config.py`

```python
decision_weight_rule:  float = Field(default=0.4)
decision_weight_ml:    float = Field(default=0.3)
decision_weight_ti:    float = Field(default=0.2)
decision_weight_depth: float = Field(default=0.1)
```

### Fichier : `server/oseye/decision/engine.py`

`WeightedScorer.__init__` accepte les 4 poids en paramètres. `DecisionEngine.__init__` les reçoit et les passe au scorer.

### Fichier : `server/oseye/main.py`

Passer les 4 settings à `DecisionEngine`.

---

## Bloc 7 — Client enrollment dans l'agent Go

### Problème
L'enrollment est 100% manuel. L'agent doit pouvoir s'enroller automatiquement au premier démarrage si un token est fourni.

### Config : `agent/internal/config/config.go`

```go
EnrollServerURL string // OSEYE_ENROLL_URL, default ""
EnrollToken     string // OSEYE_ENROLL_TOKEN, default ""
```

### Nouveau package : `agent/internal/enrollment/client.go`

- Si `OSEYE_ENROLL_TOKEN` est défini et que `TLSCertFile` n'existe pas :
  1. `GET {EnrollServerURL}/api/v1/enroll/{token}` → récupère le CA cert, l'écrit dans `CACertFile`
  2. Génère une paire de clés Ed25519 + CSR (CN = hostname)
  3. `POST {EnrollServerURL}/api/v1/enroll/{token}` → reçoit le cert signé, l'écrit dans `TLSCertFile`
- Appelé dans `main.go` avant l'init du transport gRPC

---

## Bloc 8 — Action NOTIFY fonctionnelle

### Problème
`NOTIFY` dans `ActionExecutor` est silencieux — publié sur `decisions:completed` mais sans effet réel.

### Approche
Ajouter un **worker de notification configurable** via le système de plugins. Quand une décision `NOTIFY` est produite, `ActionExecutor` publie sur un topic `notifications:pending`. Un plugin `ExporterPlugin` s'abonne à ce topic via l'IPC socket et envoie vers Slack/email/webhook.

**Côté serveur :** `ActionExecutor._emit_notification(decision)` publie sur `notifications:pending`. Pas de dépendance SMTP/Slack dans le core — tout passe par le plugin SDK.

---

## Bloc 9 — Tests manquants

| Fichier à créer | Couvre |
|---|---|
| `server/tests/unit/test_api_response_actions.py` | GET list, GET detail, POST rollback, 404, 409 |
| `server/tests/unit/test_api_agents.py` | GET /agents/blocked, DELETE /{cn}, POST /{cn}/unblock |
| `server/tests/unit/test_decision_ml_integration.py` | Vérifie que ml_score > 0 quand ml_engine est câblé |
| `agent/internal/responder/executor_test.go` | KillProcess PID guard, QuarantineFile, RestoreFile |
| `agent/internal/responder/dedup_test.go` | Allow, déduplication TTL |

---

## Ordre d'exécution recommandé

```
Bloc 1 (câblage ML)          — 1 fichier, impact immédiat, correction de bug
Bloc 3 (consommation ml)     — dépend de Bloc 1 pour être utile
Bloc 2 (feedback FP)         — dépend de Bloc 1
Bloc 4 (tâches périodiques)  — indépendant, 2 fichiers
Bloc 6 (poids configurables) — dépend de Bloc 1 (même fichier main.py)
Bloc 5 (table agents)        — indépendant, travail plus large
Bloc 7 (enrollment Go)       — indépendant, nouveau package Go
Bloc 8 (NOTIFY)              — indépendant, extensible via plugins
Bloc 9 (tests)               — après chaque bloc
```

---

## Vérification globale

```bash
# Python
cd server
pytest tests/unit/ -q
# Vérifier que ml_score > 0 dans les décisions après Bloc 1

# Go
cd agent
go test ./... -race

# UI
cd ui
npm run test
npx tsc --noEmit
```

**Indicateur clé post-Bloc 1 :** lancer `make run-server`, envoyer des events via l'agent, vérifier que `GET /api/v1/decisions` retourne des décisions avec `ml_score > 0.0`.
