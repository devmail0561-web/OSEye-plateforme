# OSEye — Skills Claude Code

Ce répertoire contient les **skills Claude Code** du projet OSEye. Un skill est un ensemble d'instructions spécialisées qui guide Claude pour accomplir une tâche récurrente de façon cohérente avec l'architecture du projet.

## Prérequis

**Claude Code** doit être installé :
```bash
npm install -g @anthropic-ai/claude-code
```

Les skills sont automatiquement disponibles dès que vous ouvrez Claude Code depuis la racine du projet (`/oseye`). Aucune configuration supplémentaire requise.

---

## Skills disponibles

| Commande | Description | Utilisation typique |
|---|---|---|
| `/oseye-collector` | Créer un collecteur d'événements (Go) | Ajouter fanotify, netlink, ETW, etc. |
| `/oseye-worker` | Créer un worker de traitement (Python) | Implémenter rule_worker, ml_worker, etc. |
| `/oseye-api-endpoint` | Ajouter un endpoint FastAPI | Nouveaux endpoints REST ou WebSocket |
| `/oseye-rule` | Écrire une règle de détection YAML | Règles MITRE ATT&CK pour le Rule Engine |
| `/oseye-task` | Avancer sur le plan d'action | Implémenter la prochaine tâche `PLAN_ACTION.md` |
| `/oseye-debug` | Diagnostiquer un problème | Tests qui échouent, pipeline silencieux |
| `/oseye-security` | Review de sécurité | Avant merge d'une PR sensible |
| `/oseye-agent-step` | Avancer sur le plan agent Go (M14-M21) | Implémenter mapper, watchdog, policy, eBPF, auditd... |

---

## Comment utiliser un skill

Dans Claude Code, tapez simplement le nom du skill avec `/` :

```
/oseye-collector
```

Claude chargera les instructions du skill et vous guidera. Vous pouvez aussi fournir des informations directement :

```
/oseye-collector linux netlink
```

```
/oseye-task P2.03
```

```
/oseye-rule "SSH brute-force depuis IP externe"
```

---

## Guide par cas d'usage

### Ajouter un collecteur Linux

```
/oseye-collector
```

Le skill vous demandera :
- L'OS cible (`linux` / `windows` / `darwin`)
- Le nom du collecteur (`netlink`, `journald`, `etw`...)
- La source de données kernel

Il génère :
- `agent/internal/platform/linux/<nom>/collector.go` — implémentation Go complète
- Tests unitaires
- Adapter normalizer Python
- Mise à jour du PlatformDriver

### Implémenter un worker de traitement

```
/oseye-worker
```

Le skill crée le worker avec le pattern `GracefulWorker` :
- Consommation du bus (subscribe_pattern)
- Retry avec DLQ
- SIGTERM drain
- Checkpoint pour workers stateful (ML)

### Ajouter un endpoint REST

```
/oseye-api-endpoint
```

Fournissez méthode + path + rôle minimum :
```
/oseye-api-endpoint POST /api/v1/agents/{id}/isolate senior_analyst
```

### Écrire une règle de détection

```
/oseye-rule
```

Exemple :
```
/oseye-rule "lecture /etc/shadow hors root" linux critical T1003.008
```

### Avancer sur le plan d'action

```
/oseye-task
```

Charge automatiquement la prochaine tâche disponible dans `docs/PLAN_ACTION.md` en respectant les dépendances. Peut aussi cibler une tâche précise :

```
/oseye-task P2.03
```

### Débugger un problème

```
/oseye-debug
```

Le skill analyse les logs, lance les tests de diagnostic et identifie la cause racine. Utile quand :
- Un test échoue sans raison claire
- Le pipeline event-bus est silencieux
- L'agent consomme trop de CPU

### Review de sécurité

```
/oseye-security
```

À invoquer avant tout merge d'une PR touchant :
- L'authentification / autorisation
- Le transport gRPC / mTLS
- Les collectors kernel
- La gestion de secrets ou credentials

---

## Conventions de code rappelées par les skills

### Go (agent)
- Build tag `//go:build linux` en première ligne pour tout fichier OS-spécifique
- Interface satisfaite statiquement : `var _ collector.Collector = (*Type)(nil)`
- Métriques thread-safe : `atomic.Uint64`, `atomic.Bool`, `atomic.Value`
- Anti double-close : `select { case <-c.stopCh: default: close(c.stopCh) }`
- Pas de goroutine leak — toujours un `ctx` ou `stopCh`

### Python (server)
- Hot path : `model_validate_json(raw)` — jamais `json.loads + model_validate(dict)` sauf modification nécessaire
- Imports au niveau module, jamais dans les fonctions
- `get_settings()` (lru_cache) — jamais `Settings()` direct
- Publish depuis thread gRPC : `asyncio.get_running_loop()` + `ensure_future`
- Repository pattern : jamais d'accès direct au backend dans le code métier

### Tests
- Pas de mocks DB — utiliser SQLite in-memory (`sqlite+aiosqlite:///:memory:`)
- Mocks autorisés : services externes (AbuseIPDB, VirusTotal), gRPC server
- Nommage : `test_<ce_qui_est_testé>_<condition>_<résultat_attendu>`
- Couverture cible : > 80%

---

## Références

| Document | Description |
|---|---|
| `docs/ARCHITECTURE.md` | Architecture complète — source de vérité |
| `docs/PLAN_ACTION.md` | 188 tâches, phases, dépendances |
| `docs/DEVELOPMENT_PLAN_PHASE2.md` | Plan Phase 2 (M12-M18) |
| `docs/DEVELOPMENT_PLAN_AGENT.md` | Plan agent Go détaillé (M14-M21) — fichiers, fonctions, tests |
| `CONTRIBUTING.md` | Workflow de contribution, PR, reviews |

---

## Maintenir les skills à jour

Les skills reflètent l'état du projet. Quand l'architecture évolue, mettre à jour les fichiers dans `.claude/skills/` **et** dans `~/.claude/skills/` (copie locale de l'auteur) :

```bash
# Après modification d'un skill dans le projet
cp .claude/skills/oseye-collector.md ~/.claude/skills/oseye-collector.md
```

Les skills sont versionnés avec le code — chaque PR majeure doit inclure les mises à jour des skills si les conventions changent.
