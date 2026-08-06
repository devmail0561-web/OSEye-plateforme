# Skill : OSEye — Avancer sur le plan d'action

## Quand utiliser ce skill
Invoquer avec `/oseye-task` quand l'utilisateur dit "continue le plan", "on passe à la prochaine tâche", "avance sur P1.XX", ou demande de travailler sur une tâche spécifique du `PLAN_ACTION.md`.

---

## Ce que tu dois faire

### Étape 1 — Lire l'état courant du plan

> **Phase courante (2026-08-06) : Phase 2 démarrée — M12 complété (fanotify + inotify)**
> Pour les nouvelles tâches, consulter `docs/DEVELOPMENT_PLAN_PHASE2.md` (M12-M18).

Lire `docs/PLAN_ACTION.md` et identifier :
1. La prochaine tâche `[ ]` non commencée (la plus faible numérotation `Pn.m`)
2. Vérifier que toutes ses dépendances sont `[x]`
3. Si l'utilisateur a demandé une tâche spécifique (`P2.05`), utiliser celle-là

Annoncer clairement : **"Je travaille sur P2.05 — `platform/linux/udev/`"**

### Étape 2 — Vérifier le contexte architectural

Avant d'écrire du code, lire les sections pertinentes de `docs/ARCHITECTURE.md` :
- La section du composant concerné (§3, §4, §5, §6, §7...)
- Les interfaces contrats si la tâche implémente un Protocol ou une Interface Go

### Étape 3 — Implémenter la tâche

Utiliser les skills spécialisés si la tâche correspond :
- Nouveau collector → `/oseye-collector`
- Nouvelle règle de détection → `/oseye-rule`
- Nouvel endpoint API → `/oseye-api-endpoint`
- Nouveau worker → `/oseye-worker`

Sinon, implémenter directement en respectant :
- Les interfaces définies dans les fichiers contrats (Annexe ARCHITECTURE.md)
- Les conventions de nommage du monorepo
- Le logger OTel structuré JSON (`get_logger(__name__)`)
- Aucun import direct de backend — toujours passer par les Protocols/interfaces

### Étape 4 — Écrire les tests associés

Chaque tâche d'implémentation inclut ses tests :
- **Go** : `*_test.go` dans le même package
- **Python** : `tests/unit/<composant>/test_<fichier>.py`
- Couverture cible : > 80%

### Étape 5 — Mettre à jour le plan

Après avoir terminé, marquer la tâche `[x]` dans `docs/PLAN_ACTION.md` :

```markdown
- [x] **P2.05** — `platform/linux/udev/` : collecteur udev (events devices)
```

### Étape 6 — Résumé de fin de tâche

Indiquer :
- Ce qui a été créé/modifié (fichiers avec chemins)
- Prochaine tâche disponible selon le plan
- Toute dépendance débloquée

---

## Règles générales de code OSEye

### Go (agent)
- Build tag obligatoire en première ligne pour tout fichier OS-spécifique
- Interfaces satisfaites implicitement — vérifier avec `var _ Interface = (*Type)(nil)`
- Pas de goroutine leak — toute goroutine démarre avec un `ctx` ou un `stopCh`
- Logger : `slog` avec handler JSON, champs structurés

### Python (server)
- Type hints stricts sur toutes les fonctions publiques
- Pydantic v2 pour tous les modèles de données
- `async`/`await` partout — pas de code bloquant dans les coroutines
- Logger : `get_logger(__name__)` depuis `oseye.core.observability`
- Repository pattern : jamais d'import direct d'un backend dans le code métier
- **Hot path** : utiliser `model_validate_json()` au lieu de `json.loads` + `model_validate(dict)`
- Settings : utiliser `get_settings()` (lru_cache) — jamais `Settings()` direct
- Depuis un thread gRPC : publier via `asyncio.get_running_loop().call_soon_threadsafe(asyncio.ensure_future, coro)`

### Tests
- Pas de mocks pour la DB — utiliser SQLite in-memory en test
- Les mocks sont autorisés uniquement pour les services externes (AbuseIPDB, VirusTotal, gRPC)
- Nommer les tests : `test_<ce_qui_est_testé>_<condition>_<résultat_attendu>`

---

## Référence rapide des chemins importants

```
docs/ARCHITECTURE.md          # référence architecturale complète
docs/PLAN_ACTION.md           # plan d'action avec toutes les tâches
docs/DEVELOPMENT_PLAN_PHASE2.md  # plan Phase 2 (M12-M18)

agent/internal/platform/      # drivers OS (linux/, windows/, darwin/)
agent/internal/platform/linux/fanotify/  # collecteur fanotify (M12 ✅)
agent/internal/platform/linux/inotify/   # collecteur inotify (M12 ✅)
agent/internal/collector/     # interface Collector OS-agnostique
server/oseye/core/schema.py   # modèles Pydantic — source de vérité
server/oseye/core/pagination.py   # PageResult[T] — factoriser ici
server/oseye/bus/interface.py # Protocol EventBus
server/oseye/storage/interface.py  # Protocols Repository
server/oseye/workers/         # workers de traitement pipeline
server/oseye/api/routers/     # endpoints FastAPI
rules/builtin/                # règles de détection intégrées
infra/k8s/                    # manifestes Kubernetes
proto/                        # définitions Protobuf
```
