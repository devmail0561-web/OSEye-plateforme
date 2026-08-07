# Skill : OSEye — Avancer sur le plan agent Go

## Quand utiliser ce skill
Invoquer avec `/oseye-agent-step` quand l'utilisateur dit :
- "implémente M14", "implémente M15", ... "implémente M21"
- "continue le plan agent", "prochaine étape agent"
- "câble les collecteurs", "ajoute le watchdog", "implémente le mapper"
- "implémente [nom d'un composant de DEVELOPMENT_PLAN_AGENT.md]"

---

## Ce que tu dois faire

### Étape 1 — Identifier le module à traiter

Lire `docs/DEVELOPMENT_PLAN_AGENT.md` et `docs/PROGRESS.md` pour identifier :
1. Le module demandé par l'utilisateur (M14-M21)
2. Si l'utilisateur n'en spécifie pas : le premier module dont toutes les dépendances sont `[x]`
3. Annoncer : **"Je travaille sur M14 — Câblage collecteurs + mapper event"**

### Étape 2 — Vérifier les dépendances

Avant de commencer, vérifier dans `docs/PROGRESS.md` que les modules prérequis sont bien `[x]`.

- M14 nécessite : M12 ✅, M13 ✅ → peut démarrer
- M15 nécessite : M14
- M16 nécessite : M14
- M17 nécessite : M14
- M18 nécessite : M13 ✅
- M19 nécessite : M14
- M20 nécessite : M14
- M21 nécessite : M14-M20

Si une dépendance n'est pas `[x]`, l'indiquer et proposer de traiter la dépendance en premier.

### Étape 3 — Lire la spec du module

Dans `docs/DEVELOPMENT_PLAN_AGENT.md`, lire la section complète du module :
- La liste des fichiers à créer ou modifier
- Les signatures exactes de chaque fonction
- Les comportements attendus (ce qui est décrit après chaque signature)

**Ne pas implémenter depuis la mémoire.** Le plan est la source de vérité.

### Étape 4 — Créer la branche Git

```bash
git checkout -b M<N>/<nom-branche>
```
La branche exacte est indiquée dans la section du module dans le plan.

Exemples :
- M14 → `git checkout -b M14/agent-wire-mapper`
- M15 → `git checkout -b M15/buffer-proto-storage`
- M16 → `git checkout -b M16/agent-watchdog`
- M17 → `git checkout -b M17/agent-policy-commands`
- M18 → `git checkout -b M18/server-normalizers-phase2`
- M19 → `git checkout -b M19/auditd-collector`
- M20 → `git checkout -b M20/ebpf-collector`
- M21 → `git checkout -b M21/tests-resilience`

### Étape 5 — Implémenter dans l'ordre donné par le plan

Le plan liste les fichiers dans un ordre précis (nouveau → modifié). Respecter cet ordre car certains fichiers modifiés importent des nouveaux packages.

**Règles de code Go obligatoires :**
- Build tag `//go:build linux` en première ligne pour tout fichier OS-spécifique
- Vérification statique d'interface : `var _ collector.Collector = (*XxxCollector)(nil)`
- Pas de goroutine leak : toute goroutine doit s'arrêter sur `ctx.Done()` ou `stopCh`
- `Stop()` doit être idempotent : utiliser le pattern `select { case <-c.stopCh: default: close(c.stopCh) }`
- Logger structuré : `slog.Info(...)` / `slog.Warn(...)` / `slog.Error(...)` avec champs nommés
- Compteurs atomiques : `atomic.Int64`, `atomic.Bool`, `atomic.Value` (pas de mutex pour les compteurs)
- `RawEvent.OS` toujours positionné : `"linux"`
- `RawEvent.Timestamp` en nanosecondes : `time.Now().UnixNano()`

**Règles Python (M18) :**
- Type hints stricts sur toutes les fonctions publiques
- `model_validate_json()` au lieu de `json.loads` + `model_validate`
- Logger via `get_logger(__name__)` depuis `oseye.core.observability`
- Valeurs par défaut explicites pour tous les champs optionnels de `UniversalEvent`

### Étape 6 — Écrire les tests listés dans le plan

Chaque module a une liste de fonctions de test explicites dans le plan. Les implémenter toutes.

**Go :**
- Nommage : `Test<Composant>_<Condition>_<Résultat>` ou `Test<FonctionTestée>` selon le plan
- Skip avec message explicite si le test requiert un privilège ou une ressource système :
  ```go
  if os.Getuid() != 0 {
      t.Skip("requires root / CAP_SYS_ADMIN")
  }
  ```
- Pour les tests sans syscall : pas de build tag nécessaire (tests unitaires purs)

**Python :**
- Nommage : `test_<ce_qui_est_testé>_<condition>` (snake_case)
- Payload synthétique : construire des dict Python, pas de fichiers de fixtures

### Étape 7 — Vérifier la qualité

Exécuter dans l'ordre :
```bash
cd agent
go build ./...
go test ./...
go test -race ./...
go vet ./...
golangci-lint run --timeout=5m
```

Pour M18 (Python) :
```bash
cd server
mypy --strict oseye/normalizer/
ruff check oseye/normalizer/
python -m pytest tests/unit/normalizer/ -v
```

Si des erreurs surviennent : les corriger avant de passer à l'étape 8.

### Étape 8 — Mettre à jour la documentation

**`docs/PROGRESS.md` :** Ajouter le module dans le tableau Phase 2 avec statut `[x]` :
```markdown
| M14 | Câblage collecteurs + mapper event | `[x]` Mergé | N tests go | GAP-01/02/03 résolus |
```

**`docs/PLAN_ACTION.md` :** Marquer les tâches correspondantes `[x]`.

### Étape 9 — Commit et merge

```bash
git add <fichiers spécifiques — jamais git add -A>
git commit -m "feat(M<N>): <description courte>"
git checkout main
git merge M<N>/<nom-branche>
```

### Étape 10 — Résumé de fin de module

Indiquer :
- Fichiers créés (avec chemins relatifs)
- Fichiers modifiés (avec ce qui a changé)
- Tests ajoutés (nombre et packages)
- GAP(s) résolus
- Prochain module débloqué

---

## Référence rapide : fichiers clés du plan agent

```
docs/DEVELOPMENT_PLAN_AGENT.md   # ← source de vérité de ce skill

agent/internal/mapper/            # M14 — nouveau package
agent/internal/watchdog/          # M16 — à implémenter
agent/internal/policy/            # M17 — nouveau package
agent/internal/commands/          # M17 — nouveau package
agent/internal/platform/linux/driver.go   # M14 — câbler 6 collecteurs
agent/cmd/oseye-agent/main.go     # M14/M16/M17 — modifications main

agent/internal/platform/linux/auditd/collector.go  # M19 — remplacer stub
agent/internal/platform/linux/ebpf/                # M20 — tout à créer
agent/internal/platform/linux/ebpf/programs/       # M20 — .bpf.c

server/oseye/normalizer/adapters/linux/   # M18 — 6 nouveaux adapters
server/oseye/normalizer/engine.py         # M18 — enregistrement adapters

agent/tests/resilience/           # M21 — tests E2E
```

---

## Points d'attention par module

**M14 (mapper)** : le package `mapper` est entièrement nouveau. `main.go` doit importer `github.com/google/uuid` qui est déjà dans go.sum. Le format de stockage dans le buffer change (proto bytes, non JSON) : s'assurer que les tests existants de `buffer_test.go` restent verts.

**M16 (watchdog)** : la formule de throttle CPU utilise `runtime.NumCPU()` et des jiffies depuis `/proc/self/stat`. Les champs `utime` et `stime` sont aux positions 14 et 15 (indexés depuis 1) dans `/proc/self/stat` — mais attention : le champ 2 (comm) peut contenir des espaces et parenthèses. Parser en splittant après la dernière `)`.

**M17 (policy+commands)** : `GRPCClient` n'expose pas encore `ServiceClient()`. L'ajouter comme indiqué dans la spec avant d'utiliser le client depuis `policy/` et `commands/`.

**M18 (normalizers)** : vérifier dans `server/oseye/normalizer/adapters/linux/` le nom exact de la classe de base (`BaseAdapter`) et ses paramètres requis avant de créer les nouveaux adapters.

**M19 (auditd)** : l'approche retenue est sans CGO (lecture de `/var/log/audit/audit.log`). Le parser de lignes audit est sensible au format : `type=X msg=audit(ts.ms:serial): key=value ...`. Le champ `comm` peut contenir une valeur hexadécimale entre guillemets (`comm="bash"` ou `comm=62617368`) — gérer les deux cas dans `parseLine`.

**M20 (eBPF)** : `bpf2go` de `github.com/cilium/ebpf` génère automatiquement `loader_bpfeb.go` et `loader_bpfel.go` depuis les `.bpf.c`. Ajouter `//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang execve ./programs/execve.bpf.c` en commentaire `go:generate` dans `loader.go`. Si le kernel de développement ne supporte pas eBPF, utiliser la dégradation gracieuse (retourner `nil` au lieu d'une erreur fatale).
