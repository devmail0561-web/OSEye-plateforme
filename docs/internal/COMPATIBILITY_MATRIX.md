# OSEye — Matrice de compatibilité des versions

**Mis à jour :** 2026-08-15  
**Contexte :** Problèmes découverts lors de la mise en place du CI self-hosted.

---

## Versions de référence

| Composant | Version requise | Version locale | Notes |
|-----------|----------------|----------------|-------|
| Go | **1.25** | 1.23.8 ⚠️ | go.mod exige ≥ 1.25 (dépendances) |
| Python | **≥ 3.12** | 3.11.9 ⚠️ | pyproject.toml exige 3.12 |
| Node.js | **20** | 20.20.1 ✅ | |
| golangci-lint | **≥ 1.25-compatible** | 1.23-based ❌ | Retiré du CI (voir ci-dessous) |

> **Important :** Go local = 1.23.8 mais go.mod = 1.25.0.  
> Toujours utiliser le Go installé par `actions/setup-go@v5` en CI, pas le Go système.

---

## Problèmes découverts (2026-08-15)

### 1. `go.mod` vs Go système — CRITIQUE

**Symptôme :**
```
can't load config: the Go language version (go1.23) used to build golangci-lint
is lower than the targeted Go version (1.25.0)
```

**Cause :** `go.mod` déclare `go 1.25.0` car `golang.org/x/sync@v0.22.0` l'exige.  
Le Go installé localement est 1.23.8. Le CI utilisait `GO_VERSION: "1.23"`.

**Règle :** `GO_VERSION` dans les workflows doit toujours correspondre à la directive `go` de `go.mod`.  
Vérifier avec :
```bash
head -3 agent/go.mod          # directive go
go version                    # Go système (peut différer)
```

**Fix appliqué :** `GO_VERSION: "1.25"` dans `ci.yml` et `release.yml`.

---

### 2. `golangci-lint` incompatible avec Go 1.25 — BLOQUANT

**Symptôme :**
```
the Go language version (go1.23) used to build golangci-lint is lower than
the targeted Go version (1.25.0)
```

**Cause :** golangci-lint doit être compilé avec une version de Go ≥ à la version cible.  
`golangci-lint-action@v6` avec `version: latest` télécharge un binaire compilé avec Go 1.23.

**Règle :** Quand `go.mod` est mis à jour, vérifier que la version de golangci-lint disponible  
supporte la nouvelle version Go AVANT de mettre à jour go.mod.

**Fix appliqué :** golangci-lint retiré du CI, remplacé par `go vet` (toujours compatible).  
Ré-introduire golangci-lint quand une version compilée avec Go 1.25 est disponible via l'action.

---

### 3. `golang.org/x/sync` force Go 1.25 — À RETENIR

**Cause :** `golang.org/x/sync@v0.22.0` déclare `go 1.25.0` dans son `go.mod`.  
Impossible de rester sur Go 1.23 sans rétrograder cette dépendance.

**Règle :** Avant de mettre à jour un module `golang.org/x/*`, vérifier la version Go minimale  
qu'il exige et s'assurer que tous les outils CI (golangci-lint, govulncheck) la supportent.

---

### 4. `oseye_sdk` non déclaré dans `server/pyproject.toml` — BLOQUANT CI

**Symptôme :**
```
ERROR tests/unit/test_phase8.py
ModuleNotFoundError: No module named 'oseye_sdk'
```

**Cause :** `test_phase8.py` importe `oseye_sdk` mais le SDK (`sdk/`) est un package  
séparé non listé dans les dépendances de `server/pyproject.toml`.

**Règle :** Tout nouveau test important `oseye_sdk` doit s'assurer que le SDK est installé.  
En CI : `pip install -e "../sdk"` avant `pip install -e ".[dev]"`.

**Fix appliqué :** Étape install CI mise à jour.

---

### 5. Mot de passe bcrypt > 72 bytes — BLOQUANT RUNNER

**Symptôme :**
```
ValueError: password cannot be longer than 72 bytes, truncate manually if necessary
```

**Cause :** Le runner self-hosted hérite des variables d'environnement du shell.  
`OSEYE_ADMIN_PASSWORD` dans le shell du développeur contient un mot de passe > 72 bytes  
(limite bcrypt). Le hachage à l'import du module `auth.py` crashe.

**Fix appliqué :**
1. `auth.py` : truncature à 72 bytes avant hachage (`encoded = pw.encode("utf-8")[:72]`)
2. CI : override explicite `OSEYE_ADMIN_PASSWORD=admin123` pour les tests

**Règle :** Sur un runner self-hosted, toujours forcer les variables sensibles dans le  
workflow YAML pour éviter d'hériter de l'environnement système.

---

### 6. `agent/gen/` et `server/gen/` absents du repo — BLOQUANT CI

**Symptôme :**
```
cmd/oseye-agent/main.go:17:2: no required module provides package
github.com/oseye/agent/gen; to add it: go get github.com/oseye/agent/gen
```

**Cause :** Les fichiers générés par `protoc` (`*.pb.go`, `*_pb2.py`) étaient dans  
`.gitignore`. Sans `protoc` installé sur le runner, le build échoue.

**Fix appliqué :** `agent/gen/` et `server/gen/` commités (pratique standard quand  
le CI n'a pas de chaîne protobuf).

**Règle :** Après tout `make proto` (régénération), commiter les fichiers générés.

---

## Checklist avant mise à jour des versions

Avant de bumper une dépendance Go ou la directive `go` dans `go.mod` :

- [ ] Vérifier la version Go minimale requise par la nouvelle dépendance
- [ ] Vérifier que golangci-lint disponible supporte cette version Go
- [ ] Vérifier que `GO_VERSION` dans `ci.yml` et `release.yml` est aligné
- [ ] Tester `go build ./...` localement après le bump
- [ ] Si les fichiers `gen/` sont modifiés par `go mod tidy`, les commiter

Avant de bumper Python :

- [ ] Vérifier `requires-python` dans `pyproject.toml`
- [ ] Vérifier que `PYTHON_VERSION` dans `ci.yml` est ≥ `requires-python`
- [ ] Vérifier que `oseye_sdk` (sdk/) reste compatible
