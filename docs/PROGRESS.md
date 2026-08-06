# OSEye — Suivi de progression

**Version :** 1.2  
**Dernière mise à jour :** 2026-08-06  
**Branche active :** `main`  
**Phase courante :** Phase 1 — Foundation `[~]` (M2/M3/M4/M6/M7/M9/M10 restants)

---

## Légende

| Symbole | Signification |
|---------|--------------|
| `[x]` | Terminé |
| `[~]` | En cours |
| `[ ]` | À faire |
| ⚠ | Bloque la suite |
| 🔴 | Bug critique / faille CRITICAL |
| 🟠 | Bug majeur / faille MAJOR |
| 🟡 | Problème mineur / dette technique |
| ✅ | Faux positif accepté / risque assumé |

---

## Vue d'ensemble des modules (Phase 1)

| # | Module | Branche | Statut | Bloqueurs ouverts |
|---|--------|---------|--------|------------------|
| M0 | Scaffolding + Contrats | `M0/foundation-contracts` | `[x]` Mergé | — |
| M1 | Crypto & Buffer (Go) | `M1/agent-crypto-buffer` | `[x]` Mergé | — |
| M2 | Collectors Linux (Go) | `M2/agent-collectors-linux` | `[ ]` | ✅ Débloqué |
| M3 | Transport gRPC Agent (Go) | `M3/agent-grpc-transport` | `[ ]` | ✅ Débloqué |
| M4 | Agent Bootstrap (Go) | `M4/agent-bootstrap` | `[ ]` | Attend M2+M3 |
| M5 | Event Bus (Python) | `M5/server-event-bus` | `[x]` Mergé | — |
| M6 | Ingestion gRPC (Python) | `M6/server-ingest` | `[ ]` | ✅ Débloqué |
| M7 | Normalizer (Python) | `M7/server-normalizer` | `[ ]` | ✅ Débloqué |
| M8 | Storage (Python) | `M8/server-storage` | `[x]` Mergé | SEC-0002 ✅ fermé |
| M9 | API REST + Auth (Python) | `M9/server-api` | `[ ]` | ✅ Débloqué |
| M10 | Workers dev (Python) | `M10/server-workers` | `[ ]` | Attend M6+M7+M8 |
| M11 | Infra & CI | `M11/infra-ci` | `[x]` Mergé | — |

**Parallélisme disponible maintenant :** M2 + M3 + M6 + M7 + M9 simultanément.

---

## M0 — Scaffolding + Contrats `[x]`

### Fichiers contrats ⚠

| Fichier | Statut | Notes |
|---------|--------|-------|
| `proto/event.proto` | `[x]` | UniversalEventPB, IngestRequest/Response, AgentService (3 RPCs) |
| `server/oseye/core/schema.py` | `[x]` | Tous les modèles Pydantic v2 |
| `server/oseye/bus/interface.py` | `[x]` | Protocol EventBus |
| `agent/internal/platform/interface.go` | `[x]` | PlatformDriver + PlatformCapabilities |
| `agent/internal/platform/registry.go` | `[x]` | Register() + Resolve() |
| `agent/internal/collector/interface.go` | `[x]` | Collector + RawEvent |
| `server/oseye/storage/interface.py` | `[x]` | Protocols Repository (Page[T] structural uniquement) |
| `server/oseye/storage/router.py` | `[x]` | StorageRouter dev/prod split |
| `server/oseye/config.py` | `[x]` | Settings pydantic-settings, env OSEYE_* |
| `server/oseye/core/observability.py` | `[x]` | structlog JSON + OTel |
| `scripts/generate_proto.sh` | `[x]` | Génère Go + Python, fixe les imports relatifs |

### Scaffolding

| Élément | Statut | Notes |
|---------|--------|-------|
| `agent/go.mod` | `[x]` | Go 1.23, dépendances : ebpf, grpc, protobuf, blake3, sqlite3 |
| `server/pyproject.toml` | `[x]` | Python 3.12+, stack complète |
| Arborescence monorepo | `[x]` | Tous les répertoires + `.gitkeep` |
| `infra/docker/docker-compose.dev.yml` | `[x]` | Redis, Postgres, server, agent, ui |
| `scripts/generate_certs.sh` | `[x]` | PKI dev : CA 4096b, server 2048b + SAN, agent 2048b, JWT RSA |
| `ui/package.json` | `[ ]` | Non initialisé — React/TypeScript/Vite absent |
| `.golangci.yml` | `[x]` | Mentionné dans CONTRIBUTING.md mais absent |
| `.env.example` | `[x]` | Négation dans `.gitignore` mais fichier absent |
| Dockerfiles | `[x]` | `docker-compose.dev.yml` les référence mais ils n'existent pas |

### Tests M0

| Test | Statut | Notes |
|------|--------|-------|
| `server/tests/unit/test_schema_completeness.py` | `[x]` | Instancie tous les modèles Pydantic |
| `agent/internal/platform/contracts_test.go` | `[x]` | Assertions de compilation sur les interfaces |
| `scripts/test_proto_compile.sh` | `[ ]` | Non créé |

### Outils — Audit Engine `[x]`

L'audit engine (`tools/audit/`) est implémenté et fonctionnel :
- Scanner regex multi-pattern sur tout le codebase
- 26 patterns par défaut (12 sécurité + 14 debug + self-audit)
- Persistance d'état (`audit_state.json`, gitignored)
- CLI complète (`--mode`, `--diff`, `--verify`, `--report`, `--add-pattern`, `--fix`, `--fp`)
- Auto-audit (patterns TOOL-P001–TOOL-P007)

---

## Failles de sécurité

### SEC-0001 — CORS wildcard ✅ Faux positif accepté

- **Sévérité :** CRITICAL (pattern) → accepté FP
- **Fichier :** `server/oseye/config.py`, champ `api_cors_origins`
- **Détail :** La valeur par défaut est `["http://localhost:5173"]`, non `["*"]`. Le pattern a matché la chaîne littérale dans la définition du Field. Aucune wildcard CORS réelle.
- **Statut :** ✅ Faux positif confirmé

---

### SEC-0002 — Triggers d'immuabilité manquants en DB ✅ Fermé

- **Sévérité :** CRITICAL → fermé
- **Fichier :** `server/oseye/storage/migrations/__init__.py`
- **Détail :** Triggers PostgreSQL `prevent_decision_update` et `prevent_custody_update` implémentés dans `_install_immutability_triggers()`. Appelés par `run_migrations()` lors du démarrage du serveur sur PostgreSQL.
- **Module :** M8 — Storage (commit `ebd2614`)
- **Statut :** ✅ Fermé — M8 mergé le 2026-08-06

---

### SEC-0003 — `shell=True` dans le scanner d'audit ✅ Risque assumé

- **Sévérité :** MAJOR (pattern) → accepté risque assumé
- **Fichier :** `tools/audit/scanner.py:50`
- **Détail :** `subprocess.run(cmd, shell=True, ...)` où `cmd` provient de `audit_patterns.json`. Le fichier est versionné dans le dépôt et contrôlé. Risque résiduel : si le dépôt est compromis (supply-chain), les patterns pourraient exécuter des commandes arbitraires. La substitution `{ROOT}` avec `str(ROOT)` est sûre tant que le chemin du projet ne contient pas de caractères shell spéciaux.
- **Statut :** ✅ Risque assumé — mitiger en P10 si audit engine exposé hors dev

---

### SEC-0004 — Credentials dev en clair dans docker-compose 🟡 MINEUR

- **Sévérité :** MINOR
- **Fichier :** `infra/docker/docker-compose.dev.yml:21-22`
- **Détail :** `POSTGRES_PASSWORD: oseye_dev` en clair. Également dans `ci.yml` : `POSTGRES_PASSWORD: test`. Ces credentials ne sont utilisés qu'en environnement de développement/CI et ne correspondent à aucun environnement de production. Le fichier est versionné intentionnellement.
- **Correction recommandée :** Ajouter une note dans le fichier rappelant que ces valeurs ne doivent jamais être réutilisées en production. Ne pas migrer vers Docker secrets pour le dev (overhead injustifié).
- **Statut :** 🟡 Accepté pour dev — à documenter

---

### SEC-PREV-001 — agent_id trust model (mTLS CN) — Prévention proactive ⚠

- **Sévérité :** À prévenir en M6
- **Fichier :** `server/oseye/ingest/grpc_service.py` (à créer)
- **Détail :** Le proto spécifie que l'`agent_id` doit être lu depuis le CN du certificat mTLS client, et non depuis le payload de la requête. Pattern SEC-P006 dans l'audit engine détectera automatiquement si `grpc_service.py` lit `agent_id` depuis `request.*` au lieu de `context.auth_context`.
- **Action requise (P1.28) :** Implémenter la vérification CN dans `grpc_service.py`. Ne jamais faire confiance au champ `agent_id` du message protobuf.
- **Statut :** Non concerné actuellement — surveillance active via audit pattern

---

### SEC-PREV-002 — Rate limiting `/auth/token` — Prévention proactive ⚠

- **Sévérité :** MAJOR (sera CRITICAL si absent en M9)
- **Fichier :** `server/oseye/api/routers/auth.py` (à créer)
- **Détail :** L'endpoint `POST /auth/token` est une cible de brute force JWT. Pattern SEC-P012 (inverse) détectera automatiquement son absence quand le fichier existera. Utiliser `slowapi` + rate limit par IP : 5 req/min sur `/auth/token`, 600 req/min global JWT, 300 req/min API key.
- **Action requise (P1.40 + P10.13) :** Intégrer `slowapi` dès la création du router auth.
- **Statut :** Non concerné actuellement — surveillance active via audit pattern

---

## Bugs

### BUG-001 — `getenvDuration` : sémantique trompeuse ✅ Corrigé

- **Sévérité :** MINOR
- **Fichier :** `agent/internal/config/config.go`
- **Détail :** La conversion `* time.Millisecond` a été déplacée dans `getenvDuration` ; le callsite utilise maintenant `getenvDuration(...)` sans multiplicateur.
- **Statut :** ✅ Corrigé — commit M0 audit

---

### BUG-002 — CI : seuil de couverture 80% non enforced 🟠 MAJEUR

- **Sévérité :** MAJOR
- **Fichier :** `.github/workflows/ci.yml`, job `audit-coverage`
- **Détail :** Le step "Check coverage thresholds" est un stub :
  ```yaml
  - name: Check coverage thresholds
    run: |
      echo "Vérification seuil 80%..."
      # Script à implémenter : parse coverage.out / coverage.xml / lcov.info
      # Fail si < 80%
  ```
  Il sort toujours avec code 0. La couverture est mesurée et uploadée sur Codecov mais jamais contrainte par la CI. La règle "couverture > 80% obligatoire" documentée dans `CONTRIBUTING.md` n'est donc pas enforced.
- **Correction (M11) :**
  - Go : ajouter `go test -race -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | awk '/total/ {if ($3+0 < 80) exit 1}'`
  - Python : `pytest --cov-fail-under=80`
- **Statut :** ✅ Corrigé — M11 (Infra & CI)

---

### BUG-003 — Pattern DBG-P003 : labeling "PATTERN INVERSÉ" incohérent 🟡 MINEUR

- **Sévérité :** MINOR — comportement final correct, cohérence interne cassée
- **Fichier :** `tools/audit/persistence.py`, pattern `DBG-P003`
- **Détail :** Le pattern est commenté `# PATTERN INVERSÉ` et utilise un `script` shell (`ls agent/gen/*.go server/gen/*.py`) dont la sortie vide = 0 hits = pas de finding. Ce comportement est correct : le finding se déclenche quand le codegen est absent. Cependant, `DBG-P003` n'est pas dans `_INVERSE_PATTERN_IDS`, ce qui crée une incohérence : le commentaire dit inversé, mais le mécanisme d'inversion n'est pas utilisé. Si un développeur remplace le `script` par un `pattern` regex, le sens s'inversera sans warning.
- **Correction :** Soit ajouter `DBG-P003` dans `_INVERSE_PATTERN_IDS` et le convertir en regex, soit supprimer le commentaire `# PATTERN INVERSÉ`.
- **Statut :** 🟡 Ouvert — faible priorité

---

### BUG-004 — `Page[T]` non instanciable ✅ Résolu (workaround)

- **Sévérité :** MINOR
- **Fichier :** `server/oseye/storage/interface.py`, `server/oseye/storage/repositories/*.py`
- **Détail :** `Page[T]` dans l'interface reste un type structurel. Chaque repository utilise un `@dataclass PageResult[T]` local comme type de retour concret. À factoriser en M10 (DESIGN-002).
- **Statut :** 🟡 Workaround en place — factorisation en M10

---

## Dettes techniques et éléments manquants

| ID | Élément | Priorité | Module |
|----|---------|----------|--------|
| DETTE-001 | `ui/package.json` absent — UI React non initialisée | Haute | M11 / Phase 9 |
| ~~DETTE-002~~ | ~~`.golangci.yml` absent — lint Go non configurable~~ | Haute | M11 `[x]` |
| ~~DETTE-003~~ | ~~`.env.example` absent — onboarding développeur incomplet~~ | Moyenne | M11 `[x]` |
| ~~DETTE-004~~ | ~~Dockerfiles absents (server, agent, ui)~~ | Haute | M11 `[x]` |
| DETTE-005 | `scripts/test_proto_compile.sh` non créé | Moyenne | M0 |
| DETTE-006 | `docs/note.txt` — brouillon design à nettoyer | Faible | — |
| DETTE-007 | Proto codegen non exécuté — `agent/gen/` et `server/gen/` absents | Haute | M0/M1/M6 |
| DETTE-008 | `audit_patterns.json` et `persistence.py` contiennent les mêmes patterns — synchronisation manuelle risquée | Faible | M11 |
| ~~DETTE-009~~ | ~~`go.mod` manque cilium/ebpf, blake3, mattn/go-sqlite3~~ | blake3+sqlite ajoutés en M1 | M1 `[x]` |
| DETTE-010 | `.gitkeep` redondants dans `signer/` et `chain/` — fichiers .go présents | Faible | — |
| LINT-001 | ~~ruff UP035/I001 dans bus/interface.py, schema.py~~ | Corrigé | M0 |
| LINT-002 | ~~E501 config.py:51~~ | Corrigé | M0 |
| MYPY-001 | ~~mypy strict : `DecisionRepository.list` conflit builtin~~ | Corrigé (→ `list_decisions`) | M0 |
| CI-001 | ~~`cmd/oseye-agent/` vide → `go build` échoue~~ | Corrigé (stub main.go) | M0 |
| DESIGN-001 | `EventBus` Protocol sans méthode `close()` — risque de leak | Moyenne | M5 |
| DESIGN-002 | `PageResult[T]` redéfini dans chaque repository — à factoriser | Faible | M10 |
| DESIGN-003 | `redis_bus.py` `subscribe_pattern` utilise `KEYS *` — O(N) bloquant prod | Moyenne | M5-bis |
| OTel-001 | `observability.py` : OTel SDK non initialisé (stub) | Faible | M6/M9 |
| BUG-005 | ~~`go.mod` M1 avait écrasé grpc+protobuf~~ | ✅ Corrigé (grpc@v1.68.0 réajouté) | fix commit |
| WARN-001 | `test_storage.py` : 3 warnings `Event loop is closed` (aiosqlite teardown) | Faible | M8-bis |

---

## Décisions assumées (non-bugs)

| ID | Décision | Justification |
|----|----------|---------------|
| ASSUME-001 | Credentials dev en clair dans `docker-compose.dev.yml` | Périmètre dev uniquement, jamais utilisé en prod |
| ASSUME-002 | `shell=True` dans `tools/audit/scanner.py` | Source contrôlée (patterns versionnés), jamais exposé à input utilisateur |
| ASSUME-003 | `agent` container `privileged: true` + `network_mode: host` | Requis pour eBPF Linux — documenté dans architecture |
| ASSUME-004 | Faux positifs DBG-0030–DBG-0040 (print stderr dans audit engine) | La fonction `_warn()` est intentionnellement un print de diagnostic, pas du code de prod |
| ASSUME-005 | Faux positifs DBG-0001–DBG-0003 (assertions interface Go) | Ce sont les fichiers de définition d'interfaces, pas des implémentations concrètes |

---

## Critères d'acceptance Phase 1

- [ ] `go test -race ./...` — verts, couverture > 80%
- [ ] `pytest server/tests/ --cov-fail-under=80` — verts
- [ ] `docker compose up --build --wait` — tous services healthy
- [ ] Events eBPF réels insérés en DB SQLite
- [ ] `GET /api/v1/events` retourne les events
- [ ] Client WS reçoit les events en < 1s
- [ ] CI GitHub Actions passe sur `main`
- [ ] Aucun finding CRITICAL ou BLOCKER ouvert dans l'audit engine

---

## Qualité du code — tableau de bord

| Dimension | Valeur | Seuil | Statut |
|-----------|--------|-------|--------|
| Tests Python | 40/40 | 100% | ✅ |
| Tests Go | 43/43 | 100% | ✅ |
| Couverture Python | 83% | 80% | ✅ |
| Couverture Go (code écrit) | chain 100%, signer 87%, config 100%, buffer 73% | 80% | 🟡 buffer |
| ruff (server/oseye) | 0 erreur | 0 | ✅ |
| mypy --strict | 0 erreur | 0 | ✅ |
| go vet | 0 erreur | 0 | ✅ |

## Benchmarks — chemins chauds (Intel i7-8665U, 1.9 GHz)

| Opération | Résultat | Cible | Marge |
|-----------|---------|-------|-------|
| BLAKE3 chain 1 KB (Go) | 428 MB/s — 2.4 µs/op | 500 MB/s | 0.9× |
| Ed25519 sign 32B (Go) | 43.7 µs → 22 900 signs/s | 2 signs/s | **11 450×** |
| Buffer Push/1000 — modernc (CGO=0) | 34 ms | <1 ms | fallback CI |
| Buffer Push/1000 — mattn+WAL (CGO=1) | 14 ms | <1 ms | prod disk <1ms |
| insert_batch 1000 events (Python/SQLite) | 189 ms → 5 290 events/s | 100k/s (prod) | pipeline M10 |
| event→row Pydantic→ORM (Python) | 84 µs / appel | — | 11 800 ops/s |

**Décision architecture SQLite :** dual build — `mattn/go-sqlite3` CGO (WAL, prod) + `modernc.org/sqlite` pure-Go (CI cross-platform, CGO_ENABLED=0). Rust/FFI non justifié — marges BLAKE3/Ed25519 trop larges.

## Historique des commits

| Hash | Message | Date |
|------|---------|------|
| `8ac1abb` | perf: benchmarks hot path + buffer CGO (mattn/sqlite3 + WAL) | 2026-08-06 |
| `8bf5214` | fix: qualité code — ruff/mypy clean, tests config Go, types stricts | 2026-08-06 |
| `4ce4329` | docs: audit Phase 1 — mise à jour PROGRESS.md | 2026-08-06 |
| `19838ae` | fix: go.mod pin grpc v1.68+x/net v0.32 to go1.23 | 2026-08-06 |
| `cac33ae` | Merge M11/infra-ci → main | 2026-08-06 |
| `3f79b62` | Merge M8/server-storage → main | 2026-08-06 |
| `fc48260` | Merge M5/server-event-bus → main | 2026-08-06 |
| `68dcc21` | Merge M1/agent-crypto-buffer → main | 2026-08-06 |
| `ccfd307` | Merge M0/foundation-contracts → main | 2026-08-06 |
| `b88ff36` | chore: initial project foundation — docs, CI templates, LICENSE, SECURITY | 2026-08-05 |
