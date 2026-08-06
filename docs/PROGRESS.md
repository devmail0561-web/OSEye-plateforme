# OSEye — Suivi de progression

**Version :** 1.0  
**Dernière mise à jour :** 2026-08-06  
**Branche active :** `M0/foundation-contracts`  
**Phase courante :** Phase 1 — Foundation

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
| M0 | Scaffolding + Contrats | `M0/foundation-contracts` | `[~]` En cours | SEC-0002 (CRITICAL) |
| M1 | Crypto & Buffer (Go) | `M1/agent-crypto-buffer` | `[ ]` | Attend M0 mergé |
| M2 | Collectors Linux (Go) | `M2/agent-collectors-linux` | `[ ]` | Attend M1 |
| M3 | Transport gRPC Agent (Go) | `M3/agent-grpc-transport` | `[ ]` | Attend M1 |
| M4 | Agent Bootstrap (Go) | `M4/agent-bootstrap` | `[ ]` | Attend M2 + M3 |
| M5 | Event Bus (Python) | `M5/server-event-bus` | `[ ]` | Attend M0 mergé |
| M6 | Ingestion gRPC (Python) | `M6/server-ingest` | `[ ]` | Attend M5 |
| M7 | Normalizer (Python) | `M7/server-normalizer` | `[ ]` | Attend M5 |
| M8 | Storage (Python) | `M8/server-storage` | `[ ]` | Attend M0 mergé |
| M9 | API REST + Auth (Python) | `M9/server-api` | `[ ]` | Attend M8 |
| M10 | Workers dev (Python) | `M10/server-workers` | `[ ]` | Attend M6 + M7 + M8 |
| M11 | Infra & CI | `M11/infra-ci` | `[ ]` | Attend M0 mergé |

**Parallélisme disponible après merge M0 :** M1 + M5 + M8 + M11 simultanément.

---

## M0 — Scaffolding + Contrats `[~]`

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

### SEC-0002 — Triggers d'immuabilité manquants en DB 🔴 CRITIQUE — OUVERT

- **Sévérité :** CRITICAL
- **Fichier :** `server/oseye/storage/migrations/__init__.py`
- **Détail :** Les triggers PostgreSQL `prevent_decision_update` et `prevent_custody_update` sont absents. L'architecture exige que les enregistrements `Decision` et `CustodyEntry` soient immuables au niveau DB (append-only). Sans ces triggers, rien n'empêche une modification ou suppression directe en base, compromettant la traçabilité légale du journal.
- **Module concerné :** M8 — Storage
- **Correction requise (P5.11 + P7.11) :** Migration Alembic avec triggers `BEFORE UPDATE OR DELETE` sur `decisions` et `custody_log` levant `RAISE EXCEPTION`.
- **Statut :** 🔴 Ouvert — bloque la certification du journal comme preuve

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

### BUG-004 — `Page[T]` non instanciable 🟡 MINEUR

- **Sévérité :** MINOR
- **Fichier :** `server/oseye/storage/interface.py`
- **Détail :** La classe générique `Page[T]` déclare ses attributs (`items`, `total`, `page`, `page_size`, `has_next`) sans `__init__`. Elle fonctionne comme type structurel (Protocol) mais ne peut pas être instanciée directement. Si un repository retourne `Page(items=[...], ...)`, Python lèvera `TypeError`.
- **Correction (M8) :** Soit convertir en `@dataclass`, soit en `TypedDict`, soit en Pydantic model, selon l'usage prévu.
- **Statut :** 🟡 Ouvert — à corriger en M8 (Storage)

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
| DETTE-009 | `go.mod` manque cilium/ebpf, blake3, mattn/go-sqlite3 | Moyenne | M1 |
| LINT-001 | ~~ruff UP035/I001 dans bus/interface.py, schema.py~~ | Corrigé | M0 |
| LINT-002 | ~~E501 config.py:51~~ | Corrigé | M0 |
| MYPY-001 | ~~mypy strict : `DecisionRepository.list` conflit builtin~~ | Corrigé (→ `list_decisions`) | M0 |
| CI-001 | ~~`cmd/oseye-agent/` vide → `go build` échoue~~ | Corrigé (stub main.go) | M0 |
| DESIGN-001 | `EventBus` Protocol sans méthode `close()` — risque de leak en M5 | Moyenne | M5 |
| OTel-001 | `observability.py` : OTel SDK non initialisé (stub) | Faible | M6/M9 |

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

## Historique des commits

| Hash | Message | Date |
|------|---------|------|
| `53e3fba` | M0: audit engine — self-audit + output credibility + explicit error handling | 2026-08-05 |
| `ec2fdf5` | M0: audit engine — delegate finding verification to tools | 2026-08-05 |
| `8a06dd5` | M0: add proto/.gitkeep — track empty proto dir | 2026-08-05 |
| `db4e1fe` | M0: refactor audit engine — modular architecture (tools/audit/) | 2026-08-05 |
| `ef9607a` | M0: add OSEye Audit Engine — dynamic security & debug scanner | 2026-08-05 |
| `040c15e` | M0: scaffolding, contracts, proto — Phase 1 foundation | 2026-08-05 |
| `b88ff36` | chore: initial project foundation — docs, CI templates, LICENSE, SECURITY | 2026-08-05 |
