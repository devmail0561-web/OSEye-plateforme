# Skill : OSEye — Security Review

## Quand utiliser ce skill

Invoquer avec `/oseye-security` quand :
- Une PR est prête à merger et touche du code sensible
- Un nouveau composant vient d'être implémenté
- Un CVE ou incident de sécurité a été signalé
- L'utilisateur demande une revue de sécurité

---

## Périmètre couvert par l'audit tool

L'engine couvre maintenant **l'intégralité du projet** : agent Go, server Python, UI TypeScript (M0–M32).

**42 patterns actifs** répartis en :
- **SEC-P001–P020** : sécurité (Go + Python + TypeScript)
- **DBG-P001–P014** : qualité de code
- **TOOL-P001–P007** : auto-audit de l'engine lui-même

**Périmètre par langage :**
| Cible | Patterns |
|-------|----------|
| `server/**/*.py` | SEC-P001–P012, DBG-P001,P004,P009,P012 |
| `agent/**/*.go` | SEC-P005,P008, DBG-P001,P005,P007,P008,P014 |
| `ui/src/**/*.ts(x)` | SEC-P018,P019,P020, DBG-P011 |
| `server/oseye/rule_engine/` | SEC-P013 (eval sandboxé) |
| `server/oseye/plugin/` | SEC-P014,P015 (path traversal, signature) |
| `server/oseye/decision/` | SEC-P016 (journal hash) |
| `server/oseye/api/auth/` | SEC-P004,P017 (HS256), SEC-P012 (rate limit) |

---

## Périmètre : tool vs skill

**Délégué au tool** — déterministe :
- Patterns regex/script sur tout le code source
- Re-vérification des anciens findings sur fichiers modifiés
- Détection de régressions sur findings "fixés"
- Auto-résolution quand le code est corrigé

**Fait par le skill** — jugement humain requis :
- Confirmer ou infirmer chaque finding (lire le fichier à la ligne indiquée)
- Distinguer faux positif légitime vs vraie vulnérabilité
- Évaluer l'exploitabilité réelle (contexte d'usage, surface d'attaque)
- Repérer les vulnérabilités logiques hors regex (race conditions, flux auth incomplet)
- Interpréter les patterns INVERSÉS (fire = présence attendue manquante)

---

## Commandes canoniques

```bash
cd /home/virus-one/Documents/OSEye_project

# ── Scan complet ──────────────────────────────────────────────────────────
python -m tools.audit --mode security             # scan complet (revalide tout)
python -m tools.audit --mode security --diff      # fichiers modifiés uniquement

# ── Vérification ciblée ───────────────────────────────────────────────────
python -m tools.audit --verify                    # re-vérifie tous les findings ouverts
python -m tools.audit --verify SEC-0001           # re-vérifie un finding précis
python -m tools.audit --verify-files "server/oseye/api/**"  # scan + re-verify glob (PR)

# ── Consultation ──────────────────────────────────────────────────────────
python -m tools.audit --report                    # rapport consolidé
python -m tools.audit --list-patterns             # 42 patterns + hit_count
```

---

## Étape 1 — Vérifier la crédibilité du tool

```bash
python -m tools.audit --mode security 2>audit_stderr.txt; cat audit_stderr.txt
python -m tools.audit --list-patterns | grep "jamais déclenché" | head -10
```

**Signaux d'un tool peu fiable :**
- `[AUDIT-WARN]` sur stderr
- Patterns avec `hit_count=0` sur modules implémentés depuis longtemps
- TOOL-P* en BLOCKER/CRITICAL

---

## Étape 2 — Lire le rapport existant

```bash
python -m tools.audit --report
```

Priorité : `BLOCKER` > `CRITICAL` > `MAJOR` > `MINOR/INFO`.
Ne jamais reconstruire un audit de zéro — l'historique est dans `tools/audit_state.json`.

---

## Étape 3 — Scanner et analyser

```bash
python -m tools.audit --mode security --diff   # après un commit
python -m tools.audit --verify-files "server/oseye/api/**"   # avant PR
```

### Table de jugement par pattern

| ID | Ce que le skill doit vérifier |
|----|-------------------------------|
| `SEC-P001` eval | Confirmer que c'est `eval()` natif Python, pas `ast.parse + compile + eval(..., {"__builtins__":{}}, ns)`. Lire la fonction entière. |
| `SEC-P002` shell=True | Lire le chemin passé à subprocess. Vient-il d'un input utilisateur ou d'une constante interne ? |
| `SEC-P003` SQL f-string | `{var}` dans la requête vient-il d'un input externe ou d'une constante interne ? |
| `SEC-P004` HS256 | La branche `_algorithm = "HS256"` est-elle conditionnelle sur `secret is not None` (mode test) ? |
| `SEC-P005` secret hardcodé | Fichier de test ou code de production ? Valeur synthétique ou vrai secret ? |
| `SEC-P006` agent_id payload | `agent_id` vient-il du CN du certificat mTLS ou de `request.agent_id` ? |
| `SEC-P007` import backend | Le fichier est-il un point d'entrée app (main.py, runner.py) ou un composant métier ? |
| `SEC-P009` CORS wildcard | `allow_origins=["*"]` dans config dev ou production ? |
| `SEC-P011` trigger absent (INVERSE) | Les triggers `prevent_decision_update` et `prevent_custody_update` sont-ils dans la migration V001 ? |
| `SEC-P012` rate limit absent (INVERSE) | `slowapi.Limiter` est-il présent dans auth.py ou app.py ? |
| `SEC-P013` eval sandboxé | Même que SEC-P001 mais ciblé sur `rule_engine/evaluator.py`. Vérifier `_check_ast` + `builtins={}`. |
| `SEC-P014` path traversal | Le chemin est-il résolu avec `.resolve()` puis vérifié avec `.is_relative_to(PLUGIN_DIR)` ? |
| `SEC-P015` signature plugin (INVERSE) | Dans `install()` : `verify=True` par défaut et `_verifier.verify()` appelé avant la copie ? |
| `SEC-P016` journal hash (INVERSE) | `journal_hash` et `prev_journal_hash` sont-ils bien calculés ET vérifiés dans `journal.py` ? |
| `SEC-P017` HS256 prod | `_algorithm = "HS256"` est-il dans une branche conditionnelle `secret is not None` ou hors condition ? |
| `SEC-P018` localStorage JWT | Le token JWT est-il en localStorage ? Si oui, vérifier la présence de CSP dans app.py (SEC-P019). |
| `SEC-P019` security headers (INVERSE) | `Content-Security-Policy` ou `SecurityHeadersMiddleware` présent dans app.py ? |
| `SEC-P020` WS JWT (INVERSE) | `ws.send(token)` appelé dans `ws.onopen` côté UI et côté serveur vérifié dans le handler WS ? |

**Vulnérabilités hors patterns à chercher manuellement :**
- Flux d'authentification incomplet (JWT vérifié mais rôle non contrôlé sur un endpoint)
- Race conditions dans les workers asyncio
- État partagé non protégé entre coroutines
- ML score non borné dans [0.0, 1.0]
- `asyncio.run()` dans un thread gRPC (RuntimeError event loop already running)

---

## État actuel des findings (2026-08-10)

### Vrais positifs ouverts

| ID | Sévérité | Description | Fichier | Action |
|----|----------|-------------|---------|--------|
| SEC-0036 | MAJOR | JWT stocké en localStorage | `ui/src/stores/authStore.ts:38` | Ajouter CSP strict ou migrer vers httpOnly cookie |
| SEC-0037 | MAJOR | JWT stocké en localStorage | `ui/src/stores/authStore.ts:51` | Même correction |

### Findings résolus confirmés (faux positifs documentés)

| ID | Pattern | Raison FP |
|----|---------|-----------|
| SEC-0004 | eval() rule_engine | Sandbox AST complet : `ast.parse + _check_ast + compile + builtins={}` |
| SEC-0005 | HS256 | Conditionnel sur `secret is not None` — RS256 utilisé en production |
| SEC-0006–0011 | secrets | Valeurs synthétiques dans `server/tests/` |
| SEC-0012 | import backend | `main.py` = point d'entrée app, instanciation directe acceptable |
| SEC-0013–0014 | eval doublon | Même ligne que SEC-0004 |
| SEC-0015–0017 | path traversal | Imports `pathlib` niveau module, pas d'accès fichier non contrôlé |
| SEC-0018–0027 | plugin signature | Vérification présente dans `install()` avec `verify=True` par défaut |
| SEC-0028–0034 | journal hash | Pattern INVERSÉ — hash bien présent et vérifié |
| SEC-0035 | HS256 doublon | Même ligne que SEC-0005 |
| SEC-0038 | localStorage | Fichier de test (`authStore.test.ts`) |
| SEC-0039 | WS JWT | Pattern INVERSÉ — `ws.send(token)` bien présent dans `onopen` |

---

## Étape 4 — Traiter les findings

```bash
# Correction faite — laisser le scan auto-fermer :
python -m tools.audit --mode security --diff
# → "AUTO-RÉSOLUS" dans la sortie = finding fermé ✓

# Vérifier un finding précis :
python -m tools.audit --verify SEC-XXXX

# Marquer faux positif (après lecture du code) :
python -m tools.audit --fp SEC-XXXX --note "raison précise + ligne"
# Règle : ne jamais --fp sans avoir lu la ligne concernée
```

---

## Étape 5 — Ajouter un pattern pour un vecteur non couvert

```bash
python -m tools.audit --add-pattern
```

Puis synchroniser dans `persistence.py` → `DEFAULT_PATTERNS` et mettre à jour la liste d'exclusion de `TOOL-P002` si le nouveau pattern est inversé (script-only, targets=[]).

---

## Checklist de sécurité Go/Python avant PR

- [ ] `atomic.Value` pour champs partagés entre goroutines (pas de mutex sur compteurs fréquents)
- [ ] `asyncio.ensure_future()` depuis threads gRPC (jamais `asyncio.run()`)
- [ ] `lru_cache` sur `get_settings()` — éviter instanciation multiple
- [ ] Scores ML bornés dans `[0.0, 1.0]` avant retour
- [ ] Toute goroutine s'arrête sur `ctx.Done()` ou `stopCh`
- [ ] `Stop()` idempotent : `select { case <-stopCh: default: close(stopCh) }`

---

## Failles connues et corrigées

| ID | Description | Statut | Fichier(s) |
|----|-------------|--------|------------|
| SEC-PREV-001 | `agent_id` extrait du CN du certificat mTLS, pas du champ payload | Corrigé | `server/oseye/grpc/grpc_service.py` |
| SEC-PREV-002 | Data race sur `lastError` dans fanotify/inotify — `atomic.Value` | Corrigé | `agent/internal/platform/linux/fanotify/`, `inotify/` |
| SEC-PREV-003 | Trigger immuabilité (`prevent_decision_update`, `prevent_custody_update`) absents | Corrigé | `server/oseye/storage/migrations/` |

---

## Fichiers de l'engine

| Fichier | Quand le modifier |
|---------|------------------|
| `tools/audit_patterns.json` | Ajouter/modifier/désactiver un pattern |
| `tools/audit/persistence.py` | Synchroniser `DEFAULT_PATTERNS` + liste exclusion `TOOL-P002` |
| `tools/audit/modules.py` | Nouveau module dans `_MODULE_SIGNATURES` |
| `tools/audit/models.py` | `_INVERSE_PATTERN_IDS` ou nouveau champ dataclass |
| `tools/audit/scanner.py` | Nouveau type de scan |
| `tools/audit/verifier.py` | Modifier la tolérance `_still_present()` |
| `tools/audit/reporter.py` | Format d'affichage ou rapport JSON |
| `tools/audit/commands.py` | Nouvelle commande interactive |
| `tools/audit/cli.py` | Nouvel argument CLI |

---

## Références

- Engine : `tools/audit/` (package modulaire, s'audite lui-même via `TOOL-P*`)
- Shim : `tools/oseye_audit.py`
- État : `tools/audit_state.json` (local, non commité)
- Patterns : `tools/audit_patterns.json` (commité, versionné)
- Rapports : `tools/audit_reports/`

---

## Journal des mises à jour

### 2026-08-10 — v7
- **Modules M12–M32 ajoutés** dans `modules.py` (agent Go complet, server M22-M31, UI M32)
- **12 nouveaux patterns** : SEC-P013–P020 (eval sandboxé, path traversal, signature plugin, journal hash, HS256 prod, localStorage JWT, security headers, WS JWT) + DBG-P011–P014 (TODO UI, asyncio.run gRPC, ML score, goroutine leak)
- **Scan complet lancé** sur le nouveau périmètre : 45 findings → 34 FP documentés → **2 vrais positifs ouverts** (JWT localStorage)
- Table de jugement étendue aux 20 patterns actifs
- Section "État actuel des findings" mise à jour

### 2026-08-06 — v6
- Ajout checklist sécurité : atomic.Value, asyncio.ensure_future, lru_cache
- Failles connues : SEC-PREV-001 (agent_id CN mTLS), SEC-PREV-002 (data race atomic.Value)

### 2026-08-05 — v5
- Section périmètre tool vs skill
- Vérification crédibilité du tool
- Tableau de jugement par pattern (M0–M11)
