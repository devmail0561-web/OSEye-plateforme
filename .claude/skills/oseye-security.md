# Skill : OSEye — Security Review

## Quand utiliser ce skill

Invoquer avec `/oseye-security` quand :
- Une PR est prête à merger et touche du code sensible
- Un nouveau composant vient d'être implémenté
- Un CVE ou incident de sécurité a été signalé
- L'utilisateur demande une revue de sécurité

---

## Périmètre : ce que le tool fait, ce que le skill fait

**Délégué au tool** — automatisable, déterministe, ne requiert pas de jugement :
- Détecter les patterns connus (eval, shell=True, SQL f-string, HS256, secrets hardcodés, etc.)
- Re-vérifier les anciens findings sur les fichiers modifiés
- Détecter les régressions sur les findings marqués "fixed"
- Auditer l'engine lui-même (patterns `TOOL-P*`)
- Générer les rapports horodatés JSON

**Fait par le skill** — requiert lecture, contexte, jugement :
- Lire le fichier incriminé et confirmer ou infirmer le finding
- Distinguer faux positif légitime vs vraie vulnérabilité
- Évaluer la criticité réelle (contexte d'usage, exploitabilité)
- Décider si une correction est suffisante
- Repérer les vulnérabilités logiques que les regex ne voient pas (ex : race condition, état partagé non protégé, flux d'authentification incomplet)
- Interpréter les avertissements `[AUDIT-WARN]` sur stderr

---

## Commandes canoniques

```bash
cd /home/virus-one/Documents/OSEye_project

# ── Scan ───────────────────────────────────────────────────────────────────
python -m tools.audit --mode security             # scan complet + verify auto de tous les findings
python -m tools.audit --mode security --diff      # fichiers modifiés : scan + re-verify anciens findings
python -m tools.audit --mode security --module M9 # cibler un seul module

# ── Vérification des findings existants ────────────────────────────────────
python -m tools.audit --verify                    # re-vérifie TOUS les findings ouverts
python -m tools.audit --verify SEC-0001           # re-vérifie un finding précis
python -m tools.audit --verify-files "server/oseye/api/**"  # re-vérifie + scanne un glob (PR)

# ── Consultation ───────────────────────────────────────────────────────────
python -m tools.audit --report                    # rapport consolidé
python -m tools.audit --list-patterns             # voir tous les patterns (incl. TOOL-P*)
```

**Comportements automatiques :**
- `--diff` : scan du nouveau code + re-verify des anciens findings sur les fichiers changés → auto-ferme ceux résolus
- Scan complet : re-vérifie tous les findings ouverts avant de scanner → aucun fantôme
- L'engine s'audite lui-même via les patterns `TOOL-P001` à `TOOL-P007`

---

## Étape 1 — Vérifier la crédibilité du tool avant de lire les findings

**Avant de faire confiance à la sortie, vérifier :**

```bash
# 1. Avertissements sur stderr (regex invalide, fichier illisible, script en erreur)
python -m tools.audit --mode security 2>audit_stderr.txt; cat audit_stderr.txt
# Si [AUDIT-WARN] présents → corriger le pattern avant de continuer

# 2. Patterns actifs sur les fichiers qui existent réellement
python -m tools.audit --list-patterns | grep -v "jamais déclenché" | head -20
# Un pattern "jamais déclenché" après plusieurs scans sur des fichiers implémentés
# = soit la regex est trop stricte, soit les targets sont mal configurés

# 3. L'engine s'audite lui-même — vérifier qu'il n'a pas de BLOCKER sur lui-même
python -m tools.audit --mode debug --module M0 | grep "TOOL-P"
# Des BLOCKER sur TOOL-P* = l'engine a des problèmes structurels

# 4. Cohérence du nombre de findings
python -m tools.audit --report | grep "ouverts:"
# Si 0 findings ouverts après ajout de code → suspect, vérifier les targets des patterns
```

**Signaux d'un tool peu fiable :**
- `[AUDIT-WARN]` sur des patterns actifs
- Patterns avec `hit_count=0` sur des modules implémentés depuis longtemps
- Nombre de findings qui ne varie jamais malgré les modifications de code
- Patterns `TOOL-P*` en BLOCKER ou CRITICAL

---

## Étape 2 — Lire l'état existant

```bash
python -m tools.audit --report
```

Lire en priorité : `BLOCKER` > `CRITICAL` > `MAJOR` > `MINOR/INFO`.
Ne jamais reconstruire un audit de zéro — l'historique est dans `tools/audit_state.json`.

---

## Étape 3 — Scanner et analyser

```bash
# Après un merge ou une modification :
python -m tools.audit --mode security --diff

# Avant d'ouvrir une PR (scope précis) :
python -m tools.audit --verify-files "server/oseye/api/**"
```

Pour chaque `BLOCKER` ou `CRITICAL`, **lire le fichier au numéro de ligne indiqué** avant de conclure.

**Ce que le skill juge, le tool ne peut pas :**

| Pattern ID | Ce que le skill doit vérifier en lisant le code |
|------------|------------------------------------------------|
| `SEC-P001` eval | Confirmer que c'est `eval()` natif Python, pas `asteval`. Lire la ligne + les 5 lignes de contexte. |
| `SEC-P002` shell=True | Lire le chemin passé à subprocess. Est-il construit depuis une variable utilisateur ? |
| `SEC-P003` SQL f-string | Lire si `{var}` dans la requête vient d'un input externe ou d'une constante interne. |
| `SEC-P004` HS256 | Vérifier si c'est en production ou dans un test. Les tests peuvent utiliser HS256. |
| `SEC-P005` secret hardcodé | Lire la valeur. Est-ce un vrai secret (32+ chars aléatoires) ou un placeholder de test ? |
| `SEC-P006` agent_id payload | Tracer le code : d'où vient `agent_id` exactement — cert CN ou champ du message ? |
| `SEC-P007` import backend | Lire les imports du fichier. Est-ce `from oseye.storage.backends.sqlite import X` ? |
| `SEC-P008` clé loggée | Lire la ligne de log. Est-ce le chemin vers la clé ou la clé en clair ? |
| `SEC-P010` certs commités | Vérifier que `.gitignore` contient bien `infra/certs/`. |
| `SEC-P011` trigger absent | Lire la migration V001. Les triggers sont-ils présents ou dans une autre migration ? |
| `SEC-P012` rate limit absent | `/auth/token` est-il implémenté ? Si oui, chercher `slowapi` ou `Limiter` dans toute l'app. |
| `TOOL-P003` shell=True engine | Lire `scan_script()`. Le script vient-il de patterns.json (contrôlé) ou d'un input utilisateur ? |

**Vulnérabilités que le tool ne détecte pas — à chercher manuellement :**
- Flux d'authentification incomplet (ex : JWT vérifié mais rôle non contrôlé sur un endpoint)
- Race conditions dans les workers asyncio (ex : deux workers qui écrivent le même finding)
- État partagé non protégé entre coroutines
- Logique de décision contournable (ex : score toujours bas car un signal n'est jamais alimenté)

---

## Checklist de sécurité

Points à vérifier manuellement avant toute PR touchant le code Go ou Python :

- [ ] **`atomic.Value`** pour les champs partagés entre goroutines (`lastError`, `throttle`) — ne pas utiliser de mutex sur des valeurs lues/écrites fréquemment depuis plusieurs goroutines
- [ ] **`asyncio.ensure_future`** utilisé depuis les threads gRPC (jamais `asyncio.run()` — provoque `RuntimeError: This event loop is already running`)
- [ ] **`lru_cache`** sur `get_settings()` — éviter l'instanciation multiple de `Settings()` à chaque requête

---

## Étape 4 — Traiter les findings

```bash
# Correction faite → laisser le scan auto-fermer (méthode recommandée) :
python -m tools.audit --mode security --diff
# → "AUTO-RÉSOLUS" dans la sortie = finding auto-fermé ✓

# Vérifier qu'un finding précis est résolu :
python -m tools.audit --verify SEC-XXXX

# Marquer manuellement (correction dans une branche non scannée) :
python -m tools.audit --fix SEC-XXXX --note "corrigé dans jwt.py:42 — RS256 enforced"

# Marquer faux positif (après avoir lu le code et confirmé) :
python -m tools.audit --fp SEC-XXXX --note "raison précise"
# Règle : ne jamais marquer --fp sans avoir lu la ligne concernée
```

---

## Failles connues et corrigées

| ID | Description | Statut | Fichier(s) |
|----|-------------|--------|------------|
| SEC-PREV-001 | `agent_id` extrait du CN du certificat mTLS, pas du champ payload — empêche l'usurpation d'identité d'agent | Corrigé, enforced | `server/oseye/grpc/grpc_service.py` |
| SEC-PREV-002 | Data race sur `lastError` dans les modules fanotify/inotify (M12) — champ lu/écrit depuis plusieurs goroutines sans synchronisation | Corrigé avec `atomic.Value` | `agent/internal/platform/linux/fanotify/`, `inotify/` |

---

## Étape 5 — Ajouter un pattern pour un vecteur non couvert

Quand une vulnérabilité n'est pas couverte par les patterns existants.

### 5a — Dans `audit_patterns.json`

```bash
python -m tools.audit --add-pattern
```

### 5b — Synchroniser `DEFAULT_PATTERNS` dans `persistence.py`

Copier l'entrée JSON en dict Python dans `tools/audit/persistence.py` → `DEFAULT_PATTERNS`.

### 5c — Si pattern inversé → `models.py`

Ajouter l'ID dans `_INVERSE_PATTERN_IDS` dans `tools/audit/models.py`.

### 5d — Si nouveau module → `modules.py`

Ajouter dans `_MODULE_SIGNATURES` dans `tools/audit/modules.py`.

### 5e — Vérifier que le nouveau pattern fonctionne

```bash
# Forcer un scan complet pour déclencher le nouveau pattern :
python -m tools.audit --mode security
# Vérifier avec --list-patterns que hit_count > 0 si des fichiers cibles existent
python -m tools.audit --list-patterns | grep "SEC-PXXX"
```

---

## Étape 6 — Workflow PR complet

```bash
# 1. Avant d'ouvrir la PR — audit ciblé sur les fichiers modifiés :
python -m tools.audit --verify-files "server/oseye/api/**" 2>stderr.txt
cat stderr.txt  # vérifier les AUDIT-WARN

# 2. Lire et juger les findings BLOCKER/CRITICAL (voir tableau Étape 3)

# 3. Corriger le code

# 4. Après merge — scan incrémental de confirmation :
python -m tools.audit --mode security --diff
# Les findings résolus apparaissent dans "AUTO-RÉSOLUS"
```

---

## Fichiers de l'engine à modifier selon le besoin

| Fichier | Quand le modifier |
|---------|------------------|
| `tools/audit_patterns.json` | Ajouter/modifier/désactiver un pattern |
| `tools/audit/persistence.py` | Synchroniser `DEFAULT_PATTERNS` après ajout |
| `tools/audit/models.py` | `_INVERSE_PATTERN_IDS` ou nouveau champ dataclass |
| `tools/audit/modules.py` | Nouveau module dans `_MODULE_SIGNATURES` |
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
- Architecture sécurité : `docs/ARCHITECTURE.md` §5

---

## Journal des mises à jour

### 2026-08-06 — v6
- Ajout section "Checklist de sécurité" : atomic.Value, asyncio.ensure_future depuis threads gRPC, lru_cache sur get_settings()
- Ajout section "Failles connues et corrigées" : SEC-PREV-001 (agent_id CN mTLS), SEC-PREV-002 (data race lastError avec atomic.Value)

### 2026-08-05 — v5
- Section "Périmètre" : distinction explicite délégué-au-tool vs jugé-par-le-skill
- Étape 1 : vérification de la crédibilité du tool (AUDIT-WARN, hit_count=0, TOOL-P* findings)
- Tableau Étape 3 : pour chaque pattern, ce que le skill doit vérifier manuellement
- Vulnérabilités non détectables par regex listées explicitement
- Règle : ne jamais --fp sans avoir lu la ligne concernée
- Self-audit : patterns TOOL-P001 à TOOL-P007 couvrent tools/audit/ lui-même

### 2026-08-05 — v4
- Commandes : --verify-files, --no-verify-existing
- Comportement automatique : --diff re-vérifie + scanne, scan complet vérifie tout

### 2026-08-05 — v3
- Commande canonique : python -m tools.audit
- Étape mise à jour des tools documentée (4a-4e)
