# Skill : OSEye — Debugging

## Quand utiliser ce skill

Invoquer avec `/oseye-debug` quand :
- Un test échoue et la cause n'est pas immédiatement claire
- Un composant ne répond pas ou produit des données incorrectes
- Le pipeline event-bus est silencieux
- L'agent Go consomme trop de CPU/mémoire
- Une régression après un merge
- L'utilisateur dit "ça marche pas"

---

## Périmètre : ce que le tool fait, ce que le skill fait

**Délégué au tool** — automatisable, déterministe, ne requiert pas de jugement :
- Détecter les patterns connus (TODO, `__init__.py` absent, `go func()` sans ctx, `except:` bare, etc.)
- Re-vérifier les anciens findings sur les fichiers modifiés
- Détecter les régressions sur les findings "fixed"
- Auditer l'engine lui-même (patterns `TOOL-P*`)
- Calculer quels fichiers ont changé depuis le dernier scan

**Fait par le skill** — requiert lecture de code, exécution, jugement :
- Lire les logs Docker/Go/Python pour identifier la cause racine
- Exécuter les commandes de diagnostic (`go test -race`, `redis-cli`, `alembic current`)
- Interpréter une stacktrace ou une `ValidationError` Pydantic
- Distinguer un faux positif du tool (pattern trop large) d'un vrai bug
- Relier un finding de pattern à un symptôme utilisateur
- Interpréter les avertissements `[AUDIT-WARN]` sur stderr

---

## Commandes canoniques

```bash
cd /home/virus-one/Documents/OSEye_project

# ── Scan ───────────────────────────────────────────────────────────────────
.venv/bin/python -m tools.audit --mode debug             # scan complet + verify auto de tous les findings
.venv/bin/python -m tools.audit --mode debug --diff      # fichiers modifiés : scan + re-verify anciens findings
.venv/bin/python -m tools.audit --mode debug --module M2 # cibler un seul module

# ── Vérification des findings existants ────────────────────────────────────
.venv/bin/python -m tools.audit --verify                 # re-vérifie TOUS les findings ouverts
.venv/bin/python -m tools.audit --verify DBG-0001        # re-vérifie un finding précis
.venv/bin/python -m tools.audit --verify-files "agent/internal/chain/*.go"  # re-vérifie + scanne un glob

# ── Consultation ───────────────────────────────────────────────────────────
.venv/bin/python -m tools.audit --report                 # rapport consolidé
.venv/bin/python -m tools.audit --list-patterns          # voir tous les patterns (incl. TOOL-P*)
```

**Comportements automatiques :**
- `--diff` : scan du nouveau code + re-verify des anciens findings sur les fichiers changés → auto-ferme ceux résolus
- Scan complet : re-vérifie tous les findings ouverts avant de scanner
- L'engine s'audite lui-même via `TOOL-P*`

---

## Commandes de diagnostic

```bash
cd /home/virus-one/Documents/OSEye_project

# Go — tests avec race detector
cd agent && go test -race ./... 2>&1 | tail -20

# Python — tests complets avec coverage
.venv/bin/python -m pytest server/tests/ -v --tb=short

# Ruff + mypy
.venv/bin/python -m ruff check server/oseye/
.venv/bin/python -m mypy server/oseye/ --no-error-summary

# Proto codegen test
./scripts/test_proto_compile.sh
```

---

## Symptômes connus et causes

| Symptôme | Cause | Correction |
|----------|-------|------------|
| `coroutine 'publish' was never awaited` | `asyncio.run()` ou `await` appelé depuis un thread gRPC sans loop active | Utiliser `asyncio.get_running_loop()` + `ensure_future` depuis le thread gRPC |
| `close of closed channel` (Go) | Double-close de `stopCh` lors d'un Stop() concurrent | Protéger avec `select { case <-c.stopCh: default: close(c.stopCh) }` |
| `Event loop is closed` (aiosqlite teardown) | Nettoyage asyncio en fin de test avant fermeture de la connection aiosqlite | Normal dans les tests — non bloquant, ne pas corriger côté code applicatif |

---

## Étape 1 — Vérifier la crédibilité du tool avant de lire les findings

**Avant de faire confiance à la sortie, vérifier :**

```bash
# 1. Avertissements sur stderr
python -m tools.audit --mode debug 2>audit_stderr.txt; cat audit_stderr.txt
# [AUDIT-WARN] regex invalide → finding manquant silencieux
# [AUDIT-WARN] script timeout  → pattern de script ne tourne pas
# [AUDIT-WARN] fichier illisible → permissions ou chemin cassé

# 2. Patterns jamais déclenchés sur des modules implémentés
python -m tools.audit --list-patterns | grep "jamais déclenché"
# Si un pattern ne s'est jamais déclenché après que son module est "implemented"
# → sa regex est peut-être trop stricte ou ses targets sont erronés

# 3. L'engine lui-même sans problème structurel
python -m tools.audit --mode debug --module M0 2>&1 | grep "TOOL-P"
# BLOCKER sur TOOL-P* = l'engine a des bugs → les corriger avant de faire confiance aux résultats

# 4. Le nombre de findings est cohérent avec le code
python -m tools.audit --report | grep "ouverts:"
# 0 findings après ajout de code complexe = suspect → vérifier les targets des patterns actifs
```

**Signaux d'un tool peu fiable (à corriger avant d'interpréter les findings) :**
- `[AUDIT-WARN]` répétés sur les mêmes patterns
- Pattern `hit_count=0` sur un module implémenté depuis plusieurs semaines
- `TOOL-P001` (except bare dans l'engine) ouvert = scanner peut avaler des exceptions silencieusement
- Patterns `TOOL-P*` en CRITICAL ou BLOCKER

---

## Étape 2 — Consulter l'état existant

```bash
python -m tools.audit --report
```

Ne jamais diagnostiquer de zéro. L'historique complet est dans `tools/audit_state.json`.
**Si un finding connu correspond au symptôme → aller directement à l'étape 4.**

---

## Étape 3 — Tri initial du symptôme

```bash
git log --oneline -5 && git status --short | head -10
docker compose -f infra/docker/docker-compose.dev.yml ps 2>/dev/null
docker compose -f infra/docker/docker-compose.dev.yml logs --tail=40 2>/dev/null \
  | grep -E "ERROR|FATAL|panic|Traceback|Exception" | head -20
[ -d agent ] && cd agent && go test ./... 2>&1 | grep -E "^(ok|FAIL|---)" && cd ..
[ -d server ] && cd server && python -m pytest --tb=no -q 2>&1 | tail -10 && cd ..
```

**Arbre de décision — ce que le skill cherche, pas le tool :**

| Symptôme | Ce que le skill exécute et interprète |
|----------|--------------------------------------|
| `go build` échoue | `go build ./... 2>&1` — lire l'erreur. `undefined` = build tag ou `go generate`. `cannot use` = interface non satisfaite. |
| `DATA RACE` | `go test -race ./...` — lire quelle goroutine et quel champ. DBG-P007 (goroutine sans ctx) peut en être la cause. |
| eBPF rejeté | `dmesg | grep bpf` + `uname -r` — le tool ne fait pas ça. |
| BLAKE3 `chain_break` | Lire `hasher.go` : `last_hash` est-il chargé depuis le buffer SQLite au redémarrage ? DBG-P* ne couvre pas ce cas logique. |
| `ImportError` Python | `find server/oseye -type d | while read d; do [ ! -f "$d/__init__.py" ] && echo $d; done` — DBG-P002 couvre ça, mais le skill doit lire le message d'erreur. |
| `ValidationError` Pydantic | `python -c "from oseye.core.schema import X; print([n for n,f in X.model_fields.items() if f.is_required()])"` |
| gRPC `UNAUTHENTICATED` | `openssl x509 -in infra/certs/agent-dev.crt -noout -dates` — cert expiré ? CN ≠ OSEYE_AGENT_ID ? |
| Alembic échoue | `alembic current` puis `OSEYE_DB_URL="sqlite+aiosqlite:///:memory:" alembic upgrade head` |
| Events Redis, pas en DB | `redis-cli XINFO GROUPS events:normalized` → consumer group présent ? |
| API 401/403/500 | `curl /api/v1/health` d'abord. Lire la stacktrace dans les logs. |
| CPU agent > 4% | `cat /proc/$(pgrep oseye-agent)/status | grep VmRSS` — le tool ne mesure pas ça. |

---

## Étape 4 — Diagnostic ciblé (ne s'applique qu'aux fichiers qui existent)

### Agent Go

```bash
cd agent && go build ./... 2>&1
go generate ./internal/platform/linux/ebpf/... 2>/dev/null
go test -race ./... 2>&1 | grep -A 10 "DATA RACE"
uname -r && capsh --print 2>/dev/null | grep -E "cap_bpf|cap_sys_admin"
dmesg | grep -i "bpf\|verif" | tail -10
```

**Bugs connus (alimentés par les findings passés) :**
- `*_bpfel.go` absent → `go generate` jamais lancé sur `ebpf/` → DBG-P003
- `go func()` sans ctx → goroutine orpheline au Stop() → DBG-P007
- `last_hash` en mémoire → rupture chain après redémarrage (non couvert par pattern — logique)

### Server Python

```bash
python -c "from oseye.core.schema import UniversalEvent; print('schema OK')"
python -c "from oseye.config import Settings; print('config OK')"
find server/oseye -type d | while read d; do [ ! -f "$d/__init__.py" ] && echo "MISSING: $d"; done
ls server/gen/ 2>/dev/null || echo "gen/ absent"
openssl x509 -in infra/certs/agent-dev.crt -noout -dates 2>/dev/null
```

**Bugs connus :**
- `gen/` absent → `from gen import event_pb2` échoue → DBG-P003
- Cert expiré (90j) → `UNAUTHENTICATED` → relancer `generate_certs.sh`
- CN ≠ `OSEYE_AGENT_ID` → `grpc_service.py` rejette

### Pipeline Event Bus

```bash
redis-cli --scan --pattern "events:*" 2>/dev/null | while read k; do
  echo "$k: $(redis-cli XLEN "$k") msgs"
done
redis-cli XINFO GROUPS events:normalized 2>/dev/null
redis-cli XLEN events:dlq 2>/dev/null
sqlite3 oseye_dev.db "SELECT count(*), category FROM events GROUP BY category;" 2>/dev/null
```

**Identifier le blocage (jugement du skill) :**
- `events:raw:*` vide → agent ne produit pas ou gRPC échoue
- `events:normalized` vide → Normalizer ne consomme pas
- `events:normalized` plein, DB vide → StorageWriter arrêté ou `insert_batch` silencieusement
- `events:dlq` plein → erreur répétée → lire les logs du worker

### API REST

```bash
curl -s http://localhost:8000/api/v1/health | python -m json.tool
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -d '{"username":"admin","password":"admin"}' -H "Content-Type: application/json" \
  | python -m json.tool | grep access_token | cut -d'"' -f4)
curl -sH "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/events | python -m json.tool
```

---

## Étape 5 — Enregistrer le bug comme pattern

Un bug résolu qui n'est pas encodé comme pattern reviendra sans alarme.

```bash
# Ajouter interactivement :
python -m tools.audit --add-pattern

# Après ajout dans audit_patterns.json, synchroniser persistence.py DEFAULT_PATTERNS
# Si pattern inversé → ajouter l'ID dans models.py _INVERSE_PATTERN_IDS
# Si nouveau module → ajouter dans modules.py _MODULE_SIGNATURES

# Vérifier que le pattern fonctionne :
python -m tools.audit --mode debug
python -m tools.audit --list-patterns | grep "DBG-PXXX"
# hit_count doit augmenter si des fichiers cibles existent
```

---

## Étape 6 — Fermer et vérifier

```bash
# Méthode recommandée : laisser le scan auto-fermer après correction :
python -m tools.audit --mode debug --diff
# → "AUTO-RÉSOLUS" dans la sortie = finding auto-fermé ✓

# Vérifier un composant entier après correction :
python -m tools.audit --verify-files "agent/internal/chain/*.go"

# Vérifier un finding précis :
python -m tools.audit --verify DBG-XXXX
# "Résolus" = fermé ✓  /  "Confirmés" = toujours là, correction insuffisante

# Marquer manuellement si nécessaire :
python -m tools.audit --fix DBG-XXXX --note "description de la correction"
```

---

## Fichiers de l'engine à modifier selon le besoin

| Fichier | Quand le modifier |
|---------|------------------|
| `tools/audit_patterns.json` | Ajouter/modifier/désactiver un pattern |
| `tools/audit/persistence.py` | Synchroniser `DEFAULT_PATTERNS` après ajout |
| `tools/audit/models.py` | `_INVERSE_PATTERN_IDS` ou nouveau champ dataclass |
| `tools/audit/modules.py` | Nouveau module dans `_MODULE_SIGNATURES` |
| `tools/audit/scanner.py` | Nouveau type de scan ou modifier gestion d'erreur |
| `tools/audit/verifier.py` | Modifier `_still_present()` (tolérance ligne, etc.) |
| `tools/audit/reporter.py` | Format d'affichage ou rapport JSON |
| `tools/audit/commands.py` | Nouvelle commande interactive |
| `tools/audit/cli.py` | Nouvel argument CLI |

---

## Références

- Engine : `tools/audit/` (s'audite lui-même via `TOOL-P*`)
- Shim : `tools/oseye_audit.py`
- État : `tools/audit_state.json` (local, non commité)
- Patterns : `tools/audit_patterns.json` (commité, versionné)
- Rapports : `tools/audit_reports/`

---

## Journal des mises à jour

### 2026-08-06 — v6
- Commandes canoniques : chemin venv corrigé en `.venv/bin/python`
- Ajout section "Commandes de diagnostic" : go test -race, pytest, ruff, mypy, proto codegen
- Ajout section "Symptômes connus et causes" : coroutine never awaited, close of closed channel, Event loop is closed

### 2026-08-05 — v5
- Section "Périmètre" : distinction explicite délégué-au-tool vs fait-par-le-skill
- Étape 1 : vérification crédibilité du tool (AUDIT-WARN, hit_count=0, TOOL-P* findings)
- Arbre de décision Étape 3 : colonne "ce que le skill exécute et interprète" (pas le tool)
- Section "Bugs connus" : reliée aux patterns qui les couvrent
- Règle : ne jamais marquer --fp sans avoir lu la ligne concernée

### 2026-08-05 — v4
- Commandes : --verify-files, comportement auto --diff

### 2026-08-05 — v3
- Commande canonique : python -m tools.audit
- Étape mise à jour des tools documentée
