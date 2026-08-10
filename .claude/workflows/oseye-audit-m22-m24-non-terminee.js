
export const meta = {
  name: 'oseye-audit-m22-m24',
  description: 'Audit complet des modules M22-M24 : Rule Engine, API, Keys, RBAC, rules YAML, Go agent',
  phases: [
    { title: 'Audit Go', detail: 'Correctness, races, panics, config, mapper, transport' },
    { title: 'Audit Python', detail: 'Evaluator sandbox, evaluator temporal, auth, API Keys, rule_versions, workers' },
    { title: 'Audit Sécurité', detail: 'RBAC, JWT, API Keys, WebSocket, sandbox, auth' },
    { title: 'Audit Règles', detail: 'YAML correctness, conditions, MITRE, faux positifs' },
    { title: 'Vérification', detail: 'Adversarial verify des findings CRITICAL/HIGH' },
  ],
}

const FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
          file: { type: 'string' },
          line: { type: 'number' },
          title: { type: 'string' },
          description: { type: 'string' },
          remediation: { type: 'string' },
        },
        required: ['id', 'severity', 'file', 'title', 'description', 'remediation'],
      },
    },
  },
  required: ['findings'],
}

const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    confirmed: { type: 'boolean' },
    rationale: { type: 'string' },
  },
  required: ['confirmed', 'rationale'],
}

// ─── Phase 1 : Go ────────────────────────────────────────────────────────────
phase('Audit Go')

const goAudit = await agent(`
Tu es un ingénieur Go senior spécialisé en sécurité et systèmes. Audite le code Go du projet OSEye.
Répertoire : /home/virus-one/Documents/OSEye_project/agent/

LIS ces fichiers en entier (utilise Read) :
- agent/internal/config/config.go
- agent/internal/mapper/mapper.go
- agent/internal/platform/linux/ebpf/loader.go
- agent/internal/platform/linux/ebpf/collector.go
- agent/internal/platform/linux/fanotify/collector.go
- agent/internal/platform/linux/inotify/collector.go
- agent/internal/transport/grpc_client.go
- agent/internal/policy/handler.go

DIMENSIONS À VÉRIFIER :
1. Panics potentiels (index out of range, nil dereference, division par zéro)
2. Races conditions (accès concurrents sans mutex, channel usage)
3. Fuites de goroutines (goroutines qui ne se terminent pas)
4. Gestion des erreurs (erreurs ignorées, bare returns)
5. Validation d'entrées (bounds checks insuffisants)
6. Logique du mapper (mapCategory, mapFields, firstStrField, intField)
7. Config.Validate() : est-elle appelée quelque part ?
8. Transport grpc_client : le backoff est-il correct ? maxRetries=15 suffisant ?
9. La sync.Once dans ReadEvents est-elle correctement utilisée ?
10. Double-close sync.Once dans fanotify/inotify : couvre-t-elle tous les chemins ?

Retourne UNIQUEMENT un JSON avec les findings réels trouvés après lecture du code.
`, { label: 'audit-go', phase: 'Audit Go', schema: FINDINGS_SCHEMA })

// ─── Phase 2 : Python ────────────────────────────────────────────────────────
phase('Audit Python')

const [pyEvaluator, pyApi, pyWorkers] = await parallel([
  () => agent(`
Tu es un ingénieur Python senior spécialisé en sécurité. Audite le rule engine et les adapters.
Répertoire : /home/virus-one/Documents/OSEye_project/server/

LIS ces fichiers en entier :
- server/oseye/rule_engine/evaluator.py
- server/oseye/rule_engine/engine.py
- server/oseye/rule_engine/parser.py
- server/oseye/normalizer/adapters/linux/ebpf.py
- server/oseye/normalizer/adapters/linux/procfs.py
- server/oseye/normalizer/adapters/linux/auditd.py

DIMENSIONS À VÉRIFIER :
1. Sandbox evaluator : re_match wrapper — peut-on encore accéder à __globals__ ou __builtins__ via autre vecteur ? (via event dict, via callable passé, via string formatting)
2. _temporal_windows : le verrou threading.Lock est-il acquis dans TOUS les accès lecture/écriture ?
3. _purge_old_windows : la purge fonctionne-t-elle ? appel tous les 500 enregistrements ?
4. Engine hot-reload : condition de race entre reload() et evaluate() sur self._rules ?
5. Parser : injection YAML — si un fichier rules contient du code Python, est-il exécuté ?
6. Adapters safe_int : que se passe-t-il si la valeur est un float ? un dict ? une liste ?
7. ebpf adapter : event_type manquant dans le payload — que se passe-t-il ?
8. Toute exception silencieuse (bare except, pass, continue sans log)

Retourne UNIQUEMENT un JSON avec les findings réels.
`, { label: 'audit-py-evaluator', phase: 'Audit Python', schema: FINDINGS_SCHEMA }),

  () => agent(`
Tu es un ingénieur Python senior. Audite l'API FastAPI et les repositories.
Répertoire : /home/virus-one/Documents/OSEye_project/server/

LIS ces fichiers en entier :
- server/oseye/api/auth/rbac.py
- server/oseye/api/auth/jwt.py
- server/oseye/api/routers/api_keys.py
- server/oseye/api/routers/alerts.py
- server/oseye/api/routers/auth.py
- server/oseye/api/ws/alerts.py
- server/oseye/storage/repositories/api_keys.py
- server/oseye/storage/repositories/rule_versions.py
- server/oseye/storage/models.py

DIMENSIONS À VÉRIFIER :
1. api_keys : la clé raw est retournée UNE FOIS — mais est-elle aussi loggée quelque part (logs structlog, traces OTEL) ?
2. api_keys : hash SHA-256 sans sel — rainbow table attack possible ?
3. rbac.py _resolve_identity : si api_key_repo est None ET un X-API-Key header est présent, que se passe-t-il ?
4. rbac.py : Bearer token ET X-API-Key présents simultanément — lequel prend priorité ? est-ce voulu ?
5. jwt.py : algorithme HS256 vs RS256 — lequel est utilisé en production ? la clé secrète par défaut est-elle sûre ?
6. alerts.py mark_false_positive : IDOR possible ? un analyst peut-il marquer n'importe quelle alerte ?
7. api_keys router : rate limiting sur POST /api-keys ?
8. alerts WebSocket : token validé, mais que se passe-t-il après connexion si le token expire ?
9. rule_versions : pas de contrainte UNIQUE sur (rule_id, alert_id) — insertions dupliquées possibles ?
10. models.py ApiKeyRow : pas d'index sur created_by ou expires_at — perf sur grandes tables ?

Retourne UNIQUEMENT un JSON avec les findings réels.
`, { label: 'audit-py-api', phase: 'Audit Python', schema: FINDINGS_SCHEMA }),

  () => agent(`
Tu es un ingénieur Python senior. Audite les workers et le bus.
Répertoire : /home/virus-one/Documents/OSEye_project/server/

LIS ces fichiers en entier :
- server/oseye/workers/storage_writer.py
- server/oseye/workers/rule_worker.py
- server/oseye/workers/runner.py
- server/oseye/bus/redis_bus.py
- server/oseye/main.py

DIMENSIONS À VÉRIFIER :
1. storage_writer : double-parse corrigé — est-ce que model_validate_json peut lever une exception non capturée ?
2. rule_worker : que se passe-t-il si create_alert() échoue (DB down) — l'événement est-il perdu ?
3. runner.py : socket.gethostname() peut lever une exception — est-ce gardé ?
4. redis_bus backoff exponentiel : le cap est-il borné ? (éviter backoff infini si Redis reste down)
5. main.py lifespan : si l'init DB échoue, les workers sont-ils démarrés quand même ?
6. main.py lifespan : si grpc_server.start() échoue, le yield se produit-il quand même ?
7. main.py app module-level (ligne ~131) : _build_lifespan appelé deux fois — double initialisation des workers ?
8. normalizer_loop : source hardcodée à "procfs" — tous les events reçus sont traités comme procfs ?

Retourne UNIQUEMENT un JSON avec les findings réels.
`, { label: 'audit-py-workers', phase: 'Audit Python', schema: FINDINGS_SCHEMA }),
])

// ─── Phase 3 : Sécurité ──────────────────────────────────────────────────────
phase('Audit Sécurité')

const secAudit = await agent(`
Tu es un auditeur de sécurité offensive. Cherche des vulnérabilités exploitables.
Répertoire : /home/virus-one/Documents/OSEye_project/server/

LIS ces fichiers :
- server/oseye/api/auth/rbac.py
- server/oseye/api/auth/jwt.py
- server/oseye/api/routers/api_keys.py
- server/oseye/api/routers/auth.py
- server/oseye/api/ws/alerts.py
- server/oseye/rule_engine/evaluator.py
- server/oseye/storage/repositories/api_keys.py

CHERCHE :
1. Injection (SQL, YAML, template, format string)
2. Broken authentication (contournement JWT, clés faibles, timing attacks)
3. Broken access control (IDOR, escalade de privilèges, bypass RBAC)
4. Information disclosure (stack traces, UUIDs prévisibles, timing side-channels)
5. Denial of service (boucles non bornées, allocations non limitées, regex catastrophique)
6. Cryptographie faible (algo déprécié, entropie insuffisante, hash sans sel)
7. Vecteurs d'attaque spécifiques au sandbox rule engine (code execution résiduel)

Pour chaque vulnérabilité : décris le scénario d'exploitation concret.
Retourne UNIQUEMENT un JSON avec les findings réels.
`, { label: 'audit-security', phase: 'Audit Sécurité', schema: FINDINGS_SCHEMA })

// ─── Phase 4 : Règles YAML ───────────────────────────────────────────────────
phase('Audit Règles')

const rulesAudit = await agent(`
Tu es un ingénieur sécurité DFIR. Audite les règles de détection YAML.
Répertoire : /home/virus-one/Documents/OSEye_project/rules/builtin/

LIS ces fichiers en entier :
- rules/builtin/credential_access.yaml
- rules/builtin/lateral_movement.yaml
- rules/builtin/defense_evasion.yaml
- rules/builtin/privilege_escalation.yaml
- rules/builtin/discovery.yaml
- rules/builtin/impact_c2.yaml
- rules/builtin/persistence.yaml (si existe)
- rules/builtin/execution.yaml (si existe)

DIMENSIONS :
1. Conditions logiquement impossibles ou toujours-fausses restantes
2. Faux positifs évidents sur workstations dev (git, npm, pip, docker, make)
3. Règles trop larges couvrant des comportements légitimes courants
4. Règles dont la condition ne correspond pas à la catégorie déclarée (event.category)
5. MITRE ATT&CK IDs incorrects ou trop génériques
6. Règles sans timeframe sur des événements à haute fréquence (spam d'alertes)
7. Règles qui ne peuvent jamais se déclencher avec les champs produits par les adapters Python
8. Manque de règles pour des TTPs courants Linux (T1059, T1055, T1036, T1070)

Retourne UNIQUEMENT un JSON avec les findings réels.
`, { label: 'audit-rules', phase: 'Audit Règles', schema: FINDINGS_SCHEMA })

// ─── Phase 5 : Vérification adversariale ─────────────────────────────────────
phase('Vérification')

// Consolider tous les findings CRITICAL et HIGH
const allFindings = [
  ...(goAudit?.findings ?? []),
  ...(pyEvaluator?.findings ?? []),
  ...(pyApi?.findings ?? []),
  ...(pyWorkers?.findings ?? []),
  ...(secAudit?.findings ?? []),
  ...(rulesAudit?.findings ?? []),
].filter(Boolean).filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')

log(`${allFindings.length} findings CRITICAL/HIGH à vérifier`)

const verified = await pipeline(
  allFindings,
  (f, _, i) => agent(`
Vérifie adversarialement ce finding de sécurité. Ton rôle est de le RÉFUTER si possible.
Lis le fichier concerné pour vérifier si le finding est réel.

Finding #${i + 1}:
ID: ${f.id}
Sévérité: ${f.severity}
Fichier: ${f.file}
Titre: ${f.title}
Description: ${f.description}

INSTRUCTIONS :
1. Lis le fichier ${f.file} (utilise Read)
2. Cherche si le problème existe réellement dans le code actuel
3. Vérifie si une mitigation existe déjà
4. Conclus : confirmed=true si le finding est réel et non mitigé, false sinon

Retourne UNIQUEMENT un JSON {"confirmed": bool, "rationale": "..."}
`, { label: `verify-${f.id}`, phase: 'Vérification', schema: VERDICT_SCHEMA })
    .then(v => ({ ...f, confirmed: v?.confirmed ?? false, rationale: v?.rationale ?? '' }))
)

const confirmed = verified.filter(Boolean).filter(f => f.confirmed)
const allLow = [
  ...(goAudit?.findings ?? []),
  ...(pyEvaluator?.findings ?? []),
  ...(pyApi?.findings ?? []),
  ...(pyWorkers?.findings ?? []),
  ...(secAudit?.findings ?? []),
  ...(rulesAudit?.findings ?? []),
].filter(Boolean).filter(f => f.severity === 'MEDIUM' || f.severity === 'LOW')

log(`Findings confirmés CRITICAL/HIGH : ${confirmed.length}/${allFindings.length}`)

return {
  summary: {
    total_raw: allFindings.length + allLow.length,
    critical_high_raw: allFindings.length,
    critical_high_confirmed: confirmed.length,
    medium_low: allLow.length,
  },
  confirmed_critical_high: confirmed,
  medium_low: allLow,
  all_raw: {
    go: goAudit?.findings ?? [],
    py_evaluator: pyEvaluator?.findings ?? [],
    py_api: pyApi?.findings ?? [],
    py_workers: pyWorkers?.findings ?? [],
    security: secAudit?.findings ?? [],
    rules: rulesAudit?.findings ?? [],
  },
}
