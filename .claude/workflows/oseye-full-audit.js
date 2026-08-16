export const meta = {
  name: 'oseye-full-audit',
  description: 'Audit complet tous modules OSEye — Go agent + Python server + Règles YAML',
  phases: [
    { title: 'Audit Go', detail: 'Core + backoff, enrollment, responder, signer' },
    { title: 'Audit Python Core', detail: 'config, main, bus, ingest, normalizer, storage' },
    { title: 'Audit Python API', detail: 'tous les routers + auth + rbac + ws' },
    { title: 'Audit Python Workers', detail: 'rule_engine, workers, correlation' },
    { title: 'Audit Nouveaux Modules', detail: 'decision, forensic, ml_engine, plugin, policy, phase4' },
    { title: 'Audit Règles', detail: 'rules/builtin/*.yaml — correctness, FP, MITRE' },
    { title: 'Vérification', detail: 'Vérification adversariale des findings CRITICAL/HIGH' },
    { title: 'Synthèse', detail: 'Consolidation, déduplication, rapport final' },
  ],
}

const FINDING_SCHEMA = {
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

const ROOT = '/home/virus-one/Documents/OSEye_project'

// ─── Phases 1-6 en parallèle ────────────────────────────────────────────────
log('Lancement des 6 audits en parallèle...')

const [goAudit, goNewAudit, pyCore, pyApi, pyWorkers, pyDecision, pyForensic, pyMlPlugin, pyPhase4, rulesAudit] = await parallel([

  // ── Audit Go Core ──────────────────────────────────────────────────────────
  () => agent(`
Tu es un auditeur sécurité/qualité Go expert. Audite les modules CORE de l'agent OSEye.

Répertoire racine : ${ROOT}/agent/

LIS CHAQUE fichier source Go (pas les tests) :
- cmd/oseye-agent/main.go
- internal/buffer/buffer.go
- internal/chain/chain.go
- internal/collector/interface.go
- internal/collector/manager.go
- internal/commands/client.go
- internal/config/config.go
- internal/mapper/mapper.go
- internal/platform/linux/driver.go
- internal/platform/linux/ebpf/collector.go
- internal/platform/linux/ebpf/loader.go
- internal/platform/linux/auditd/collector.go
- internal/platform/linux/fanotify/collector.go
- internal/platform/linux/inotify/collector.go
- internal/platform/linux/journald/collector.go
- internal/platform/linux/netlink/collector.go
- internal/platform/linux/procfs/collector.go
- internal/platform/linux/syslog/collector.go
- internal/platform/linux/udev/collector.go
- internal/platform/registry.go
- internal/transport/batcher.go
- internal/transport/grpc_client.go
- internal/watchdog/watchdog.go
- internal/policy/client.go
- internal/policy/handler.go

Cherche :
- Panics potentiels (nil deref, index OOB, send on closed channel)
- Race conditions (accès concurrent sans mutex/sync.Once)
- Fuites de goroutines ou ressources (fd, net.Conn)
- Erreurs ignorées silencieusement (err discarded)
- Logique incorrecte ou edge cases non gérés
- Problèmes de sécurité (injection, overflow, validation manquante)
- Dettes techniques HIGH/MEDIUM

Pour chaque fichier lu, note ce que tu trouves ou "rien à signaler".
Retourne un JSON avec les findings.
`, { label: 'audit-go-core', phase: 'Audit Go', schema: FINDING_SCHEMA }),

  // ── Audit Go Nouveaux modules ───────────────────────────────────────────────
  () => agent(`
Tu es un auditeur sécurité/qualité Go expert. Audite les modules NOUVEAUX de l'agent OSEye.

Répertoire racine : ${ROOT}/agent/

LIS CHAQUE fichier source Go :
- internal/backoff/backoff.go
- internal/enrollment/client.go
- internal/responder/dedup.go
- internal/responder/executor.go
- internal/responder/reporter.go
- internal/responder/state.go
- internal/signer/signer.go

Cherche en priorité :
- enrollment/client.go : validation du certificat reçu (CN, signature CA), token dans URL vs header, HTTP vs HTTPS
- responder/executor.go : nft flush chain efface tous les blocages (A-1), injection shell via IP non validée
- responder/state.go : race conditions sur l'accès concurrent à ActionState
- responder/dedup.go : logique de déduplication incorrecte (faux négatifs)
- responder/reporter.go : erreurs ignorées, fuites
- backoff/backoff.go : boucle infinie possible, overflow du délai
- signer/signer.go : clé faible, algorithme non sécurisé, validation des entrées

Retourne un JSON avec les findings. Chaque finding doit avoir un ID unique (ex: G-N-01).
`, { label: 'audit-go-new', phase: 'Audit Go', schema: FINDING_SCHEMA }),

  // ── Audit Python Core ──────────────────────────────────────────────────────
  () => agent(`
Tu es un auditeur sécurité/qualité Python expert. Audite les modules CORE du serveur OSEye.

Répertoire racine : ${ROOT}/server/oseye/

LIS CHAQUE fichier :
- config.py
- main.py
- core/schema.py
- core/observability.py
- core/pagination.py
- bus/interface.py
- bus/memory_bus.py
- bus/redis_bus.py
- bus/factory.py
- ingest/grpc_service.py
- ingest/normalizer_bridge.py
- ingest/server.py
- ingest/validator.py
- normalizer/engine.py
- normalizer/secret_masker.py
- normalizer/adapters/linux/_utils.py
- normalizer/adapters/linux/procfs.py
- normalizer/adapters/linux/auditd.py
- normalizer/adapters/linux/ebpf.py
- normalizer/adapters/linux/fanotify.py
- normalizer/adapters/linux/inotify.py
- normalizer/adapters/linux/journald.py
- normalizer/adapters/linux/netlink.py
- normalizer/adapters/linux/syslog.py
- normalizer/adapters/linux/udev.py
- storage/backends/sqlite.py
- storage/migrations/__init__.py
- storage/models.py
- storage/repositories/events.py
- storage/repositories/alerts.py
- storage/repositories/decisions.py
- storage/repositories/cases.py
- storage/repositories/api_keys.py
- storage/repositories/rule_versions.py
- storage/repositories/incidents.py
- storage/repositories/agents.py
- storage/repositories/blocked_agents.py
- storage/repositories/response_actions.py

Cherche :
- SQL injection, command injection, path traversal
- Race conditions asyncio (shared state sans lock)
- Fuites de connexions/sessions DB
- Validation insuffisante des entrées
- Erreurs swallowed silencieusement
- Auth bypass, info leak, SSRF
- Dettes techniques HIGH/MEDIUM

Retourne un JSON avec les findings. IDs : PC-01, PC-02...
`, { label: 'audit-py-core', phase: 'Audit Python Core', schema: FINDING_SCHEMA }),

  // ── Audit Python API ───────────────────────────────────────────────────────
  () => agent(`
Tu es un auditeur sécurité API REST expert. Audite TOUS les routers API du serveur OSEye.

Répertoire racine : ${ROOT}/server/oseye/

LIS CHAQUE fichier :
- api/app.py
- api/auth/jwt.py
- api/auth/rbac.py
- api/routers/auth.py
- api/routers/events.py
- api/routers/alerts.py
- api/routers/rules.py
- api/routers/api_keys.py
- api/routers/incidents.py
- api/routers/ti.py
- api/routers/health.py
- api/routers/agents.py
- api/routers/cases.py
- api/routers/decisions.py
- api/routers/enrollment.py
- api/routers/plugins.py
- api/routers/policies.py
- api/routers/response_actions.py
- api/routers/snapshots.py
- api/ws/alerts.py
- api/ws/manager.py

Cherche en priorité :
- IDOR (accès à des ressources d'autres utilisateurs)
- Privilege escalation (RBAC mal implémenté)
- Endpoints sans auth
- Rate limiting absent ou insuffisant
- Input validation insuffisante (injections, DoS)
- Mass assignment / over-posting
- Information disclosure dans les erreurs
- CORS misconfiguration
- JWT vulnérabilités (alg confusion, weak keys, expiry non vérifié)
- WebSocket security issues
- enrollment.py : token exposé, validation insuffisante

Retourne un JSON avec les findings. IDs : API-01, API-02...
`, { label: 'audit-py-api', phase: 'Audit Python API', schema: FINDING_SCHEMA }),

  // ── Audit Python Workers ───────────────────────────────────────────────────
  () => agent(`
Tu es un auditeur qualité/sécurité expert. Audite les workers et rule engine d'OSEye.

Répertoire racine : ${ROOT}/server/oseye/

LIS CHAQUE fichier :
- rule_engine/__init__.py
- rule_engine/engine.py
- rule_engine/evaluator.py
- rule_engine/models.py
- rule_engine/parser.py
- workers/rule_worker.py
- workers/storage_writer.py
- workers/ti_worker.py
- workers/correlation_worker.py
- workers/ml_worker.py
- workers/runner.py
- correlation/engine.py
- correlation/linkers/same_host.py

Cherche :
- Sandbox escape dans l'évaluateur de règles (module re, exec, eval, import)
- Race conditions dans les workers asyncio
- Memory leaks (accumulation sans purge, cache non borné)
- Message loss (events consommés mais non traités en cas d'erreur)
- Logique de corrélation incorrecte
- YAML injection, ReDoS dans le rule parser
- Appels synchrones bloquant la boucle asyncio

Retourne un JSON avec les findings. IDs : W-01, W-02...
`, { label: 'audit-py-workers', phase: 'Audit Python Workers', schema: FINDING_SCHEMA }),

  // ── Audit Decision Engine ──────────────────────────────────────────────────
  () => agent(`
Tu es un auditeur sécurité expert. Audite le Decision Engine et les modules NOUVEAUX Python d'OSEye.

Répertoire racine : ${ROOT}/server/oseye/

LIS CHAQUE fichier :
- decision/engine.py
- decision/action_executor.py
- decision/human_queue.py
- decision/journal.py

Cherche en priorité :
- action_executor.py : actions exécutées sans vérification de l'état de l'agent, injection via dst_ip, ISOLATE sans dst_ip silencieux (A-8), commandes bloquantes dans asyncio
- engine.py : logique de décision incorrecte (faux positifs massifs, escalade non bornée), état partagé sans lock
- human_queue.py : race condition sur la file d'approbation, approbation rejouable, timeout non géré
- decision/journal.py : fuites d'info sensibles dans le journal, intégrité non vérifiée

Retourne un JSON avec les findings. IDs : D-01, D-02...
`, { label: 'audit-decision', phase: 'Audit Nouveaux Modules', schema: FINDING_SCHEMA }),

  // ── Audit Forensic ─────────────────────────────────────────────────────────
  () => agent(`
Tu es un auditeur sécurité expert. Audite le module Forensic d'OSEye.

Répertoire racine : ${ROOT}/server/oseye/forensic/

LIS CHAQUE fichier :
- case_manager.py
- snapshot.py
- timeline.py
- exporter/html_report.py
- exporter/json_export.py
- exporter/misp_export.py
- exporter/pdf_report.py
- exporter/thehive_export.py

Cherche en priorité :
- XSS dans html_report.py (injection de données non échappées dans HTML)
- Path traversal dans les exports (noms de fichiers contrôlables)
- SSRF dans misp_export.py et thehive_export.py (URLs configurables)
- Info leak dans json_export.py et pdf_report.py (données sensibles exportées sans filtre)
- Fuites de credentials (clés API MISP/TheHive dans les logs ou exports)
- Race conditions dans case_manager.py et snapshot.py
- Logique incorrecte dans timeline.py (tri, gaps, données corrompues)

Retourne un JSON avec les findings. IDs : F-01, F-02...
`, { label: 'audit-forensic', phase: 'Audit Nouveaux Modules', schema: FINDING_SCHEMA }),

  // ── Audit ML/Plugin/Policy ─────────────────────────────────────────────────
  () => agent(`
Tu es un auditeur sécurité expert. Audite les modules ML, Plugin et Policy d'OSEye.

Répertoire racine : ${ROOT}/server/oseye/

LIS CHAQUE fichier :
- ml_engine/engine.py
- ml_engine/classifier.py
- ml_engine/anomaly.py
- ml_engine/features.py
- ml_engine/ab_test.py
- plugin/manager.py
- plugin/sandbox.py
- plugin/verifier.py
- plugin/examples/exporter_s3.py
- plugin/examples/notifier_pagerduty.py
- policy/engine.py

Cherche en priorité :
- plugin/sandbox.py : sandbox escape (module builtins, __import__, exec, compile accessible ?)
- plugin/verifier.py : signature non vérifiée, fichiers malveillants acceptés
- plugin/manager.py : arbitrary code execution via upload, path traversal, plugin reload
- ml_engine/engine.py : modèle empoisonnable (data poisoning via false positive feedback), appels ML synchrones bloquant asyncio
- ml_engine/classifier.py + anomaly.py : featurization déterministe ? overflow numérique ?
- ml_engine/ab_test.py : split non aléatoire, biais de sélection
- policy/engine.py : politiques appliquées sans validation, bypass possible

Retourne un JSON avec les findings. IDs : ML-01, PL-01, POL-01...
`, { label: 'audit-ml-plugin', phase: 'Audit Nouveaux Modules', schema: FINDING_SCHEMA }),

  // ── Audit Phase 4 (ThreatIntel) ────────────────────────────────────────────
  () => agent(`
Tu es un auditeur sécurité expert. Audite les modules Threat Intel d'OSEye.

Répertoire racine : ${ROOT}/server/oseye/

LIS CHAQUE fichier :
- threat_intel/models.py
- threat_intel/breaker.py
- threat_intel/retry.py
- threat_intel/cache.py
- threat_intel/client.py
- threat_intel/providers/base.py
- threat_intel/providers/abuseipdb.py
- threat_intel/providers/virustotal.py
- threat_intel/providers/misp.py
- storage/repositories/incidents.py

Cherche :
- SSRF via les providers TI (requêtes vers IPs/URLs contrôlées par l'attaquant)
- Cache poisoning (clés de cache manipulables)
- Race conditions dans AsyncCircuitBreaker
- Fuites de clés API dans les logs
- Logique de retry incorrecte (boucle infinie, amplification)
- SQL injection dans incidents repository
- Logique d'agrégation incorrecte dans ThreatIntelClient

Retourne un JSON avec les findings. IDs : TI-01, TI-02...
`, { label: 'audit-phase4', phase: 'Audit Nouveaux Modules', schema: FINDING_SCHEMA }),

  // ── Audit Règles YAML ──────────────────────────────────────────────────────
  () => agent(`
Tu es un expert en détection SIEM/EDR. Audite toutes les règles YAML d'OSEye.

Répertoire : ${ROOT}/rules/builtin/

LIS TOUS les fichiers YAML :
- credential_access.yaml
- defense_evasion.yaml
- discovery.yaml
- impact_c2.yaml
- lateral_movement.yaml
- persistence.yaml
- privilege_escalation.yaml

Pour chaque règle, vérifie :
1. Les conditions référencent-elles des champs réellement émis par les adapters (category, type, event_type, executable, resource, dst_port, dst_ip, uid, pid, hostname) ?
2. Les timeframe/threshold sont-ils raisonnables (spam / rate de détection) ?
3. Les exclusions (not()) sont-elles correctes et suffisantes ?
4. Y a-t-il des règles avec une logique inversée ?
5. Les tags MITRE ATT&CK correspondent-ils à la technique décrite ?
6. Les sévérités sont-elles appropriées ?
7. Y a-t-il des règles jamais déclenchables (conditions contradictoires) ?

Retourne un JSON avec les findings. IDs : R-01, R-02...
`, { label: 'audit-rules', phase: 'Audit Règles', schema: FINDING_SCHEMA }),

])

// ─── Consolidation ────────────────────────────────────────────────────────────
const allRaw = [
  ...(goAudit?.findings ?? []),
  ...(goNewAudit?.findings ?? []),
  ...(pyCore?.findings ?? []),
  ...(pyApi?.findings ?? []),
  ...(pyWorkers?.findings ?? []),
  ...(pyDecision?.findings ?? []),
  ...(pyForensic?.findings ?? []),
  ...(pyMlPlugin?.findings ?? []),
  ...(pyPhase4?.findings ?? []),
  ...(rulesAudit?.findings ?? []),
].filter(Boolean)

const critHigh = allRaw.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
const medLow = allRaw.filter(f => f.severity === 'MEDIUM' || f.severity === 'LOW')

log(`Total brut : ${allRaw.length} findings (${critHigh.length} CRITICAL/HIGH, ${medLow.length} MEDIUM/LOW)`)

// ─── Phase Vérification adversariale ─────────────────────────────────────────
phase('Vérification')

const verified = await pipeline(
  critHigh,
  (f, _, i) => agent(`
Vérifie adversarialement ce finding de sécurité/qualité. Ton rôle est de le RÉFUTER si possible.
Lis le fichier concerné pour vérifier si le finding est réel et non déjà corrigé.

Finding #${i + 1}:
ID: ${f.id}
Sévérité: ${f.severity}
Fichier: ${f.file}${f.line ? ':' + f.line : ''}
Titre: ${f.title}
Description: ${f.description}

INSTRUCTIONS :
1. Lis le fichier ${f.file} (chemin absolu : ${ROOT}/${f.file})
2. Va à la ligne ${f.line || 'mentionnée'} et vérifie si le problème existe réellement
3. Cherche si une mitigation existe déjà dans le code
4. confirmed=true uniquement si le finding est réel et non mitigé

Retourne {"confirmed": bool, "rationale": "..."}
`, { label: `verify-${f.id}`, phase: 'Vérification', schema: VERDICT_SCHEMA })
    .then(v => ({ ...f, confirmed: v?.confirmed ?? false, rationale: v?.rationale ?? '' }))
)

const confirmed = verified.filter(Boolean).filter(f => f.confirmed)
log(`Findings confirmés CRITICAL/HIGH : ${confirmed.length}/${critHigh.length}`)

// ─── Phase Synthèse ───────────────────────────────────────────────────────────
phase('Synthèse')

const synthesis = await agent(`
Tu es un auditeur senior OSEye. Synthétise les résultats de cet audit complet.

Findings CRITICAL/HIGH confirmés (${confirmed.length}) :
${JSON.stringify(confirmed, null, 2)}

Findings MEDIUM/LOW (${medLow.length}) — non vérifiés individuellement :
${JSON.stringify(medLow.map(f => ({ id: f.id, severity: f.severity, file: f.file, title: f.title })), null, 2)}

Produis :
1. Tableau récapitulatif par sévérité et module (Go Core / Go Nouveaux / Python Core / Python API / Python Workers / Decision / Forensic / ML-Plugin / ThreatIntel / Règles)
2. Top 5 des findings les plus critiques à corriger en priorité (avec justification)
3. Patterns récurrents identifiés (ex: "4 findings de race condition asyncio dans les workers")
4. Estimation du risque global : faible / moyen / élevé / critique
5. Modules les plus sains vs les plus problématiques
6. Recommandations d'actions immédiates (cette semaine)

Sois concis et factuel. Évite les répétitions.
`, { label: 'synthesis', phase: 'Synthèse' })

return {
  summary: {
    total_raw: allRaw.length,
    critical_high_raw: critHigh.length,
    critical_high_confirmed: confirmed.length,
    medium_low: medLow.length,
    modules_audited: 10,
  },
  confirmed_critical_high: confirmed,
  medium_low_findings: medLow,
  synthesis,
}
