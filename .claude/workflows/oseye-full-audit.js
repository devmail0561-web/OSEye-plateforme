export const meta = {
  name: 'oseye-full-audit',
  description: 'Audit complet tous modules OSEye — Go agent + Python server + Règles YAML',
  phases: [
    { title: 'Audit Go', detail: 'Agent Go — buffer, transport, collectors, mapper, config, chain, watchdog' },
    { title: 'Audit Python Core', detail: 'ingest, normalizer, bus, storage, core, config, main' },
    { title: 'Audit Python API', detail: 'api routers, auth, rbac, ws, app' },
    { title: 'Audit Python Workers', detail: 'rule_engine, workers, rule_worker, ti_worker, correlation_worker' },
    { title: 'Audit Phase 4', detail: 'threat_intel, correlation engine, incidents repo' },
    { title: 'Audit Règles', detail: 'rules/builtin/*.yaml — correctness, dead rules, FP, MITRE' },
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

// ─── Phase 1 : Audit Go ──────────────────────────────────────────────────────
phase('Audit Go')

const goAudit = await agent(`
Tu es un auditeur de sécurité et de qualité Go expert. Audite tous les fichiers Go de l'agent OSEye.

Répertoire : /home/virus-one/Documents/OSEye_project/agent/

LIS CHAQUE fichier source Go (pas les tests, pas les fichiers gen/) :
- cmd/oseye-agent/main.go
- internal/buffer/buffer.go + buffer_cgo.go
- internal/chain/chain.go
- internal/collector/interface.go + manager.go
- internal/commands/client.go
- internal/config/config.go
- internal/mapper/mapper.go
- internal/platform/linux/auditd/collector.go
- internal/platform/linux/driver.go
- internal/platform/linux/ebpf/collector.go + loader.go
- internal/platform/linux/fanotify/collector.go
- internal/platform/linux/inotify/collector.go
- internal/platform/linux/journald/collector.go
- internal/platform/linux/netlink/collector.go
- internal/platform/linux/procfs/collector.go
- internal/platform/linux/syslog/collector.go
- internal/platform/linux/udev/collector.go
- internal/platform/registry.go
- internal/policy/client.go + handler.go
- internal/signer/signer.go
- internal/transport/batcher.go + grpc_client.go
- internal/watchdog/watchdog.go

Cherche :
- Panics potentiels (index out of range, nil deref, send on closed channel)
- Race conditions (accès concurrent sans mutex)
- Fuites de goroutines ou de ressources (fd, connection)
- Erreurs ignorées silencieusement
- Logique incorrecte ou edge cases non gérés
- Problèmes de sécurité (injection, overflow, validation manquante)
- Dettes techniques sérieuses

Pour chaque fichier lu, commente ce que tu as trouvé ou "rien à signaler".
Retourne un JSON avec les findings.
`, { label: 'audit-go', phase: 'Audit Go', schema: FINDING_SCHEMA })

// ─── Phase 2 : Audit Python Core ─────────────────────────────────────────────
phase('Audit Python Core')

const pyCore = await agent(`
Tu es un auditeur de sécurité et de qualité Python expert. Audite les modules core du serveur OSEye.

Répertoire : /home/virus-one/Documents/OSEye_project/server/oseye/

LIS CHAQUE fichier :
- config.py
- main.py
- core/schema.py
- core/observability.py
- core/pagination.py
- bus/interface.py + memory_bus.py + redis_bus.py + factory.py
- ingest/grpc_service.py + normalizer_bridge.py + server.py + validator.py
- normalizer/engine.py + secret_masker.py
- normalizer/adapters/linux/_utils.py + procfs.py + auditd.py + ebpf.py + fanotify.py + inotify.py + journald.py + netlink.py + syslog.py + udev.py
- storage/backends/sqlite.py
- storage/migrations/__init__.py
- storage/models.py
- storage/repositories/events.py + alerts.py + decisions.py + cases.py + api_keys.py + rule_versions.py + incidents.py

Cherche :
- Injections SQL, command injection, path traversal
- Erreurs non gérées ou swallowed silencieusement
- Race conditions asyncio (shared mutable state sans lock)
- Fuites de connexions/sessions DB
- Validation insuffisante des entrées
- Problèmes de sécurité (auth bypass, info leak, SSRF)
- Logique incorrecte ou incomplète
- Dettes techniques HIGH/MEDIUM

Retourne un JSON avec les findings.
`, { label: 'audit-py-core', phase: 'Audit Python Core', schema: FINDING_SCHEMA })

// ─── Phase 3 : Audit Python API ──────────────────────────────────────────────
phase('Audit Python API')

const pyApi = await agent(`
Tu es un auditeur de sécurité API REST expert. Audite les modules API du serveur OSEye.

Répertoire : /home/virus-one/Documents/OSEye_project/server/oseye/

LIS CHAQUE fichier :
- api/app.py
- api/auth/jwt.py + rbac.py
- api/routers/auth.py
- api/routers/events.py
- api/routers/alerts.py
- api/routers/rules.py
- api/routers/api_keys.py
- api/routers/incidents.py
- api/routers/ti.py
- api/routers/health.py
- api/ws/alerts.py + manager.py

Cherche en priorité :
- IDOR (accès à des ressources d'autres utilisateurs)
- Privilege escalation (RBAC mal implémenté)
- Missing auth sur des endpoints
- Rate limiting insuffisant ou absent
- Input validation insuffisante (injections, DoS)
- Mass assignment / over-posting
- Information disclosure dans les erreurs
- CORS misconfiguration
- JWT vulnerabilities (alg confusion, weak keys, expiry non vérifié)
- WebSocket security issues

Retourne un JSON avec les findings.
`, { label: 'audit-py-api', phase: 'Audit Python API', schema: FINDING_SCHEMA })

// ─── Phase 4 : Audit Python Workers ──────────────────────────────────────────
phase('Audit Python Workers')

const pyWorkers = await agent(`
Tu es un auditeur de qualité et sécurité expert. Audite les workers et le rule engine d'OSEye.

Répertoire : /home/virus-one/Documents/OSEye_project/server/oseye/

LIS CHAQUE fichier :
- rule_engine/__init__.py + engine.py + evaluator.py + models.py + parser.py
- workers/rule_worker.py
- workers/storage_writer.py
- workers/ti_worker.py
- workers/correlation_worker.py
- workers/runner.py
- correlation/engine.py
- correlation/linkers/same_host.py

Cherche :
- Sandbox escape dans l'évaluateur de règles
- Race conditions dans les workers asyncio
- Memory leaks (accumulation sans purge)
- Message loss (events consommés mais non traités en cas d'erreur)
- Logique de corrélation incorrecte (faux positifs massifs, faux négatifs)
- Problèmes de sécurité dans le rule parser (YAML injection, ReDoS)
- Dettes techniques HIGH/MEDIUM

Retourne un JSON avec les findings.
`, { label: 'audit-py-workers', phase: 'Audit Python Workers', schema: FINDING_SCHEMA })

// ─── Phase 5 : Audit Phase 4 modules ─────────────────────────────────────────
phase('Audit Phase 4')

const pyPhase4 = await agent(`
Tu es un auditeur de sécurité expert. Audite les modules Phase 4 d'OSEye (Threat Intel + Correlation).

Répertoire : /home/virus-one/Documents/OSEye_project/server/oseye/

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

Retourne un JSON avec les findings.
`, { label: 'audit-phase4', phase: 'Audit Phase 4', schema: FINDING_SCHEMA })

// ─── Phase 6 : Audit Règles YAML ─────────────────────────────────────────────
phase('Audit Règles')

const rulesAudit = await agent(`
Tu es un expert en détection SIEM/EDR. Audite toutes les règles YAML d'OSEye.

Répertoire : /home/virus-one/Documents/OSEye_project/rules/builtin/

LIS TOUS les fichiers YAML :
- credential_access.yaml
- defense_evasion.yaml
- discovery.yaml
- execution.yaml (si existe)
- impact_c2.yaml
- lateral_movement.yaml
- persistence.yaml (si existe)
- privilege_escalation.yaml

Pour chaque règle, vérifie :
1. Les conditions référencent-elles des champs réellement émis par les adapters (category, type, event_type, executable, resource, dst_port, dst_ip, uid, pid, hostname) ?
2. Les timeframe/threshold sont-ils raisonnables ou vont-ils générer du spam ou rater des détections ?
3. Les exclusions (not()) sont-elles correctes et suffisantes ?
4. Y a-t-il des règles avec une logique inversée (uid != 0 au lieu de uid == 0) ?
5. Les tags MITRE ATT&CK correspondent-ils à la technique décrite ?
6. Les sévérités sont-elles appropriées ?

Retourne un JSON avec les findings.
`, { label: 'audit-rules', phase: 'Audit Règles', schema: FINDING_SCHEMA })

// ─── Phase 7 : Vérification adversariale ──────────────────────────────────────
phase('Vérification')

// Consolider tous les findings CRITICAL et HIGH
const allFindings = [
  ...(goAudit?.findings ?? []),
  ...(pyCore?.findings ?? []),
  ...(pyApi?.findings ?? []),
  ...(pyWorkers?.findings ?? []),
  ...(pyPhase4?.findings ?? []),
  ...(rulesAudit?.findings ?? []),
].filter(Boolean).filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')

log(`${allFindings.length} findings CRITICAL/HIGH à vérifier`)

const verified = await pipeline(
  allFindings,
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
1. Lis le fichier ${f.file} (chemin absolu : /home/virus-one/Documents/OSEye_project/${f.file})
2. Va à la ligne ${f.line || 'mentionnée'} et vérifie si le problème existe
3. Cherche si une mitigation existe déjà
4. Conclus : confirmed=true si le finding est réel et non mitigé

Retourne {"confirmed": bool, "rationale": "..."}
`, { label: `verify-${f.id}`, phase: 'Vérification', schema: VERDICT_SCHEMA })
    .then(v => ({ ...f, confirmed: v?.confirmed ?? false, rationale: v?.rationale ?? '' }))
)

const confirmed = verified.filter(Boolean).filter(f => f.confirmed)
const allMediumLow = [
  ...(goAudit?.findings ?? []),
  ...(pyCore?.findings ?? []),
  ...(pyApi?.findings ?? []),
  ...(pyWorkers?.findings ?? []),
  ...(pyPhase4?.findings ?? []),
  ...(rulesAudit?.findings ?? []),
].filter(Boolean).filter(f => f.severity === 'MEDIUM' || f.severity === 'LOW')

log(`Findings confirmés CRITICAL/HIGH : ${confirmed.length}/${allFindings.length}`)

// ─── Phase 8 : Synthèse ───────────────────────────────────────────────────────
phase('Synthèse')

const synthesis = await agent(`
Tu es un auditeur senior. Synthétise les résultats d'audit OSEye.

Findings CRITICAL/HIGH confirmés (${confirmed.length}) :
${JSON.stringify(confirmed, null, 2)}

Findings MEDIUM/LOW (${allMediumLow.length}) — non vérifiés individuellement :
${JSON.stringify(allMediumLow.map(f => ({ id: f.id, severity: f.severity, file: f.file, title: f.title })), null, 2)}

Produis :
1. Un tableau récapitulatif par sévérité et module
2. Les 5 findings les plus critiques à corriger en priorité
3. Les patterns récurrents (ex: "5 findings de type race condition dans les workers")
4. Une estimation du risque global (faible/moyen/élevé/critique)
5. Les modules les plus sains vs les plus problématiques

Sois concis et factuel.
`, { label: 'synthesis', phase: 'Synthèse' })

return {
  summary: {
    total_raw: allFindings.length + allMediumLow.length,
    critical_high_raw: allFindings.length,
    critical_high_confirmed: confirmed.length,
    medium_low: allMediumLow.length,
  },
  confirmed_critical_high: confirmed,
  medium_low_findings: allMediumLow,
  synthesis,
}
