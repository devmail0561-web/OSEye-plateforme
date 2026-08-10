
export const meta = {
  name: 'oseye-audit-fixes',
  description: 'Corriger tous les findings audit OSEye Phase 3 (Go + Python + Règles)',
  phases: [
    { title: 'Fixes Go', detail: 'Panics eBPF, races, double-close, retry infini' },
    { title: 'Fixes Python', detail: 'RCE sandbox, auth, main.py, adapters, storage, workers' },
    { title: 'Fixes Règles', detail: 'Règles mortes, faux positifs, intégration mapper' },
    { title: 'Synthèse', detail: 'Tests, lint, commit' },
  ],
}

phase('Fixes Go')

const goFixes = await agent(`
Tu es un ingénieur Go senior. Corrige les findings d'audit dans l'agent Go OSEye situé dans /home/virus-one/Documents/OSEye_project/agent/.
Branche courante : fix/audit-phase3

LIS d'abord chaque fichier avant de le modifier. Utilise les outils Read, Edit, Write, Bash.

CORRECTIONS A FAIRE :

1. agent/internal/platform/linux/ebpf/loader.go
   - parseConnect : le guard if len(raw) < 44 est insuffisant (struct 52 bytes). Remplace par if len(raw) < 52.
   - parseOpenat : le guard if len(raw) < 284 est insuffisant (struct 292 bytes). Remplace par if len(raw) < 292.
   - ReadEvents : utilise sync.Once pour fermer le channel out. Ajoute var once sync.Once et closeOut := func() { once.Do(func() { close(out) }) }. Appelle closeOut() dans chaque goroutine (defer closeOut() apres la boucle for).

2. agent/internal/platform/linux/ebpf/collector.go
   - Race condition sur c.loader : ajoute un champ mu sync.Mutex dans EBPFCollector. Protege les acces a c.loader dans Start() et Stop() avec c.mu.Lock()/c.mu.Unlock().

3. agent/internal/platform/linux/fanotify/collector.go
   - Double-close fd : ajoute un champ closeOnce sync.Once dans la struct. Partout ou unix.Close(c.fd) est appele, utilise c.closeOnce.Do(func() { unix.Close(c.fd) }).

4. agent/internal/platform/linux/inotify/collector.go
   - Meme correction double-close que fanotify.

5. agent/internal/transport/grpc_client.go
   - Dans SendBatch, la boucle for est infinie sans cap de retries. Ajoute une constante maxRetries = 15. Modifie la boucle pour verifier : if attempt > maxRetries { return fmt.Errorf("max retries exceeded: %d attempts", maxRetries) }

6. agent/internal/policy/handler.go
   - La directive collectors_enabled est un no-op silencieux. Remplace _ = enabledSet par slog.Warn("policy collectors_enabled not implemented", "requested", enabledSet).

7. agent/internal/config/config.go
   - Ajoute une methode Validate() error qui verifie BatchSize > 0, BatchTimeout > 0, MaxCPUPct >= 0, GRPCAddr non vide. Retourne une erreur descriptive.

8. agent/internal/mapper/mapper.go - CORRECTION INTEGRATION CRITIQUE
   - La fonction mapCategory prend source string. Pour "ebpf", elle retourne toujours "process" meme pour les connexions reseau. Modifie Map() pour detecter le type eBPF : lit event_type depuis le payload JSON apres unmarshal et retourne "network" si event_type == "connect", sinon "process".
   - Dans mapFields, ajoute un case "ebpf" separe : ProcessName = firstStrField(payload, "comm", "name"), Executable = firstStrField(payload, "filename", "exe"), Type = strField(payload, "event_type"). Pour event_type == "connect" : DstIp et DstPort. Pour event_type == "openat" ou "open" : Resource = strField(payload, "filename").
   - Ajoute la helper : func firstStrField(m map[string]interface{}, keys ...string) string { for _, k := range keys { if v, ok := m[k].(string); ok && v != "" { return v } }; return "" }

Apres les corrections, lance :
  cd /home/virus-one/Documents/OSEye_project/agent && go build ./... 2>&1 | tail -30
  cd /home/virus-one/Documents/OSEye_project/agent && go vet ./... 2>&1 | tail -20

Rapport final : liste des fichiers modifies et resultat de la compilation.
`, { label: 'fix-go', phase: 'Fixes Go' })

phase('Fixes Python')

const pythonFixes = await agent(`
Tu es un ingenieur Python senior specialise en securite. Corrige les findings d'audit dans /home/virus-one/Documents/OSEye_project/server/.
Branche courante : fix/audit-phase3

LIS d'abord chaque fichier avant de le modifier. Utilise les outils Read, Edit, Write, Bash.

CORRECTIONS A FAIRE :

1. oseye/rule_engine/evaluator.py - CRITICAL RCE
   - Supprime le module re du namespace dans _build_namespace(). Le module re complet permet l'acces a __globals__ et donc RCE.
   - A la place, ajoute une fonction wrapper non-introspectable DANS _build_namespace :
     def _safe_re_match(pattern, value):
         if not isinstance(value, str): return False
         try: return bool(re.match(pattern, value))
         except: return False
   - Dans le dict retourne, remplace "re": re par "re_match": _safe_re_match
   - Le module re reste importe en haut du fichier pour usage interne seulement.

2. oseye/api/routers/auth.py - CRITICAL auth stub
   - Lis le fichier. Si c'est un stub qui accepte tout, remplace par une vraie validation.
   - Utilise passlib.context.CryptContext(schemes=["bcrypt"]) pour hasher et verifier.
   - Definis des utilisateurs par defaut dans un dict (configurable via env vars via Settings).
   - Admin : OSEYE_ADMIN_PASSWORD (defaut "admin123" en dev, documentee).
   - Analyst : OSEYE_ANALYST_PASSWORD (defaut "analyst123" en dev).
   - Ajoute passlib[bcrypt]>=1.7.4 dans server/pyproject.toml dependencies.
   - Verifie que les tests existants passent toujours (les tests utilisent username=analyst1 / admin1 avec password=password).

3. oseye/main.py - CRITICAL lifespan incomplet
   - Dans le lifespan, ajoute l'initialisation de jwt_handler et event_repo sur app.state :
     from oseye.api.auth.jwt import JWTHandler
     app.state.jwt_handler = JWTHandler(private_key_path=settings.jwt_private_key_path, public_key_path=settings.jwt_public_key_path, expire_minutes=settings.jwt_access_token_expire_minutes)
     app.state.event_repo = repo
   - Corrige l'objet app module-level (ligne ~124) qui n'a pas de lifespan :
     app = create_app(get_settings(), lifespan=_build_lifespan(get_settings()))

4. oseye/rule_engine/evaluator.py - HIGH memory leak + race
   - Ajoute _temporal_windows_lock = threading.Lock() au niveau module.
   - Dans record_event_for_temporal et _count_events_in_window, protege les acces a _temporal_windows avec ce lock.
   - Ajoute une fonction _purge_old_windows() qui supprime les cles dont toutes les entrees ont ts < time.time() - 3600 (1h).
   - Dans record_event_for_temporal, appelle _purge_old_windows() tous les 500 appels (compteur global _record_count).

5. oseye/api/ws/alerts.py - HIGH WebSocket sans auth
   - Ajoute un parametre token: str = Query(default="") a la fonction ws_alerts.
   - Avant alerts_ws_manager.connect(ws), valide le token :
     if not token: await ws.close(code=4001); return
     try:
         handler = ws.app.state.jwt_handler
         handler.verify_token(token)
     except Exception:
         await ws.close(code=4001); return
   - Met a jour le test si besoin.

6. oseye/api/auth/jwt.py - HIGH info leakage
   - Trouve la ligne qui retourne detail=f"Invalid token: {exc}" ou similaire.
   - Remplace par detail="Authentication failed".
   - Ajoute un log : _logger.warning("jwt_invalid", error=str(exc))

7. oseye/workers/storage_writer.py - MEDIUM double parse
   - Remplace le pattern json.loads + model_validate_json par :
     try:
         event = UniversalEvent.model_validate_json(message)
     except Exception:
         try:
             data = json.loads(message)
             if not data.get("event_id"):
                 data["event_id"] = str(uuid.uuid4())
             event = UniversalEvent.model_validate(data)
         except Exception as exc:
             _logger.warning("storage_writer_parse_error", error=str(exc))
             continue

8. oseye/bus/redis_bus.py - MEDIUM erreurs silencieuses
   - Lis le fichier. Dans la methode qui subscribie/consomme les messages Redis (probablement _read_stream ou subscribe), remplace le bare except par un except avec log + backoff exponentiel.

9. Adapters normalizer - MEDIUM safe_int
   - oseye/normalizer/adapters/linux/procfs.py : remplace int(data.get("pid", 0)) etc. par safe_int(data.get("pid")) (et ppid, uid, gid)
   - oseye/normalizer/adapters/linux/auditd.py : idem
   - oseye/normalizer/adapters/linux/ebpf.py : idem + corriger executable = data.get("filename", "") au lieu de "exe", resource = data.get("filename", "") pour les events openat/open, supprimer la lecture de src_ip/src_port.

10. oseye/storage/repositories/alerts.py - MEDIUM ORDER BY
    - Dans list(), ajoute .order_by(AlertRow.created_at.desc()) avant .offset().limit()

11. oseye/api/routers/alerts.py - MEDIUM AlertPatch contraintes
    - Importe Annotated from typing et StringConstraints from pydantic
    - Remplace assigned_to: str | None = None par assigned_to: Annotated[str, StringConstraints(max_length=200)] | None = None

12. oseye/rule_engine/engine.py - LOW hot-reload *.yml
    - Dans _current_mtime(), ajoute le scan des fichiers *.yml en plus de *.yaml.

13. oseye/workers/runner.py - LOW hostname hardcode
    - Remplace hostname="localhost" par socket.gethostname() (importe socket si pas deja importe).

14. oseye/core/observability.py - LOW ExceptionPrettyPrinter + OTEL insecure
    - Remplace ExceptionPrettyPrinter(file=sys.stderr) par structlog.processors.format_exc_info
    - Pour OTEL : insecure = os.getenv("OTEL_INSECURE", "false").lower() == "true" puis passe insecure=insecure a OTLPSpanExporter.

Apres toutes les corrections, lance :
  cd /home/virus-one/Documents/OSEye_project/server
  /home/virus-one/Documents/OSEye_project/.venv/bin/ruff check oseye/ 2>&1 | tail -30
  /home/virus-one/Documents/OSEye_project/.venv/bin/mypy oseye/rule_engine/ oseye/workers/ oseye/api/ oseye/main.py --ignore-missing-imports 2>&1 | tail -20
  /home/virus-one/Documents/OSEye_project/.venv/bin/pytest tests/ -q --tb=short 2>&1 | tail -20

Si des erreurs apparaissent, CORRIGE-LES. Rapport final : fichiers modifies, resultats.
`, { label: 'fix-python', phase: 'Fixes Python' })

phase('Fixes Règles')

const rulesFixes = await agent(`
Tu es un ingenieur securite. Corrige les regles YAML et l'adapter Python eBPF dans OSEye.
Projet : /home/virus-one/Documents/OSEye_project
Branche courante : fix/audit-phase3

LIS d'abord les fichiers avant de les modifier.

CORRECTIONS :

1. rules/builtin/credential_access.yaml
   - rule_ssh_bruteforce : la condition utilise event.result == "denied" qui est toujours false. Remplace par :
     event.category == "network"
     and event.protocol == "tcp"
     and event.dst_port == 22
     and event.type == "new"
     Garde timeframe: 60, threshold: 10, actions: [ALERT]
   - rule_ssh_private_key_access : ajoute a la condition : and event.process_name != "ssh" and event.process_name != "ssh-agent" and event.process_name != "git"
   - rule_memory_dump_mimipenguin : remplace mitre: [T1003.001] par mitre: [T1003.007]

2. rules/builtin/lateral_movement.yaml
   - rule_port_scan : remplace event.result == "refused" par :
     event.category == "network"
     and event.protocol == "tcp"
     and event.type == "new"
     Garde timeframe: 30, threshold: 20, actions: [ALERT]
   - rule_ssh_lateral : remplace event.dst_ip contains "172." par une liste precise :
     (event.dst_ip contains "172.16." or event.dst_ip contains "172.17." or event.dst_ip contains "172.18." or event.dst_ip contains "172.19." or event.dst_ip contains "172.20." or event.dst_ip contains "172.21." or event.dst_ip contains "172.22." or event.dst_ip contains "172.23." or event.dst_ip contains "172.24." or event.dst_ip contains "172.25." or event.dst_ip contains "172.26." or event.dst_ip contains "172.27." or event.dst_ip contains "172.28." or event.dst_ip contains "172.29." or event.dst_ip contains "172.30." or event.dst_ip contains "172.31.")
   - rule_rsync_exfil : ajoute timeframe: 60 et threshold: 3 pour reduire les faux positifs.

3. rules/builtin/defense_evasion.yaml
   - rule_history_clear : la condition actuelle est impossible (category==process ET type==delete). Remplace par :
     (event.category == "file" and event.type == "delete" and event.resource contains ".bash_history")
     or (event.category == "process" and (event.cmdline contains "history -c" or event.cmdline contains "HISTFILE=/dev/null" or event.cmdline contains "unset HISTFILE" or event.cmdline contains "HISTSIZE=0"))
     Supprime la condition and event.resource contains ".bash_history" du bloc process.

4. rules/builtin/privilege_escalation.yaml
   - rule_polkit_abuse : remplace mitre: [T1548] par mitre: [T1548.003]

5. rules/builtin/discovery.yaml
   - rule_recon_enumeration : passe timeframe: 30 (etait 10), threshold: 5 (etait 3)
   - rule_process_discovery : passe timeframe: 30 (etait 5), threshold: 10 (etait 5)

6. rules/builtin/impact_c2.yaml
   - rule_outbound_c2_beaconing : dans la condition not (...), remplace event.dst_ip contains "172." par la liste complete des blocs /12 RFC 1918 comme au point 2.

7. server/oseye/normalizer/adapters/linux/ebpf.py
   - Lis le fichier.
   - Corrige executable : utilise data.get("filename") or data.get("exe", "") en priorite.
   - Corrige resource : pour les events de type openat/open/exec (selon event_type dans data), assigne resource = str(data.get("filename", ""))
   - Supprime ou commente la lecture de src_ip et src_port (l'eBPF collector Go n'emet que dst_ip/dst_port).
   - Assure-toi que safe_int est utilise pour pid, ppid, uid, gid.

8. Verifie que tous les IDs de regles sont uniques :
   grep -h "^- id:" /home/virus-one/Documents/OSEye_project/rules/builtin/*.yaml | sort | uniq -d

Rapport : liste des fichiers modifies avec les changements appliques.
`, { label: 'fix-rules', phase: 'Fixes Règles' })

phase('Synthèse')

const synthesis = await agent(`
Tu es un ingenieur senior. Verifie et finalise les corrections d'audit dans OSEye.
Projet : /home/virus-one/Documents/OSEye_project

1. Lance les tests Python :
   cd /home/virus-one/Documents/OSEye_project/server && /home/virus-one/Documents/OSEye_project/.venv/bin/pytest tests/ -q --tb=short 2>&1 | tail -20

2. Lance ruff :
   /home/virus-one/Documents/OSEye_project/.venv/bin/ruff check oseye/ 2>&1 | tail -20

3. Lance mypy sur les modules cles :
   /home/virus-one/Documents/OSEye_project/.venv/bin/mypy oseye/rule_engine/ oseye/workers/ oseye/api/ oseye/main.py --ignore-missing-imports 2>&1 | tail -15

4. Lance go build + go vet :
   cd /home/virus-one/Documents/OSEye_project/agent && go build ./... 2>&1 | tail -20
   go vet ./... 2>&1 | tail -20

5. Verifie que le sandbox RCE est corrige :
   grep -n '"re"' /home/virus-one/Documents/OSEye_project/server/oseye/rule_engine/evaluator.py

6. Verifie les regles mortes :
   grep -A5 "rule_ssh_bruteforce" /home/virus-one/Documents/OSEye_project/rules/builtin/credential_access.yaml | head -8
   grep -A5 "rule_port_scan" /home/virus-one/Documents/OSEye_project/rules/builtin/lateral_movement.yaml | head -8

7. Si des erreurs ruff ou mypy sont presentes, CORRIGE-LES directement (Edit les fichiers).
   Si des tests echouent, CORRIGE les echecs (en lisant les erreurs et en adaptant les tests ou le code).

8. Une fois tout vert (tests pass, ruff OK, mypy OK, go build OK), commit :
   cd /home/virus-one/Documents/OSEye_project
   git add -A
   git commit -m "fix(audit-phase3): 32 corrections audit — RCE sandbox, auth, eBPF, regles mortes, races Go

CRITICAL: sandbox RCE — re retire du namespace, remplace par re_match() wrapper
CRITICAL: auth stub remplace par validation bcrypt via passlib
CRITICAL: main.py lifespan — jwt_handler + event_repo injectes
CRITICAL: eBPF mapper Go comm/filename/event_type + adapter Python corriges
CRITICAL: regles mortes rule_ssh_bruteforce + rule_port_scan reecrites
HIGH: _temporal_windows memory leak — purge TTL + verrou threading
HIGH: WebSocket /ws/alerts — auth JWT token query param
HIGH: jwt.py — detail exception opacifie
HIGH: Go eBPF panics parseConnect (44→52) + parseOpenat (284→292)
HIGH: Go race c.loader + double-close fd fanotify/inotify
HIGH: Go retry infini SendBatch → maxRetries=15
HIGH: rule_history_clear condition impossible — reecrite
MEDIUM: double parse JSON storage_writer corrige
MEDIUM: redis bus backoff exponentiel + logs
MEDIUM: safe_int dans adapters procfs/auditd/ebpf
MEDIUM: ORDER BY dans alerts list, AlertPatch contraintes
MEDIUM: faux positifs rules reduits (ssh_key, port_scan, rsync, discovery)
LOW: hot-reload *.yml, hostname runner, OTEL insecure configurable, ExceptionPrettyPrinter

Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>"

Rapport : resultats de chaque check et confirmation du commit.
`, { label: 'synthesis', phase: 'Synthèse' })

return { goFixes, pythonFixes, rulesFixes, synthesis }
