# Skill : OSEye — Créer une règle de détection

## Quand utiliser ce skill
Invoquer avec `/oseye-rule` quand l'utilisateur demande d'écrire une nouvelle règle de détection YAML pour le Rule Engine d'OSEye.

---

## Ce que tu dois faire

Tu crées une règle de détection conforme au format OSEye défini dans `docs/ARCHITECTURE.md` §3.4 et §4.8.

### Étape 1 — Recueillir les informations

Si non fournies par l'utilisateur :
- **Comportement à détecter** : décris l'attaque ou l'anomalie
- **OS cible** : `linux` | `windows` | `darwin` | `all`
- **Sévérité** : `info` | `low` | `medium` | `high` | `critical`
- **Technique MITRE ATT&CK** si connue (ex: T1003.008)

### Étape 2 — Choisir le fichier de destination

```
rules/builtin/<categorie>.yaml    # règles livrées avec OSEye
rules/custom/<nom>.yaml           # règles spécifiques à l'opérateur
```

Catégories disponibles : `credential_access`, `privilege_escalation`, `persistence`,
`defense_evasion`, `lateral_movement`, `discovery`, `exfiltration`, `c2`, `ransomware`,
`windows`, `darwin`, `impact`.

### Étape 3 — Écrire la règle

**Format complet :**

```yaml
id: "rule_<snake_case_unique>"          # doit être unique dans tout le ruleset
name: "<Description courte lisible>"
enabled: true
severity: <info|low|medium|high|critical>
tags:
  - <categorie_mitre>                   # ex: credential_access
  - <sous_categorie>                    # ex: os_credential_dumping
mitre:
  - <T1234.001>                         # technique ATT&CK principale
  - <T5678>                             # optionnel : technique secondaire
platforms:                              # vide = toutes plateformes
  - linux
  - windows
  - darwin
condition: |
  <expression_python_safe_eval>
timeframe: null                         # null OU secondes (entier) pour règles temporelles
threshold: null                         # null OU entier — utilisé avec timeframe
actions:
  - ALERT
  - INVESTIGATE                         # optionnel selon sévérité
explanation: >
  <Explication lisible par un analyste humain.
  Pourquoi c'est suspect, quel est le risque.>
```

**Opérateurs disponibles dans `condition` :**

```
Comparaison    : == != > < >= <=
Appartenance   : in  not in
Chaînes        : .startswith()  .endswith()  contains  re.match(r"...", event.field)
Booléens       : and  or  not
OS             : event.platform == "linux"
Temporel       : count_events("filter_expr", seconds) > threshold
```

**Champs disponibles de `event` :**

```
event.platform, event.category, event.type, event.severity
event.uid, event.gid, event.pid, event.ppid
event.process_name, event.executable, event.cmdline, event.cwd
event.resource, event.result
event.src_ip, event.dst_ip, event.src_port, event.dst_port, event.protocol
event.bytes_sent, event.bytes_recv
event.file_hash_before, event.file_hash_after
event.hostname, event.agent_id
event.ti_tags, event.mitre_techniques, event.rule_match_ids
```

### Étape 4 — Exemples selon le type de règle

**Règle simple (événement unique) :**
```yaml
id: "rule_shadow_read"
name: "Lecture de /etc/shadow hors root"
severity: critical
tags: [credential_access]
mitre: [T1003.008]
platforms: [linux]
condition: |
  event.category == "file"
  and event.type == "read"
  and event.resource == "/etc/shadow"
  and event.uid != 0
timeframe: null
actions: [ALERT, INVESTIGATE]
explanation: >
  Tentative de lecture du fichier /etc/shadow par un processus non-root.
  Indique un vol de credentials probable (hash cracking).
```

**Règle temporelle (pattern répété) :**
```yaml
id: "rule_ssh_bruteforce"
name: "Tentative brute-force SSH"
severity: high
tags: [credential_access, brute_force]
mitre: [T1110.001]
platforms: [linux]
condition: |
  event.platform == "linux"
  and event.category == "network"
  and event.dst_port == 22
  and count_events("event.dst_ip == self.dst_ip and event.result == 'denied'", 60) > 10
timeframe: 60
threshold: 10
actions: [ALERT]
explanation: >
  Plus de 10 connexions SSH refusées vers la même IP en 60 secondes.
  Pattern typique d'une attaque par force brute.
```

**Règle cross-OS :**
```yaml
id: "rule_credential_dump_memory"
name: "Tentative de dump mémoire LSASS / mimipenguin"
severity: critical
tags: [credential_access, os_credential_dumping]
mitre: [T1003.001]
platforms: [linux, windows]
condition: |
  event.category == "process"
  and (
    (event.platform == "linux"   and event.executable contains "mimipenguin")
    or (event.platform == "windows" and event.process_name == "lsass.exe"
        and event.type == "memory_read" and event.uid != 4)
  )
timeframe: null
actions: [ALERT, INVESTIGATE]
explanation: >
  Outil de dump de credentials détecté en mémoire. Sur Linux : mimipenguin.
  Sur Windows : accès mémoire LSASS depuis un processus non-système.
```

### Étape 5 — Valider la règle

Tester via l'API avant de commiter :
```bash
curl -X POST http://localhost:8000/api/v1/rules/validate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"condition_yaml": "<condition>", "timeframe": null}'
```

### Étape 6 — Checklist avant livraison

- [ ] `id` unique dans tous les fichiers `rules/`
- [ ] `explanation` compréhensible par un analyste sans contexte technique
- [ ] `platforms` renseigné si la règle est OS-spécifique
- [ ] Testé sur un event synthétique (positif ET négatif)
- [ ] Pas de faux positifs évidents sur des workloads propres courants
- [ ] Sévérité `critical` réservée aux comportements confirmés malveillants

---

## Contraintes à respecter

- Ne jamais utiliser `event.uid == 0` seul comme condition principale — trop générique
- Les règles temporelles (`count_events`) coûtent cher — `timeframe` > 300s requiert une justification
- `actions: [ISOLATE]` n'est pas une action valide pour une règle — c'est le Decision Engine qui décide l'isolation
- Référence : `docs/ARCHITECTURE.md` §3.4, §4.8

---

## État Phase 2

Le Rule Engine est planifié en **Phase 3** du projet (tâches P3.01 à P3.07).

- Statut actuel (2026-08-06) : non implémenté
- L'évaluateur de conditions (`condition_yaml`) et le moteur temporel (`count_events`) sont définis dans `docs/ARCHITECTURE.md` §3.4 mais non encore codés
- Les règles builtin YAML sont dans `rules/builtin/` — elles seront chargées au démarrage du Rule Engine en P3.01
- Les règles custom opérateur vont dans `rules/custom/`
- L'endpoint de validation (`/api/v1/rules/validate`) sera disponible après P3.04
