# Architecture : Agent Autonome

## Règle Fondamentale

**OSEye ne doit JAMAIS dégrader les performances de l'hôte.**

| Ressource | Contrainte | Mécanisme |
|-----------|-----------|-----------|
| CPU | Ne jamais excéder le budget (adaptatif selon les specs) | Watchdog + budget d'évaluation des règles |
| RAM | Plafond fixe proportionnel aux capacités de l'hôte | Store borné, fenêtre d'événements limitée |
| Stockage | Empreinte minimale (buffer + règles) | Compaction SQLite, rotation des règles |
| Réseau | Batch + compression, jamais saturer | Mesure de débit + adaptation dynamique |

Ces budgets ne sont **pas fixes** — ils sont calculés à partir des caractéristiques réelles de l'hôte. Un serveur 64 cœurs a plus de marge qu'un Raspberry Pi. C'est pourquoi le profil hôte existe.

---

## Pourquoi l'Autonomie Locale ?

**Problème :** Si l'hôte est sous attaque et que le serveur est injoignable (réseau coupé, DDoS, serveur down), l'agent actuel est impuissant — il ne peut que bufferer et attendre.

**Solution :** L'agent évalue TOUJOURS les règles localement et peut répondre immédiatement (agir puis prévenir). Le serveur supervise, confirme ou annule, et affine les règles en continu.

```
MODÈLE PRÉCÉDENT (passif) :
  Agent collecte → envoie au serveur → attend → exécute
  Serveur offline = aucune défense

NOUVEAU MODÈLE (autonome + supervisé) :
  Serveur apprend le comportement hôte → pousse des règles adaptatives
  Agent évalue TOUJOURS localement → agit immédiatement → rapporte
  Serveur online = confirme/annule en temps réel, affine les règles
  Serveur offline = l'agent continue de se défendre identiquement
```

L'agent agit de la même façon que le serveur soit présent ou non. La seule différence : quand le serveur est là, il peut annuler une action en temps réel (rollback rapide) et fournir des mises à jour de règles.

---

## Cycle d'Apprentissage

### Phase 1 : Première Connexion

L'agent envoie un inventaire complet de l'hôte au serveur :

```json
{
  "hostname": "prod-web-03",
  "os": "linux",
  "arch": "amd64",
  "num_cpu": 8,
  "total_mem_mb": 32768,
  "kernel_version": "6.1.0-22-amd64",
  "distro": "Debian GNU/Linux 12 (bookworm)",
  "is_container": false,
  "is_vm": true,
  "network_exposure": "dmz",
  "listening_ports": [22, 80, 443, 5432],
  "active_services": ["nginx", "postgresql", "sshd", "cron"],
  "installed_packages_count": 847,
  "systemd_units_active": ["nginx.service", "postgresql.service", "sshd.service"],
  "users_with_shell": ["root", "deploy", "postgres"],
  "uptime_seconds": 0,
  "available_bandwidth_mbps": 1000
}
```

Le serveur utilise ces données pour :
1. Déduire le **rôle** de la machine (web server, DB, CI, desktop...) à partir des services actifs et ports ouverts
2. Calculer le **budget ressources** de l'agent (proportionnel aux specs)
3. Assigner un **profil par défaut** avec des règles génériques adaptées au rôle

L'agent est immédiatement protégé — pas de période d'attente.

### Phase 2 : Apprentissage Continu

Au fur et à mesure que l'agent stream des événements, le serveur construit une **carte comportementale** :

| Dimension | Ce que le serveur apprend | Seuil de maturité |
|-----------|---------------------------|-------------------|
| Applications | Quels processus s'exécutent, arbres de processus normaux, fréquence | ~48h pour une baseline stable |
| Réseau | Destinations normales, ports, volumes par service, patterns horaires | ~7 jours |
| Fichiers | Quels processus accèdent à quels fichiers critiques, quand | ~48h |
| Utilisateurs | Comptes actifs, horaires de connexion, usage sudo/su | ~7 jours |
| Temporel | Tâches cron, fenêtres de maintenance, pics/creux | ~7 jours |

Le serveur ne génère de règles spécifiques à l'hôte qu'une fois le seuil de maturité atteint pour chaque dimension. Avant ça, seules les règles génériques du profil par défaut sont actives.

**Indicateur de maturité** : le serveur expose un score de confiance par hôte (0-100%). Les règles auto-générées portent ce score — les règles à faible confiance ont des seuils plus élevés (moins de faux positifs).

### Phase 3 : Génération Adaptative de Règles

Les engines du serveur produisent des règles de plus en plus spécifiques :

| Engine | Apprend | Produit | Algorithme |
|--------|---------|---------|-----------|
| **Profile Engine** | Patterns comportementaux de l'hôte | Profil hôte (baseline apps, réseau, utilisateurs, horaires) | Comptage fréquentiel + fenêtres temporelles glissantes |
| **Rule Engine** | Déviations par rapport à la baseline | Règles de détection pondérées adaptées à cet hôte | Seuils statistiques (écart-type) + règles MITRE templates |
| **Decision Engine** | Réponses appropriées par type d'hôte + historique FP | Politique d'autonomie + seuils de réponse | Scoring bayésien sur les retours admin (confirmé/FP) |

#### Comment le Rule Engine génère des règles :

1. Le Profile Engine fournit la baseline (ex: "sur cet hôte, seuls nginx, postgres et cron s'exécutent normalement")
2. Le Rule Engine crée une règle template : "tout process_exec avec binary NOT IN baseline = anomalie, weight 3"
3. La confiance de la baseline détermine le seuil : baseline mature (7j+) → seuil bas = plus sensible
4. Les retours FP augmentent le seuil ou ajoutent des exceptions à la baseline

#### Comment le Decision Engine apprend :

Le Decision Engine maintient un score bayésien par couple (type d'hôte, type d'action) :

```
P(action_correcte | contexte) = historique_confirmations / (confirmations + faux_positifs)
```

- Score > 0.9 → action automatique (always_act)
- Score 0.5–0.9 → action uniquement sur severity critical
- Score < 0.5 → log uniquement, en attente de plus de données

Le score est recalculé à chaque feedback admin.

### Phase 4 : Push vers l'Agent

Les règles et profils mis à jour sont poussés via le stream gRPC `ReceivePolicy`. L'agent les persiste localement (survit au redémarrage + panne serveur).

Chaque push contient :
- Un **numéro de version** (monotone croissant)
- Le **jeu complet de règles** (pas de diff — atomicité garantie)
- Le **profil hôte** mis à jour
- Les **budgets ressources** recalculés

### Phase 5 : Boucle de Feedback

Quand le serveur valide ou invalide une décision de l'agent :
1. L'admin confirme ou marque comme faux positif via le dashboard
2. Le Decision Engine met à jour son score bayésien
3. Le Rule Engine recalcule les poids et seuils des règles concernées
4. Si une app légitime a été bloquée, le Profile Engine l'ajoute à la baseline
5. Les règles mises à jour sont poussées à l'agent

L'agent **n'ajuste jamais ses propres règles** — toute l'intelligence vient du serveur. L'agent est un exécuteur discipliné.

---

## Design Respectueux des Ressources

### Pourquoi les Specs Hôte sont Critiques

Le budget ressources de l'agent doit être proportionnel aux capacités de l'hôte :

```
Hôte : 2 CPU, 2 Go RAM (petit VPS)
  → Budget évaluation règles : 1% CPU max
  → Règles max : 50
  → Taille batch : 100 événements
  → Buffer : 50 Mo
  → Fenêtre corrélation : 30s max

Hôte : 64 CPU, 256 Go RAM (base de données production)
  → Budget évaluation règles : 2% CPU max
  → Règles max : 500
  → Taille batch : 5000 événements
  → Buffer : 2 Go
  → Fenêtre corrélation : 300s max
```

La formule de budget est calculée par le serveur et poussée dans le profil :

```
max_rules     = min(500, num_cpu * 30)
cpu_budget    = min(4.0, max(0.5, total_mem_mb / 16384))
buffer_mb     = min(2048, max(50, total_mem_mb / 16))
batch_size    = min(5000, max(100, num_cpu * 200))
```

### Contrôle du Coût d'Évaluation des Règles

L'évaluation locale des règles est bornée :

1. **Budget temps par événement** : l'évaluation s'arrête si elle dépasse le budget (défaut : 100µs par événement)
2. **Limite du nombre de règles** : proportionnelle au nombre de cœurs CPU
3. **Cache de regex compilées** : pré-compilées au chargement, taille bornée (LRU)
4. **Ordre par priorité** : règles `critical` évaluées d'abord, `low` évaluées uniquement si le budget temps le permet
5. **Dégradation gracieuse sous charge** : voir section ci-dessous

### Dégradation Gracieuse (pas d'échantillonnage)

**L'échantillonnage aléatoire est interdit** — un attaquant pourrait surcharger l'hôte volontairement pour faire passer ses actions dans les événements non-évalués.

À la place, quand le budget CPU est sous pression :

1. **Niveau 1** (budget à 80%) : désactiver les règles `low` severity
2. **Niveau 2** (budget à 90%) : désactiver les règles `medium` severity
3. **Niveau 3** (budget à 95%) : ne garder que les règles `critical` + `high`
4. **Niveau 4** (budget à 100%) : ne garder que les règles `critical`

Chaque événement est TOUJOURS évalué — seul le nombre de règles diminue. Les règles critiques (reverse shell, privilege escalation) ne sont JAMAIS désactivées.

Le watchdog signale le niveau de pression au serveur → le serveur peut réduire le nombre de règles poussées pour cet hôte.

### Budget Réseau

L'agent ne sature jamais le réseau :

- **Mesure de débit** : l'agent mesure la latence RTT et le throughput gRPC à chaque batch envoyé
- **Adaptation dynamique** : si la latence augmente (réseau saturé), réduire la taille des batches et augmenter l'intervalle
- **Compression** : gzip systématique sur les batches
- **Déduplication d'événements** : événements identiques dans une fenêtre de 5s comptés (count + first_seen + last_seen), pas répétés
- **File de priorité** : événements sécurité (alertes, décisions) envoyés avant la télémétrie brute
- **Ceiling réseau** : ne jamais dépasser X% de la bande passante mesurée (configurable, défaut 5%)

---

## Format des Règles (Côté Agent)

### Règle simple (événement unique)

```json
{
  "id": "LOCAL-042",
  "name": "reverse_shell_detection",
  "version": 17,
  "severity": "critical",
  "autonomy": "always_act",
  "conditions": [
    {"field": "event_type", "op": "eq", "value": "process_exec", "weight": 1.0},
    {"field": "cmdline", "op": "regex", "value": "bash.*-i.*/dev/tcp|nc.*-e|python.*socket.*connect", "weight": 5.0},
    {"field": "binary", "op": "not_in", "value": {"ref": "baseline_apps"}, "weight": 3.0}
  ],
  "threshold": 6.0,
  "response": "kill_process",
  "confidence": 0.95
}
```

### Règle de corrélation temporelle (multi-événements)

```json
{
  "id": "LOCAL-088",
  "name": "ssh_brute_force",
  "version": 5,
  "severity": "high",
  "autonomy": "always_act",
  "correlation": {
    "event_type": "auth_failure",
    "group_by": "src_ip",
    "count_threshold": 5,
    "timeframe_seconds": 60
  },
  "threshold": 1.0,
  "response": "block_ip",
  "confidence": 0.92
}
```

### Règle de séquence (chaîne d'événements)

```json
{
  "id": "LOCAL-112",
  "name": "priv_escalation_chain",
  "version": 3,
  "severity": "critical",
  "autonomy": "always_act",
  "sequence": {
    "timeframe_seconds": 300,
    "steps": [
      {"event_type": "auth_failure", "field_match": {"service": "sudo"}},
      {"event_type": "process_exec", "field_match": {"binary": {"ref": "setuid_binaries"}}},
      {"event_type": "file_access", "field_match": {"path": "/etc/shadow", "action": "read"}}
    ],
    "group_by": "uid"
  },
  "threshold": 1.0,
  "response": "kill_process",
  "confidence": 0.88
}
```

### Résolution des références de profil

Les valeurs `{"ref": "..."}` sont résolues depuis le profil hôte au chargement des règles :

| Référence | Source dans le profil | Exemple |
|-----------|----------------------|---------|
| `baseline_apps` | `profile.baseline_apps` | `["/usr/sbin/nginx", "/usr/bin/postgres", "/usr/sbin/cron"]` |
| `baseline_net_dests` | `profile.baseline_net_dests` | `["10.0.0.0/8", "192.168.1.100"]` |
| `baseline_ports` | `profile.baseline_ports` | `[22, 80, 443, 5432]` |
| `baseline_users` | `profile.baseline_users` | `["root", "deploy", "postgres"]` |
| `setuid_binaries` | `profile.setuid_binaries` | `["/usr/bin/sudo", "/usr/bin/passwd"]` |

**Mises à jour d'applications légitimes** : quand un `apt upgrade` ajoute un nouveau binaire, l'agent le détecte comme anomalie. Le serveur voit le pattern (nouveau process stable, pas de comportement malicieux) et l'ajoute automatiquement à la baseline après la période d'observation. En attendant, le seuil élevé des règles à faible confiance empêche un blocage immédiat — seule une alerte est levée.

---

## Politique d'Autonomie

Le profil hôte définit le niveau d'autonomie :

| Profil | Autonomie | Signification |
|--------|-----------|---------------|
| `server_critical` | `always_act` | Agit sur toute règle qui fire (toutes sévérités) |
| `server_standard` | `critical_high` | Agit sur les règles critical + high |
| `workstation` | `critical_only` | Agit uniquement sur les règles critical |
| `minimal` | `log_only` | N'agit jamais localement, log tout pour analyse serveur |

L'agent évalue **toujours** toutes les règles localement. La politique d'autonomie ne contrôle que le passage à l'action :
- `always_act` : évalue + agit sur tout
- `critical_high` : évalue tout, agit uniquement si severity >= high
- `critical_only` : évalue tout, agit uniquement si severity == critical
- `log_only` : évalue tout, n'agit jamais, log pour le serveur

---

## Kill Switch et Sécurité

### Kill Switch (désactivation d'urgence)

Si l'agent cause des dommages (bloque un service critique par erreur) :

**Côté serveur (si accessible)** :
```
StreamCommands → DISABLE_AUTONOMY (priorité max, bypass toute file)
```
L'agent reçoit la commande et passe immédiatement en mode `log_only`. Toutes les actions en cours sont annulées (rollback).

**Côté hôte (si serveur inaccessible)** :
```bash
# L'admin local peut désactiver l'autonomie immédiatement
sudo oseye-config set OSEYE_AUTONOMY=disabled
sudo systemctl reload oseye-agent  # SIGHUP = reload config à chaud

# Ou via un fichier sentinelle (pas besoin de oseye-config)
sudo touch /etc/oseye/disable_autonomy
# L'agent vérifie ce fichier à chaque cycle d'évaluation
```

### Rollback automatique des règles

L'agent conserve les **2 dernières versions** du jeu de règles :

- Si la nouvelle version cause plus de 3 actions en 60 secondes sur des cibles distinctes (seuil configurable), l'agent revient automatiquement à la version précédente et signale le problème au serveur
- Ce mécanisme empêche les règles buggées de bloquer des services en cascade

### Protection contre la manipulation

- Les règles sont signées (Ed25519) par le serveur — l'agent refuse toute règle non signée
- Le fichier `/var/lib/oseye/local_rules.json` est vérifié (signature) à chaque chargement
- Un attaquant qui modifie le fichier directement ne peut pas injecter de règles

---

## Fenêtre de Corrélation Locale

Pour les règles multi-événements, l'agent maintient une **fenêtre d'événements en mémoire** :

| Paramètre | Contrôle | Borné par |
|-----------|----------|-----------|
| Durée max | `timeframe_seconds` dans la règle | Budget RAM (profil) |
| Événements max | Nombre d'événements en fenêtre | `max_correlation_events` (profil) |
| Groupes max | Nombre de `group_by` distincts en mémoire | `max_correlation_groups` (profil) |

Valeurs par défaut :
```
max_correlation_window = 300s (5 min)
max_correlation_events = 10000
max_correlation_groups = 1000
```

Quand un plafond est atteint, les entrées les plus anciennes sont évincées (LRU par groupe). Les règles critiques ont un budget dédié qui n'est pas partagé avec les règles medium/low.

---

## Flux de Données

```
┌─ AGENT (évalue TOUJOURS localement) ─────────────────────────────┐
│                                                                   │
│  [Collecteurs] → [Événement]                                     │
│                       │                                           │
│              ┌────────┴────────┐                                  │
│              ▼                 ▼                                   │
│  [Rule Engine Local]    [Batcher] → gRPC → Serveur               │
│         │                                                         │
│    Score >= seuil ?                                               │
│         │                                                         │
│    OUI + autonomie permet ?                                       │
│         │                                                         │
│    OUI → [Responder] → Agit (kill/block/quarantine)              │
│              └→ [Decision Log] → Queue rapport pour serveur       │
│                                                                   │
│  [Corrélation Window] ← fenêtre mémoire bornée (LRU)            │
│  [Rule Store] ← signé, persisté, 2 versions conservées           │
│  [Host Profile] ← persisté, résout les $refs dans les règles    │
│  [Watchdog] → dégradation gracieuse (pas d'échantillonnage)      │
│  [Kill Switch] ← fichier sentinelle + commande serveur            │
└───────────────────────────────────────────────────────────────────┘

┌─ SERVEUR (intelligence + supervision) ───────────────────────────┐
│                                                                   │
│  [Événements reçus] → Profile Engine                              │
│      │                    └→ baseline apps, réseau, users, horaires│
│      │                    └→ détecte les mises à jour légitimes   │
│      │                                                            │
│      ├→ Rule Engine                                               │
│      │     └→ génère des règles à partir de la baseline           │
│      │     └→ ajuste poids/seuils après feedback                  │
│      │     └→ signe les règles (Ed25519)                          │
│      │                                                            │
│      └→ Decision Engine                                           │
│            └→ scoring bayésien (confirmé/FP par type d'hôte)      │
│            └→ ajuste la politique d'autonomie                     │
│            └→ rollback si score trop bas                          │
│                                                                   │
│  [Push vers agent via ReceivePolicy stream] :                     │
│    - Jeu complet de règles (signé, versionné)                    │
│    - Profil hôte mis à jour (baselines résolues)                 │
│    - Budgets ressources recalculés                                │
│    - Kill switch si nécessaire                                    │
│                                                                   │
│  [Rapports de décision agent] → Boucle feedback                  │
│    - Confirmer : score bayésien ↑                                │
│    - Faux positif : score ↓, baseline ajustée, règles re-poussées│
└───────────────────────────────────────────────────────────────────┘
```

---

## Persistance et Résilience Offline

| Donnée | Stockage | Rôle |
|--------|----------|------|
| Règles (version N) | `/var/lib/oseye/local_rules.json` | Jeu actif, signé |
| Règles (version N-1) | `/var/lib/oseye/local_rules.prev.json` | Rollback automatique |
| Profil hôte | `/var/lib/oseye/host_profile.json` | Baselines, autonomie, budgets |
| Log décisions | SQLite (responder state) | Queue de rapports pour le serveur |
| Buffer événements | SQLite (`buffer.db`) | Événements pas encore envoyés |
| Kill switch | `/etc/oseye/disable_autonomy` | Fichier sentinelle (si existe → log_only) |

Au démarrage, l'agent :
1. Vérifie le kill switch
2. Charge et vérifie la signature des règles persistées
3. Charge le profil hôte
4. Résout les `$refs` (baseline_apps, etc.)
5. Commence l'évaluation immédiatement
6. Tente de se connecter au serveur (en parallèle, non-bloquant)

Si le serveur est injoignable, l'agent opère avec la dernière configuration connue indéfiniment. Quand le serveur revient, l'agent envoie tous les rapports de décision en queue et reçoit les mises à jour.

---

## Limites et Solutions

### 1. Apprentissage initial pollué

**Risque :** Un attaquant compromet la machine pendant la phase d'apprentissage → ses outils entrent dans la baseline et deviennent "normaux".

**Solution : Comparaison par groupe.**

Le serveur maintient une baseline de référence par **rôle** (tous les serveurs nginx, tous les workers CI, etc.). Si un hôte dévie significativement de son groupe, la baseline individuelle est rejetée.

```
Baseline hôte X              vs    Baseline groupe "web-servers"
  [nginx, postgres,                  [nginx, postgres, cron, logrotate]
   cron, cryptominer]
              ↑
  "cryptominer" absent du groupe → rejeté de la baseline, alerte levée
```

Mesures complémentaires :
- Les profils par défaut sont des **templates serrés** par rôle connu (pas une page blanche)
- Le rôle est déduit automatiquement des services actifs et ports au premier inventaire
- Un hôte dont la baseline ne converge pas vers son groupe après 14 jours est signalé pour audit manuel

---

### 2. Serveur compromis → règles empoisonnées

**Risque :** Un attaquant qui prend le serveur peut pousser des règles permissives, modifier les baselines, ou envoyer un kill switch global.

**Solution : Monotonie de sécurité + double signature.**

L'agent applique le principe de **monotonie** : les mises à jour de règles peuvent uniquement **ajouter ou resserrer** des détections. Toute mise à jour qui **affaiblit** la posture de sécurité nécessite une preuve d'autorité supplémentaire.

Opérations libres (signature serveur seule) :
- Ajouter une règle
- Augmenter un poids / baisser un seuil (plus sensible)
- Ajouter un élément à une baseline (nouvelle app légitime)

Opérations restreintes (double signature : serveur + clé admin séparée) :
- Supprimer une règle `critical`
- Augmenter un seuil globalement (moins sensible)
- Passer l'autonomie de `always_act` à `log_only`
- Envoyer un kill switch

La clé admin est distincte de la clé serveur — compromettre le serveur seul ne suffit pas pour désarmer les agents.

---

### 3. Dérive lente (concept drift)

**Risque :** Un attaquant patient modifie le comportement de l'hôte graduellement sur des semaines, jusqu'à ce que ses outils deviennent "normaux" dans la baseline.

**Solution : Rate-limiting de la baseline + comparaison de groupe.**

- La baseline ne peut évoluer que de **X% par semaine** (configurable par profil, défaut : 10%)
- Les changements qui dépassent ce taux sont refusés et nécessitent validation admin
- Le serveur compare régulièrement la baseline individuelle à celle du groupe — si un hôte dérive de son groupe même lentement, alerte
- Historique des baselines conservé (pas juste la dernière) — le serveur détecte une dérive cumulative sur 30/60/90 jours

```
Semaine 1 : baseline = [nginx, cron, postgres]            (stable)
Semaine 4 : baseline = [nginx, cron, postgres, tool_x]    (+1, OK < 10%)
Semaine 8 : baseline = [nginx, cron, postgres, tool_x, tool_y, tool_z]
                                                          (+3 depuis S1 = dérive détectée)
```

---

### 4. Corrélation longue durée impossible en local

**Risque :** Les attaques low-and-slow (étalées sur des heures/jours) dépassent la fenêtre de corrélation locale (5 min max).

**Solution : Compteurs persistants.**

L'agent ne garde pas tous les événements en mémoire, mais maintient des **compteurs agrégés** persistés en SQLite :

```json
{
  "counter_id": "auth_failure:src_ip:10.0.0.5",
  "count": 47,
  "first_seen": "2026-08-13T02:00:00Z",
  "last_seen": "2026-08-13T14:30:00Z",
  "window": "24h"
}
```

- Coût mémoire : quelques Ko (compteurs) au lieu de Mo (événements bruts)
- Permet de détecter "150 tentatives SSH sur 24h" sans stocker les 150 événements
- Les règles de type `correlation` peuvent référencer des fenêtres longues (1h, 24h, 7j) via ces compteurs
- Les compteurs sont purgés après expiration de leur fenêtre
- Budget : nombre de compteurs actifs limité par le profil (proportionnel à la RAM)

---

### 5. Clé de signature = single point of failure

**Risque :** Si la clé Ed25519 de signature des règles est volée, l'attaquant forge des règles arbitraires.

**Solution : HSM + rotation + double clé.**

| Mesure | Effet |
|--------|-------|
| Clé stockée en HSM (ou TPM serveur) | Jamais exportable, signing uniquement via API HSM |
| Rotation automatique tous les 30 jours | Fenêtre d'exploitation limitée |
| L'agent accepte les 2 dernières clés | Transition douce pendant la rotation |
| Double signature pour opérations destructives | Clé serveur + clé admin (voir point 2) |
| Alerte si la même clé signe un volume anormal de mises à jour | Détection de compromission |

---

### 6. Rollback contournable (seuil prévisible)

**Risque :** Un attaquant qui connaît le seuil de rollback (3 actions/60s) calibre son attaque juste en-dessous.

**Solution : Seuil adaptatif + détection de pattern.**

Le seuil de rollback n'est pas fixe :
- **Base** : moyenne historique d'actions sur cet hôte + 2 écarts-types
- **Jitter** : facteur aléatoire ±20% (l'attaquant ne peut pas prédire le seuil exact)
- **Détection de pattern** : un hôte qui déclenche régulièrement des actions **juste sous le seuil** est statistiquement suspect — le serveur reçoit les rapports et détecte ce pattern même si l'agent ne rollback pas

```
Hôte normal : 0-1 actions par jour
Seuil dynamique : 2 actions / 60s (base 1 + jitter)

Attaquant calibré à 1 action / 62s → pas de rollback
Mais le serveur voit : "5 actions en 5 min, toujours 1 par minute" → pattern anormal → alerte
```

---

### 7. Rootkit kernel = agent aveugle

**Risque :** Un attaquant avec Ring 0 peut cacher des processus, intercepter les syscalls de l'agent, ou le désactiver silencieusement.

**Solution : Détection par absence + attestation matérielle.**

L'agent ne peut pas se protéger contre un kernel compromis. Mais le **serveur et le réseau** le peuvent :

| Couche | Mécanisme | Détecte |
|--------|-----------|---------|
| **Heartbeat** | L'agent envoie un signal régulier. Absence = alerte serveur (< 30s) | Agent tué ou gelé |
| **Profil de silence** | Si un hôte habituellement actif envoie soudain zéro anomalie, c'est suspect | Rootkit qui filtre les événements |
| **Vérification croisée réseau** | Sonde réseau indépendante compare le trafic réel vs ce que l'agent rapporte | Connexions C2 cachées |
| **Attestation TPM** | Remote attestation — le serveur vérifie l'intégrité du kernel et de l'agent | Modification du binaire agent ou du kernel |
| **eBPF vérification** | L'agent vérifie que ses programmes eBPF sont toujours chargés et non modifiés | Détachement des sondes eBPF |

Principe : **l'agent est une couche, pas un mur**. La sécurité vient de la combinaison agent + serveur + réseau + matériel.

---

### 8. Coût serveur avec 10 000+ agents

**Risque :** Profile Engine + Rule Engine + Decision Engine × N hôtes = explosion des ressources serveur.

**Solution : Groupement par rôle + héritage.**

Les hôtes du même rôle/cluster partagent la majorité de leurs règles :

```
Hiérarchie des règles :
  Règles globales (s'appliquent à tous)        → 1 calcul
    └→ Règles du rôle "web-server"             → 1 calcul par rôle
         └→ Exceptions hôte "prod-web-03"      → 1 calcul par exception

10 000 hôtes, 20 rôles, 50 exceptions individuelles
= 1 + 20 + 50 = 71 calculs au lieu de 10 000
```

- Le scoring bayésien est calculé **par rôle**, pas par hôte (sauf exception)
- La baseline de groupe est la source de vérité — les baselines individuelles ne sont que des deltas
- Le Profile Engine ne recalcule un hôte individuel que quand il dévie de son groupe
- Le Rule Engine génère un jeu de règles par rôle + un patch par hôte déviant

---

### 9. Faux positifs en cascade lors d'un déploiement

**Risque :** Nouvelle version déployée → tous les hôtes du groupe alertent simultanément → actions autonomes bloquent le déploiement.

**Solution : Détection de déploiement + suppression corrélée.**

Le serveur détecte automatiquement les déploiements :

```
SI > 30% des hôtes du même groupe déclenchent la même règle dans un intervalle < 5 min
ALORS c'est un déploiement, pas une attaque
  → Suspendre les actions pour cette règle sur ce groupe (fenêtre : 30 min)
  → Alerter l'admin (info, pas critical)
  → Après la fenêtre, le Profile Engine met à jour la baseline
```

Mesures complémentaires :
- **Intégration CI/CD** : un webhook pré-déploiement passe le groupe en mode "deploy" (supprime les actions sur les nouvelles apps pendant N minutes)
- **L'agent lui-même** détecte quand `apt`/`dpkg`/`yum` tourne et envoie un événement "package_update" — le serveur sait qu'un changement légitime est en cours
- **Fenêtre de grâce** configurable par profil : les règles à faible confiance sont suspendues 15 min après un package_update détecté

---

### 10. L'agent n'est pas isolé de l'hôte

**Risque :** Un attaquant root peut lire les règles (savoir ce qui est détecté), tuer l'agent, ou supprimer les traces.

**Solution : Multi-couche + détection externe.**

Ce problème est fondamentalement insoluble en logiciel seul. Mais on peut le rendre très difficile :

| Mesure | Effet | Coût |
|--------|-------|------|
| **Stockage chiffré** (clé dérivée du TPM ou du cert mTLS) | Les règles sur disque sont illisibles sans la clé agent | Faible |
| **Binary immutable** (dm-verity / mount read-only) | L'agent ne peut pas être remplacé par un faux | Moyen |
| **Heartbeat serveur** (< 30s) | Si l'agent meurt, le serveur alerte immédiatement | Faible |
| **Watchdog systemd** (Restart=always + WatchdogSec) | Relance automatique si tué + rapport d'incident | Faible |
| **Network-side detection** | Sonde réseau indépendante — si l'hôte fait du C2 que l'agent ne rapporte pas, compromission détectée | Moyen |
| **Obfuscation des règles en mémoire** | Les règles en RAM ne sont pas en clair (XOR avec clé éphémère) — rend la lecture par un debugger plus difficile | Faible |
| **Tamper detection au boot** | L'agent vérifie son propre hash au démarrage (signé dans le package) | Faible |

Principe fondamental : **l'agent est une couche de défense, pas la seule**. Un attaquant qui a root ET qui désactive l'agent sera détecté par :
1. Le serveur (heartbeat absent)
2. Le réseau (trafic non rapporté)
3. Les autres agents du groupe (comportement anormal de cet hôte vu depuis l'extérieur)

La sécurité d'OSEye repose sur la **défense en profondeur** : aucune couche unique n'est suffisante, mais leur combinaison rend la compromission invisible extrêmement difficile.
