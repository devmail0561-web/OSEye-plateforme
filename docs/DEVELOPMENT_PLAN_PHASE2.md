# OSEye — Plan de développement Phase 2 — Full Collection

**Version :** 1.0  
**Date :** 2026-08-06  
**Statut :** Phase 2 démarrée — 0/7 modules mergés

---

## Objectif Phase 2

**9 collecteurs Linux opérationnels** + **agent robuste** face aux pannes réseau.

**Durée estimée :** S4-S6 (3 semaines)

**Prérequis :** Phase 1 complète (commit `e539c39`)

---

## Lecture du plan

- Un **module** = une **branche Git** = une **PR** vers `main`
- **Statuts :** `[ ]` à faire · `[~]` en cours · `[x]` terminé
- **Dépendances :** un module ne démarre pas si ses prérequis ne sont pas `[x]`
- **Tests inclus** : chaque module livre ses tests dans la même PR

---

## Statut des modules Phase 2

| # | Module | Branche | Dépend de | Statut | Tâches PLAN_ACTION |
|---|--------|---------|-----------|--------|--------------------|
| M12 | Collecteurs files (fanotify, inotify) | `M12/collectors-files` | Phase 1 | `[ ]` | P2.01, P2.02 |
| M13 | Collecteurs net/logs (netlink, journald, udev, syslog) | `M13/collectors-net-logs` | Phase 1 | `[ ]` | P2.03-P2.06 |
| M14 | Normalizers nouveaux collecteurs | `M14/normalizers-phase2` | M12, M13 | `[ ]` | P2.07 |
| M15 | Watchdog & throttling agent | `M15/agent-watchdog` | Phase 1 | `[ ]` | P2.08 |
| M16 | Buffer replay & backpressure | `M16/agent-resilience` | M15 | `[ ]` | P2.09, P2.10 |
| M17 | API agents & enrollment | `M17/server-api-agents` | Phase 1 | `[ ]` | P2.11, P2.12 |
| M18 | Tests résilience & DaemonSet K8s | `M18/tests-resilience` | M12-M17 | `[ ]` | P2.13-P2.15 |

---

## Graphe de dépendances

```
Phase 1 ──► M12 (collectors-files) ──► M14 (normalizers) ──► M18 (tests)
         ──► M13 (collectors-net-logs) ──► M14 ───────────► M18
         ──► M15 (watchdog) ──► M16 (resilience) ──────────► M18
         ──► M17 (api-agents) ──────────────────────────────► M18
```

**Parallélisable :** M12, M13, M15, M17 peuvent démarrer simultanément.

---

## M12 — Collecteurs files (fanotify, inotify) `[ ]`

**Objectif :** Surveillance fichiers/répertoires temps réel.

**Branche :** `M12/collectors-files`

**Dépend de :** Phase 1 complète

### Livrables

#### Code Go

1. **`agent/internal/platform/linux/fanotify/collector.go`**
   - Interface `Collector`
   - Surveille accès/modifications fichiers sensibles (`/etc/passwd`, `/etc/shadow`, `/root/.ssh/`)
   - Events : `FAN_ACCESS`, `FAN_MODIFY`, `FAN_CLOSE_WRITE`, `FAN_OPEN_PERM`
   - Filtres configurables par path patterns
   - RawEvent JSON : `{"os":"linux", "source":"fanotify", "pid":..., "path":..., "mask":..., "timestamp_ns":...}`

2. **`agent/internal/platform/linux/inotify/collector.go`**
   - Interface `Collector`
   - Watch répertoires configurables (ex: `/var/log`, `/tmp`, `/home/*/.ssh`)
   - Events : `IN_CREATE`, `IN_DELETE`, `IN_MODIFY`, `IN_MOVED_FROM/TO`, `IN_ATTRIB`
   - Support récursif optionnel
   - RawEvent JSON : `{"os":"linux", "source":"inotify", "wd":..., "mask":..., "name":..., "timestamp_ns":...}`

3. **`agent/internal/config/collectors.go`**
   - Ajout config `fanotify_paths` et `inotify_watches`
   - Exemple :
     ```go
     type CollectorConfig struct {
         FanotifyPaths []string `env:"OSEYE_FANOTIFY_PATHS" envDefault:"/etc/passwd,/etc/shadow"`
         InotifyWatches []InotifyWatch `env:"OSEYE_INOTIFY_WATCHES"`
     }
     type InotifyWatch struct {
         Path string
         Recursive bool
         Mask uint32  // IN_CREATE | IN_MODIFY etc.
     }
     ```

#### Tests Go

- `fanotify_test.go` :
  - Test ouverture `/tmp/test-fanotify`
  - Vérifier event `FAN_OPEN` reçu
  - Test permissions (nécessite CAP_SYS_ADMIN ou skip)
- `inotify_test.go` :
  - Test création fichier dans watch dir
  - Vérifier event `IN_CREATE` reçu
  - Test déplacement fichier (IN_MOVED_FROM + IN_MOVED_TO)

**Critères d'acceptance :**
- [ ] `go test ./internal/platform/linux/fanotify -v` passe (ou skip si !CAP_SYS_ADMIN)
- [ ] `go test ./internal/platform/linux/inotify -v` passe
- [ ] Couverture > 75%
- [ ] Agent peut démarrer avec fanotify + inotify actifs sans crash
- [ ] Events reçus par CollectorManager

---

## M13 — Collecteurs net/logs (netlink, journald, udev, syslog) `[ ]`

**Objectif :** Surveillance réseau kernel + logs système + devices.

**Branche :** `M13/collectors-net-logs`

**Dépend de :** Phase 1 complète

### Livrables

#### Code Go

1. **`agent/internal/platform/linux/netlink/collector.go`**
   - Interface `Collector`
   - Écoute `NETLINK_ROUTE` pour connexions TCP/UDP (via `RTMGRP_IPV4_IFADDR`, `RTMGRP_LINK`)
   - Alternative : parser `/proc/net/tcp`, `/proc/net/udp` périodiquement
   - RawEvent JSON : `{"os":"linux", "source":"netlink", "local_addr":..., "remote_addr":..., "state":"ESTABLISHED", ...}`

2. **`agent/internal/platform/linux/journald/collector.go`**
   - Interface `Collector`
   - Lecture journald via `sdjournal.h` (CGO) ou `journalctl -f -o json` pipe
   - Filtres : `_SYSTEMD_UNIT`, `PRIORITY`, `SYSLOG_IDENTIFIER`
   - RawEvent JSON : `{"os":"linux", "source":"journald", "unit":..., "message":..., "priority":..., "timestamp_ns":...}`

3. **`agent/internal/platform/linux/udev/collector.go`**
   - Interface `Collector`
   - Monitor `/dev` via `libudev` (CGO) ou parser `/sys/class/` + inotify
   - Events : device add/remove (USB, HID, block devices)
   - RawEvent JSON : `{"os":"linux", "source":"udev", "action":"add", "devpath":..., "subsystem":"usb", ...}`

4. **`agent/internal/platform/linux/syslog/collector.go`**
   - Interface `Collector`
   - Écoute `/dev/log` (UNIX socket) ou UDP 514
   - Parse RFC3164/RFC5424
   - RawEvent JSON : `{"os":"linux", "source":"syslog", "facility":..., "severity":..., "hostname":..., "message":..., "timestamp_ns":...}`

#### Tests Go

- `netlink_test.go` : mock socket netlink ou parser `/proc/net/tcp`
- `journald_test.go` : mock `journalctl` output ou skip si systemd absent
- `udev_test.go` : mock `/sys/class/` structure
- `syslog_test.go` : client UDP vers collector local, vérifier réception

**Critères d'acceptance :**
- [ ] Tests unitaires pour les 4 collecteurs passent
- [ ] Couverture > 70% (netlink/journald complexes)
- [ ] Agent démarre avec les 4 actifs
- [ ] Events reçus et formatés correctement en RawEvent

---

## M14 — Normalizers nouveaux collecteurs `[ ]`

**Objectif :** Transformer RawEvent (fanotify, inotify, netlink, journald, udev, syslog) → UniversalEvent.

**Branche :** `M14/normalizers-phase2`

**Dépend de :** M12, M13

### Livrables

#### Code Python

1. **`server/oseye/normalizer/adapters/linux/fanotify.py`**
   - Fonction `normalize_fanotify(raw: dict) -> UniversalEvent`
   - Mapping :
     - `category` = "file"
     - `type` = "access" | "modify" | "create"
     - `resource` = path du fichier
     - `pid`, `uid` extraits si présents

2. **`server/oseye/normalizer/adapters/linux/inotify.py`**
   - `normalize_inotify(raw: dict) -> UniversalEvent`
   - Mapping mask → type : `IN_CREATE` → "create", `IN_DELETE` → "delete", etc.

3. **`server/oseye/normalizer/adapters/linux/netlink.py`**
   - `normalize_netlink(raw: dict) -> UniversalEvent`
   - `category` = "network", `type` = "connection"
   - `resource` = `"{local_addr}:{local_port} → {remote_addr}:{remote_port}"`

4. **`server/oseye/normalizer/adapters/linux/journald.py`**
   - `normalize_journald(raw: dict) -> UniversalEvent`
   - `category` = "log", `type` = "syslog"
   - `severity` mappé depuis priority (0-7 → critical/high/medium/low)

5. **`server/oseye/normalizer/adapters/linux/udev.py`**
   - `normalize_udev(raw: dict) -> UniversalEvent`
   - `category` = "device", `type` = "add" | "remove"
   - `resource` = devpath

6. **`server/oseye/normalizer/adapters/linux/syslog.py`**
   - `normalize_syslog(raw: dict) -> UniversalEvent`
   - Similaire journald

7. **`server/oseye/normalizer/engine.py`**
   - Ajout dispatch pour les 6 nouveaux sources

#### Tests Python

- `test_normalizer_fanotify.py` : fixture RawEvent → vérifier UniversalEvent
- Idem pour les 5 autres adapters
- `test_normalizer_dispatch.py` : vérifier routage source → adapter

**Critères d'acceptance :**
- [ ] `pytest tests/unit/test_normalizer*.py` passe
- [ ] Couverture > 80%
- [ ] Integration test : agent envoie RawEvent fanotify → server normalise → vérifie DB

---

## M15 — Watchdog & throttling agent `[ ]`

**Objectif :** Agent auto-monitore sa consommation CPU/mémoire et throttle si nécessaire.

**Branche :** `M15/agent-watchdog`

**Dépend de :** Phase 1 complète

### Livrables

#### Code Go

1. **`agent/internal/watchdog/resource_monitor.go`**
   - Goroutine surveillant `/proc/self/stat` toutes les 5s
   - Calcul CPU % : `(utime_delta + stime_delta) / elapsed_ticks * 100`
   - Calcul mémoire RSS depuis `/proc/self/status`
   - Si CPU > 4% pendant 30s → émet event `ThrottleNeeded`

2. **`agent/internal/watchdog/throttler.go`**
   - Reçoit `ThrottleNeeded` → ajuste `throttleFactor` (0.0-1.0)
   - Formule : si CPU 6% → factor = 0.5 (drop 50% events)
   - Propage factor vers CollectorManager → chaque collector applique sampling

3. **`agent/internal/collector/manager.go`**
   - Ajout méthode `SetThrottleFactor(f float64)`
   - Collecteurs propagent factor → drop aléatoire `rand.Float64() > factor`

4. **`agent/cmd/oseye-agent/main.go`**
   - Démarre watchdog en parallèle du pipeline

#### Tests Go

- `resource_monitor_test.go` : mock `/proc/self/stat`, vérifier calcul CPU
- `throttler_test.go` : simuler CPU > 4%, vérifier factor ajusté
- Integration : stress agent avec 500k events/s, vérifier throttling auto

**Critères d'acceptance :**
- [ ] Tests passent
- [ ] Agent sous charge réduit automatiquement CPU à ~3%
- [ ] Logs structurés : `{"watchdog":"throttle_applied", "factor":0.7, "cpu_pct":4.2}`

---

## M16 — Buffer replay & backpressure `[ ]`

**Objectif :** Replay automatique post-reconnexion + backpressure serveur → agents.

**Branche :** `M16/agent-resilience`

**Dépend de :** M15

### Livrables

#### Code Go (agent)

1. **`agent/internal/buffer/buffer.go`**
   - Ajout méthode `Replay(lastAckID int64) ([]Event, error)`
   - Query SQLite : `SELECT * FROM events WHERE id > ? ORDER BY id LIMIT 1000`
   - Cleanup post-ACK : `DELETE FROM events WHERE id <= ?`

2. **`agent/internal/transport/grpc_client.go`**
   - Sur reconnexion : récupère `lastAckID` depuis state local
   - Appelle `buffer.Replay(lastAckID)` → envoie batch
   - Reçoit `IngestResponse.ack_id` → sauvegarde + cleanup buffer

3. **`agent/internal/transport/backpressure.go`**
   - Écoute stream gRPC `StreamCommands` (nouveau RPC dans proto)
   - Reçoit `ThrottleCommand{factor: 0.8}` → propage vers CollectorManager

#### Code Python (server)

1. **`server/oseye/ingest/backpressure.py`**
   - `BackpressureController` : mesure lag Redis Streams toutes les 10s
   - Si lag > 10k messages → calcule factor = 0.5
   - Envoie `ThrottleCommand` via gRPC `StreamCommands` vers tous agents connectés

2. **`proto/event.proto`**
   - Ajout RPC :
     ```proto
     rpc StreamCommands(stream CommandRequest) returns (stream CommandResponse);
     message CommandResponse {
       oneof command {
         ThrottleCommand throttle = 1;
         PolicyPush policy = 2;
       }
     }
     message ThrottleCommand {
       float factor = 1;  // 0.0-1.0
     }
     ```

#### Tests

- Go : test déconnexion 10s → reconnexion → vérifier replay
- Python : mock lag Redis → vérifier ThrottleCommand envoyé
- Integration E2E : déco réseau 60s → vérifier 0 perte events

**Critères d'acceptance :**
- [ ] Déconnexion 60s suivie de reconnexion : 0 events perdus
- [ ] Lag serveur > seuil → agents reçoivent throttle sous 15s
- [ ] Buffer SQLite cleanup automatique après ACK

---

## M17 — API agents & enrollment `[ ]`

**Objectif :** Endpoints REST pour gérer agents + enrollment sécurisé.

**Branche :** `M17/server-api-agents`

**Dépend de :** Phase 1 complète

### Livrables

#### Code Python

1. **`server/oseye/api/routers/agents.py`**
   - `GET /api/v1/agents` : liste agents (pagination)
   - `GET /api/v1/agents/{agent_id}` : détails agent
   - `GET /api/v1/agents/{agent_id}/status` : last_seen, CPU, version
   - `POST /api/v1/agents/enroll` : démarre enrollment (retourne OTP)
   - `POST /api/v1/agents/{agent_id}/csr` : soumet CSR + OTP, retourne certificat signé
   - `POST /api/v1/agents/{agent_id}/renew` : renouvellement certificat

2. **`server/oseye/storage/repositories/agents.py`**
   - CRUD agents table
   - Méthodes : `create`, `get`, `list`, `update_last_seen`, `update_status`

3. **`scripts/generate_certs.sh`**
   - Refactor pour supporter :
     - Génération OTP (8 chars alphanumériques)
     - Validation CSR (vérifier CN = agent_id)
     - Signature avec intermediate CA
   - Ajout commande : `./generate_certs.sh enroll <agent_id>` → affiche OTP

4. **Agent Go enrollment**
   - `agent/cmd/oseye-agent/enroll.go`
   - CLI : `oseye-agent enroll --server https://... --otp ABCD1234`
   - Génère keypair Ed25519 → CSR → POST /agents/{id}/csr → sauvegarde cert

#### Tests

- Python : test endpoint `/agents/enroll` → vérifier OTP créé
- Python : test CSR submission + validation
- Go : test enrollment flow E2E (mock server)

**Critères d'acceptance :**
- [ ] `curl -X POST /api/v1/agents/enroll` retourne OTP
- [ ] Agent CLI peut s'enroller avec OTP valide
- [ ] Certificat signé sauvegardé et utilisable pour mTLS

---

## M18 — Tests résilience & DaemonSet K8s `[ ]`

**Objectif :** Tests E2E + déploiement K8s local.

**Branche :** `M18/tests-resilience`

**Dépend de :** M12-M17 (tous les modules Phase 2)

### Livrables

#### Tests E2E

1. **`server/tests/integration/test_resilience.py`**
   - Scénario : agent → server, déco réseau 60s, reconnexion
   - Vérifier : 0 events perdus, replay correct

2. **`server/tests/integration/test_collectors_phase2.py`**
   - Test fanotify : toucher `/tmp/test` → event reçu
   - Test inotify : créer fichier → event reçu
   - Test journald : log systemd → event reçu

#### Infra K8s

1. **`infra/k8s/daemonset.yaml`**
   - DaemonSet oseye-agent
   - ConfigMap pour config agent
   - Secret pour certificats mTLS

2. **`infra/k8s/README.md`**
   - Instructions déploiement sur minikube/kind

#### Documentation

1. **`docs/COLLECTORS.md`**
   - Documentation des 9 collecteurs
   - Configuration de chacun
   - Exemples RawEvent → UniversalEvent

**Critères d'acceptance :**
- [ ] `pytest tests/integration/test_resilience.py` passe
- [ ] DaemonSet déployable sur minikube
- [ ] Agents dans K8s envoient events au server

---

## Checklist Phase 2 complète

- [ ] 7/7 modules mergés sur `main`
- [ ] 9 collecteurs Linux opérationnels
- [ ] Agent survit à déconnexion 60s sans perte
- [ ] Throttling automatique si CPU > 4%
- [ ] API agents fonctionnelle
- [ ] Enrollment sécurisé opérationnel
- [ ] Tests E2E résilience passent
- [ ] DaemonSet K8s déployable

**Livrable Phase 2 :** Agent robuste avec surveillance complète (files, réseau, logs, devices).
