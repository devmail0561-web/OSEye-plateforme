# OSEye — Plan de développement Agent Go + Serveur Python (Phases 2-3)

**Version :** 1.2  
**Date :** 2026-08-07  
**Basé sur :** commit `314f1f1` (M22 mergé)  
**Périmètre :** Agent Go (`agent/`) + Server Python (`server/oseye/`) + Règles de détection (`rules/`)

---

## Récapitulatif de l'existant

### Ce qui est implémenté et testé (2026-08-07)

| Package | État | Tests |
|---------|------|-------|
| `internal/buffer` | ✅ Complet (CGO + pure-Go) | buffer_test.go + bench |
| `internal/chain` | ✅ Complet | chain_test.go + bench |
| `internal/signer` | ✅ Complet | signer_test.go + bench |
| `internal/collector` | ✅ Interface + Manager + SetThrottle | manager_test.go |
| `internal/config` | ✅ Complet + Hardened (2026-08-12) | config_test.go (25 tests) — validation stricte ports, paths absolus, UUID v4, bounds |
| `cmd/oseye-config` | ✅ Nouveau (2026-08-12) | — CLI gestion config (atomic write, flock, secrets masqués) |
| `internal/transport/batcher` | ✅ Complet | batcher_test.go |
| `internal/transport/grpc_client` | ✅ Complet + ServiceClient() | grpc_client_test.go (bufconn) |
| `internal/mapper` | ✅ Complet (M14 + audit) | mapper_test.go — 32 champs, split addr, bounds |
| `internal/watchdog` | ✅ Complet (M16 + audit) | watchdog_test.go — HZ dynamique, zero-limits guard |
| `internal/policy` | ✅ Complet (M17 + audit) | handler_test.go — channel sérialisé, reconnexion EOF |
| `internal/commands` | ✅ Complet (M17) | client_test.go |
| `platform/linux/driver` | ✅ 8 collecteurs câblés (M14) | — |
| `platform/linux/procfs` | ✅ Complet | collector_test.go |
| `platform/linux/fanotify` | ✅ Complet (M12) | collector_test.go |
| `platform/linux/inotify` | ✅ Complet (M12) | collector_test.go |
| `platform/linux/netlink` | ✅ Complet (M13) | collector_test.go |
| `platform/linux/journald` | ✅ Complet (M13) | collector_test.go |
| `platform/linux/syslog` | ✅ Complet (M13) | collector_test.go |
| `platform/linux/udev` | ✅ Complet (M13) | collector_test.go |
| `normalizer/adapters/linux/*` | ✅ 6 adapters Phase 2 (M18 + audit) | test_normalizer.py |
| `normalizer/engine.py` | ✅ try/except + uuid guard (audit) | test_normalizer.py |
| `normalizer/adapters/linux/_utils.py` | ✅ safe_int + agent_ts (audit) | test_normalizer.py |

### Lacunes résolues (GAP)

| ID | Fichier | Lacune | Résolu dans |
|----|---------|--------|-------------|
| GAP-01 | `driver.go` | 6 collecteurs non câblés | M14 |
| GAP-02 | `main.go` | 4/32 champs UniversalEventPB seulement | M14 |
| GAP-03 | `main.go` | AgentId/EventId non populés | M14 + audit (H1) |
| GAP-04 | `main.go` | Buffer JSON brut, drain incomplet | M15 |
| GAP-05 | `watchdog/` | Package vide | M16 |
| GAP-06 | — | ReceivePolicy/StreamCommands jamais appelés | M17 |
| GAP-09 | `config.go` | Import unix dans fichier cross-platform | corrigé M14 |

### Lacunes restantes

*(toutes les lacunes Phases 1-2 sont résolues — aucune lacune ouverte)*

---

## Modules de développement

### Graphe de dépendances (mis à jour)

```
M12 ✅ ──┐
M13 ✅ ──┤
         └──► M14 ✅ ──► M15 ✅ (buffer proto)
                     ──► M16 ✅ (watchdog)
                     ──► M17 ✅ (policy+commands)
                     ──► M19 ✅ (auditd complet)
                     ──► M20 ✅ (eBPF)
              M14 ──► M18 ✅ (normalizers Python)
         M15 ✅ + M16 ✅ + M17 ✅ + M18 ✅ + M19 ✅ + M20 ✅ ──► M21 ✅ (tests résilience)

Phase 2 ✅ ──► M22 ✅ (Rule Engine + 30 règles) ──► M23 (API rules + WS alerts)
```

**Phase 3 en cours :** M22 livré, M23 à démarrer.

---

## M14 — Câblage collecteurs Phase 2 + mapper event

**Branche :** `M14/agent-wire-mapper`  
**Dépend de :** M12, M13  
**Résout :** GAP-01, GAP-02, GAP-03  
**Durée estimée :** 2 jours

### Fichiers à créer / modifier

#### 1. `agent/internal/mapper/mapper.go` — NOUVEAU FICHIER

Package qui traduit un `collector.RawEvent` en `*oseyev1.UniversalEventPB` complètement populé.

```go
//go:build linux

package mapper
```

**Struct :**
```go
type EventMapper struct {
    hostname  string
    agentID   []byte
}
```

**Fonctions :**

`func New(hostname string, agentID []byte) *EventMapper`
- Paramètres : `hostname` issu de `os.Hostname()`, `agentID` en bytes (UUID v4)
- Retourne une instance prête à l'emploi

`func (m *EventMapper) Map(raw collector.RawEvent, hashChain []byte) (*oseyev1.UniversalEventPB, error)`
- Parse `raw.Raw` en `map[string]interface{}` via `json.Unmarshal`
- Génère un `event_id` UUID v4 avec `github.com/google/uuid` : `uuid.New().String()` converti en bytes
- Popule les champs communs :
  - `EventId` ← UUID v4 bytes
  - `TimestampNs` ← `raw.Timestamp`
  - `Hostname` ← `m.hostname`
  - `AgentId` ← `m.agentID`
  - `Os` ← `raw.OS`
  - `Collector` ← `raw.Source`
  - `HashChain` ← paramètre `hashChain`
- Appelle `m.mapCategory(raw.Source)` pour `Category`
- Appelle `m.mapFields(payload, raw.Source, ev)` pour les champs spécifiques
- Met `ExtraJson` ← `raw.Raw` (payload brut complet, pour debugging)
- Retourne `(*oseyev1.UniversalEventPB, nil)` ; retourne une erreur uniquement si le JSON est invalide

`func (m *EventMapper) mapCategory(source string) string`
- Table de correspondance exhaustive :
  - `"procfs"` → `"process"`
  - `"fanotify"` → `"file"`
  - `"inotify"` → `"file"`
  - `"netlink"` → `"network"`
  - `"journald"` → `"log"`
  - `"syslog"` → `"log"`
  - `"udev"` → `"device"`
  - `"auditd"` → `"audit"`
  - `"ebpf"` → `"process"`
  - toute autre valeur → `"unknown"`

`func (m *EventMapper) mapFields(payload map[string]interface{}, source string, ev *oseyev1.UniversalEventPB)`
- Champs process (présents dans procfs, auditd, eBPF) :
  - `Pid` ← `payload["pid"]` via `intField(payload, "pid")`
  - `Ppid` ← `payload["ppid"]`
  - `Uid` ← `payload["uid"]`
  - `Gid` ← `payload["gid"]`
  - `ProcessName` ← `strField(payload, "name")`
  - `Executable` ← `strField(payload, "exe")`
  - `Cmdline` ← `strField(payload, "cmdline")`
- Champs fichier (fanotify, inotify) :
  - `Resource` ← `strField(payload, "path")` ou `strField(payload, "full_path")`
  - `Type` ← `strField(payload, "event_type")`
- Champs réseau (netlink) :
  - `SrcIp` ← `strField(payload, "local_addr")`
  - `DstIp` ← `strField(payload, "remote_addr")`
  - `Protocol` ← `strField(payload, "proto")`
  - `Type` ← `strField(payload, "event")` (`"new"` | `"closed"`)
- Champs log (journald, syslog) :
  - `Resource` ← `strField(payload, "unit")` ou `strField(payload, "program")`
  - `Severity` ← mapper `strField(payload, "priority")` ou `strField(payload, "severity")` vers `"info"|"warning"|"error"|"critical"`
- Champs device (udev) :
  - `Resource` ← `strField(payload, "devpath")`
  - `Type` ← `strField(payload, "action")` (`"add"` | `"remove"`)
- Si `Severity` reste vide après mapFields : `ev.Severity = "info"`

`func strField(m map[string]interface{}, key string) string`
- Retourne `m[key].(string)` si la clé existe et est un string, `""` sinon

`func intField(m map[string]interface{}, key string) int32`
- Retourne `int32(v)` si la valeur est un `float64` (JSON unmarshal par défaut), `0` sinon

#### 2. `agent/internal/mapper/mapper_test.go` — NOUVEAU FICHIER

Tests unitaires purs (pas de syscall nécessaire — build tag `linux` non requis ici).

`func TestMapCategory(t *testing.T)` : vérifie la table complète source → catégorie

`func TestMapCommonFields(t *testing.T)` : crée un `RawEvent` procfs minimal, appelle `Map()`, vérifie que `EventId`, `TimestampNs`, `Hostname`, `AgentId`, `Os`, `Collector`, `HashChain` sont populés

`func TestMapProcfsFields(t *testing.T)` : payload procfs complet `{pid, ppid, name, exe, cmdline, uid, gid}` → vérifie tous les champs proto correspondants

`func TestMapFanotifyFields(t *testing.T)` : payload fanotify `{path, event_type, pid, mask}` → vérifie `Resource`, `Type`, `Pid`

`func TestMapNetlinkFields(t *testing.T)` : payload netlink `{local_addr, remote_addr, proto, event}` → vérifie `SrcIp`, `DstIp`, `Protocol`, `Type`

`func TestMapInvalidJSON(t *testing.T)` : `raw.Raw = []byte("not json")` → vérifie que `Map()` retourne une erreur

`func TestMapExtraJsonPreserved(t *testing.T)` : vérifie que `ExtraJson` contient le payload brut original

#### 3. `agent/internal/platform/linux/driver.go` — MODIFIER

`func (d *LinuxDriver) Collectors(cfg *config.Config) ([]collector.Collector, error)`
- Remplacer le corps actuel (procfs + auditd seulement) par la liste complète :
  ```
  procfs.New()
  auditd.New()
  fanotify.New(cfg.FanotifyPaths)
  inotify.New(cfg.InotifyWatches)
  netlink.New()
  journald.New(cfg.JournaldPriority, cfg.JournaldUnits)
  syslog.New(cfg.SyslogAddr)
  udev.New()
  ```
- Note : certains constructeurs (`fanotify.New`, `inotify.New`) acceptent déjà la config. Vérifier les signatures et adapter si nécessaire.
- `journald.New` : ajouter paramètres optionnels `priority string` et `units []string` depuis config (voir GAP-09 aussi)
- `syslog.New` : ajouter paramètre `addr string` depuis `cfg.SyslogAddr`

**Nouveaux champs à ajouter dans `internal/config/config.go` :**
- `JournaldPriority string` ← `OSEYE_JOURNALD_PRIORITY`, défaut `""`
- `JournaldUnits []string` ← `OSEYE_JOURNALD_UNITS` (CSV), défaut `[]`
- `SyslogAddr string` ← `OSEYE_SYSLOG_ADDR`, défaut `"127.0.0.1:514"`

**Fix GAP-09 :** Déplacer la constante `unix.IN_ALL_EVENTS` (valeur `0xFFF`) dans `config.go` :
- Remplacer l'import `golang.org/x/sys/unix` par la constante littérale `uint32(0xFFF)`

#### 4. `agent/cmd/oseye-agent/main.go` — MODIFIER

**`func main()`**
- Ajouter après `config.Load()` :
  ```go
  hostname, _ := os.Hostname()
  agentIDStr := cfg.AgentID
  if agentIDStr == "" {
      agentIDStr = uuid.New().String()
  }
  agentIDBytes := []byte(agentIDStr)
  m := mapper.New(hostname, agentIDBytes)
  ```
- Passer `m`, `hostname`, `agentIDBytes` à la closure `sendBatch` (via capture ou paramètre)

**`func sendBatch(events []collector.RawEvent)`** (modifier la signature ou la closure)
- Pour chaque `e` dans `events` :
  1. `hashBytes := ch.Append(e.Raw)` — utiliser le raw bytes comme input de chaîne
  2. `pb, err := m.Map(e, hashBytes)` — obtenir l'event proto complet
  3. Si erreur : logger l'erreur, incrémenter un compteur, continuer avec un event minimal
  4. `protoBytes, _ := proto.Marshal(pb)` — sérialiser en proto (pas JSON)
  5. Accumuler `protoBytes` pour `buf.Push()`
  6. Accumuler `pb` pour la construction de `IngestRequest`
- Construire `batchSignature` sur les `pb.HashChain` de tous les events
- `buf.Push(allProtoBytes)` — stocker les proto bytes (pas JSON)
- Tenter l'envoi gRPC ; en cas d'échec, les données restent dans le buffer

**`func drainBuffer()`**
- `buf.Pop(500)` retourne des `[]byte` qui sont maintenant des proto bytes
- Pour chaque `payload` : `proto.Unmarshal(payload, &pb)` → event complet
- Reconstruire `IngestRequest` avec les events désérialisés
- Ne plus construire un event à la main avec uniquement `HashChain`

---

## M15 — Stockage proto dans le buffer

**Branche :** `M15/buffer-proto-storage`  
**Dépend de :** M14  
**Résout :** GAP-04  
**Durée estimée :** 0.5 jour

Ce module n'introduit pas de nouveau package. Il garantit que le format stocké dans SQLite est `proto.Marshal(UniversalEventPB)` et non du JSON brut, permettant un drain fidèle.

### Fichiers à modifier

#### `agent/internal/buffer/buffer.go` + `buffer_cgo.go`

Pas de modification de l'API — `Push` et `Pop` opèrent sur `[]byte` opaques. La responsabilité du format de sérialisation appartient à `main.go` (voir M14 ci-dessus).

#### `agent/internal/buffer/buffer_test.go` — MODIFIER

Ajouter `TestPushPopProtoRoundtrip` :
- Construire un `UniversalEventPB` complet avec tous les champs remplis
- `proto.Marshal` → `buf.Push` → `buf.Pop` → `proto.Unmarshal` → comparer avec l'original via `proto.Equal`

---

## M16 — Watchdog CPU/RAM

**Branche :** `M16/agent-watchdog`  
**Dépend de :** M14  
**Résout :** GAP-05  
**Durée estimée :** 1 jour

### Fichiers à créer / modifier

#### 1. `agent/internal/watchdog/watchdog.go` — NOUVEAU FICHIER

```go
//go:build linux

package watchdog
```

**Struct :**
```go
type Watchdog struct {
    maxCPUPct float64
    maxMemMB  float64
    manager   *collector.CollectorManager
    interval  time.Duration
    pid       int
}
```

**Fonctions :**

`func New(maxCPUPct, maxMemMB float64, mgr *collector.CollectorManager) *Watchdog`
- Initialise avec `interval = 5 * time.Second`, `pid = os.Getpid()`
- Le `CollectorManager` expose `SetThrottle(factor float64)` (à ajouter si absent)

`func (w *Watchdog) Run(ctx context.Context)`
- Goroutine principale : ticker à `w.interval`
- À chaque tick : lire CPU et RAM via `/proc/self/stat` et `/proc/self/status`
- Calculer le facteur de throttle :
  - Si CPU < 50% du max ET RAM < 50% du max : `throttle = 1.0`
  - Si CPU entre 50% et 100% du max : `throttle = 1.0 - (cpuPct / w.maxCPUPct) * 0.5`
  - Si CPU > max OU RAM > max : `throttle = 0.1` (réduction d'urgence)
- Appeler `w.manager.SetThrottle(throttle)` pour propager aux collecteurs

`func (w *Watchdog) readCPUPercent() (float64, error)`
- Lit `/proc/self/stat` champs `utime` (14) et `stime` (15)
- Calcule le delta entre deux lectures séparées par `w.interval`
- Formule : `cpuPct = (deltaJiffies / jiffiesPerSecond) / numCPU * 100`
- `jiffiesPerSecond` = 100 (valeur Linux standard, pas besoin de sysconf)
- `numCPU` = `runtime.NumCPU()`

`func (w *Watchdog) readMemMB() (float64, error)`
- Lit `/proc/self/status`, extrait la ligne `VmRSS:`
- Convertit en MB : `kB / 1024`

`func (w *Watchdog) prevCPUJiffies() uint64` — stocke l'état précédent pour le delta CPU

#### 2. `agent/internal/watchdog/watchdog_test.go` — NOUVEAU FICHIER

`func TestWatchdogThrottleCalculation(t *testing.T)` : vérifie la formule de throttle avec des valeurs CPU simulées (inject les valeurs via des champs de test, sans lire `/proc`)

`func TestWatchdogReadMemMB(t *testing.T)` : vérifie la lecture de `/proc/self/status` sur le process courant — `memMB > 0`

`func TestWatchdogRunContextCancellation(t *testing.T)` : démarre `Run(ctx)`, annule le contexte, vérifie que la goroutine se termine en < 2s

#### 3. `agent/internal/collector/manager.go` — MODIFIER

`func (m *CollectorManager) SetThrottle(factor float64)` — NOUVEAU
- Pour chaque collecteur dans `m.collectors` : `c.SetThrottle(factor)`
- `factor` est clamped dans `[0.0, 1.0]` : `if factor < 0 { factor = 0 }; if factor > 1 { factor = 1 }`

#### 4. `agent/cmd/oseye-agent/main.go` — MODIFIER

Dans `main()`, après la création du `CollectorManager` :
```go
wd := watchdog.New(cfg.MaxCPUPct, float64(cfg.MaxMemMB), mgr)
go wd.Run(ctx)
```

---

## M17 — Client Policy & Commands

**Branche :** `M17/agent-policy-commands`  
**Dépend de :** M14  
**Résout :** GAP-06  
**Durée estimée :** 1.5 jours

### Fichiers à créer

#### 1. `agent/internal/policy/client.go` — NOUVEAU FICHIER

```go
//go:build linux

package policy
```

**Struct :**
```go
type PolicyClient struct {
    svc        oseyev1.AgentServiceClient
    agentID    []byte
    onProfile  func(*oseyev1.SurveillanceProfilePB)
}
```

**Fonctions :**

`func NewClient(svc oseyev1.AgentServiceClient, agentID []byte, onProfile func(*oseyev1.SurveillanceProfilePB)) *PolicyClient`

`func (c *PolicyClient) Run(ctx context.Context)`
- Ouvre le stream `svc.ReceivePolicy(ctx, &oseyev1.PolicyRequest{AgentId: c.agentID})`
- Boucle `stream.Recv()` jusqu'à `ctx.Done()` ou `io.EOF`
- Pour chaque `SurveillanceProfilePB` reçu : appelle `c.onProfile(profile)` dans une goroutine séparée (non-bloquant)
- En cas d'erreur de stream : attente exponentielle (1s → 2s → 4s → 30s max) avant reconnexion
- Reconnexion = nouvel appel à `svc.ReceivePolicy(ctx, ...)`

#### 2. `agent/internal/policy/handler.go` — NOUVEAU FICHIER

**Struct :**
```go
type ProfileHandler struct {
    mgr     *collector.CollectorManager
    current atomic.Pointer[oseyev1.SurveillanceProfilePB]
    mu      sync.Mutex
}
```

**Fonctions :**

`func NewHandler(mgr *collector.CollectorManager) *ProfileHandler`

`func (h *ProfileHandler) Apply(profile *oseyev1.SurveillanceProfilePB)`
- Parse `profile.ConfigJson` en `map[string]interface{}`
- Si le champ `"throttle"` est présent (float64) : appelle `h.mgr.SetThrottle(throttle)`
- Si le champ `"collectors_enabled"` est une liste de strings : désactiver les collecteurs absents via `SetThrottle(0.0)` sur ceux qui ne sont pas dans la liste
- Stocke le profil courant via `h.current.Store(profile)`
- Logger le changement : `slog.Info("profile applied", "name", profile.Name, "version", profile.Version)`

#### 3. `agent/internal/commands/client.go` — NOUVEAU FICHIER

```go
//go:build linux

package commands
```

**Struct :**
```go
type CommandClient struct {
    svc        oseyev1.AgentServiceClient
    agentID    []byte
    mgr        *collector.CollectorManager
    bufferPath string
}
```

**Fonctions :**

`func NewClient(svc oseyev1.AgentServiceClient, agentID []byte, mgr *collector.CollectorManager) *CommandClient`

`func (c *CommandClient) Run(ctx context.Context)`
- Ouvre le stream `svc.StreamCommands(ctx, &oseyev1.CommandRequest{AgentId: c.agentID})`
- Boucle `stream.Recv()`
- Pour chaque `AgentCommand`, dispatche selon `cmd.CommandType` :
  - `"SET_THROTTLE"` → parse `payload_json` `{"factor": 0.5}`, appelle `c.mgr.SetThrottle(factor)`
  - `"RELOAD_PROFILE"` → log l'information (le profil arrive via ReceivePolicy)
  - `"TAKE_SNAPSHOT"` → log `slog.Info("snapshot requested")` (implémentation complète Phase 7)
  - commande inconnue → `slog.Warn("unknown command", "type", cmd.CommandType)`
- Reconnexion exponentielle identique à `PolicyClient.Run`

#### 4. `agent/cmd/oseye-agent/main.go` — MODIFIER

Dans `main()`, après `transport.New(...)` :
```go
profileHandler := policy.NewHandler(mgr)
policyClient := policy.NewClient(tr.ServiceClient(), agentIDBytes, profileHandler.Apply)
cmdClient := commands.NewClient(tr.ServiceClient(), agentIDBytes, mgr)
go policyClient.Run(ctx)
go cmdClient.Run(ctx)
```

Exposer `ServiceClient() oseyev1.AgentServiceClient` depuis `GRPCClient` (ajouter getter).

#### 5. `agent/internal/transport/grpc_client.go` — MODIFIER

`func (c *GRPCClient) ServiceClient() oseyev1.AgentServiceClient`
- Retourne `c.svc` (le champ existant de type `oseyev1.AgentServiceClient`)

---

## M18 — Normalizers Python Phase 2

**Branche :** `M18/server-normalizers-phase2`  
**Dépend de :** M13 (collecteurs implémentés)  
**Durée estimée :** 1 jour

### Fichiers à créer

Un adapter par collecteur Phase 2. Chacun suit le pattern déjà établi dans `server/oseye/normalizer/adapters/linux/`.

#### 1. `server/oseye/normalizer/adapters/linux/fanotify.py`

`class FanotifyAdapter(BaseAdapter):`

`def parse(self, raw_bytes: bytes, agent_meta: dict) -> UniversalEvent:`
- `payload = json.loads(raw_bytes)`
- `category = "file"`, `type = payload.get("event_type", "")` (ex: `"open"`, `"modify"`, `"close_write"`)
- `resource = payload.get("path", "")`
- `pid = payload.get("pid", -1)`
- `severity = "warning"` si `type in ("modify", "close_write")` else `"info"`
- Retourne un `UniversalEvent` complet

#### 2. `server/oseye/normalizer/adapters/linux/inotify.py`

`class InotifyAdapter(BaseAdapter):`

`def parse(self, raw_bytes: bytes, agent_meta: dict) -> UniversalEvent:`
- `payload = json.loads(raw_bytes)`
- `category = "file"`, `type = payload.get("event_type", "")`
- `resource = payload.get("full_path", "") or payload.get("base_path", "")`
- `severity = "warning"` si `type in ("create", "delete", "moved_from", "moved_to")` else `"info"`

#### 3. `server/oseye/normalizer/adapters/linux/netlink.py`

`class NetlinkAdapter(BaseAdapter):`

`def parse(self, raw_bytes: bytes, agent_meta: dict) -> UniversalEvent:`
- `payload = json.loads(raw_bytes)`
- `category = "network"`, `type = payload.get("event", "")` (`"new"` | `"closed"`)
- `src_ip`, `src_port` ← parser `payload["local_addr"]` (format `"ip:port"`) via `_split_addr()`
- `dst_ip`, `dst_port` ← parser `payload["remote_addr"]`
- `protocol = payload.get("proto", "")`
- `severity = "info"`

`def _split_addr(addr: str) -> tuple[str, int]:` — retourne `(ip, port)` en splittant sur le dernier `:`

#### 4. `server/oseye/normalizer/adapters/linux/journald.py`

`class JournaldAdapter(BaseAdapter):`

`def parse(self, raw_bytes: bytes, agent_meta: dict) -> UniversalEvent:`
- `payload = json.loads(raw_bytes)`
- `category = "log"`, `type = "journal_entry"`
- `resource = payload.get("unit", "")` (systemd unit)
- `severity = _map_priority(payload.get("priority", ""))` 
- `process_name = payload.get("comm", "") or payload.get("identifier", "")`
- `pid = payload.get("pid", -1)`

`def _map_priority(p: str) -> str:`
- `"0"` → `"critical"`, `"1"` → `"critical"`, `"2"` → `"critical"`, `"3"` → `"error"`
- `"4"` → `"warning"`, `"5"` → `"info"`, `"6"` → `"info"`, `"7"` → `"info"`
- valeur inconnue → `"info"`

#### 5. `server/oseye/normalizer/adapters/linux/syslog.py`

`class SyslogAdapter(BaseAdapter):`

`def parse(self, raw_bytes: bytes, agent_meta: dict) -> UniversalEvent:`
- `payload = json.loads(raw_bytes)`
- `category = "log"`, `type = "syslog_entry"`
- `resource = payload.get("program", "")`
- `severity = _map_severity(payload.get("severity", ""))`

`def _map_severity(s: str) -> str:`
- Mapper `"emergency"`, `"alert"`, `"critical"` → `"critical"` ; `"error"` → `"error"` ; `"warning"` → `"warning"` ; reste → `"info"`

#### 6. `server/oseye/normalizer/adapters/linux/udev.py`

`class UdevAdapter(BaseAdapter):`

`def parse(self, raw_bytes: bytes, agent_meta: dict) -> UniversalEvent:`
- `payload = json.loads(raw_bytes)`
- `category = "device"`, `type = payload.get("action", "")` (`"add"` | `"remove"`)
- `resource = payload.get("devpath", "")`
- `severity = "info"`

#### 7. `server/oseye/normalizer/engine.py` — MODIFIER

Dans `NormalizerEngine.__init__` (ou la méthode qui enregistre les adapters) :
```python
from oseye.normalizer.adapters.linux.fanotify import FanotifyAdapter
from oseye.normalizer.adapters.linux.inotify import InotifyAdapter
from oseye.normalizer.adapters.linux.netlink import NetlinkAdapter
from oseye.normalizer.adapters.linux.journald import JournaldAdapter
from oseye.normalizer.adapters.linux.syslog import SyslogAdapter
from oseye.normalizer.adapters.linux.udev import UdevAdapter

self._adapters[("linux", "fanotify")] = FanotifyAdapter().parse
self._adapters[("linux", "inotify")] = InotifyAdapter().parse
self._adapters[("linux", "netlink")] = NetlinkAdapter().parse
self._adapters[("linux", "journald")] = JournaldAdapter().parse
self._adapters[("linux", "syslog")] = SyslogAdapter().parse
self._adapters[("linux", "udev")] = UdevAdapter().parse
```

#### 8. Tests Python — NOUVEAUX FICHIERS

`server/tests/unit/normalizer/test_fanotify_adapter.py`  
`server/tests/unit/normalizer/test_inotify_adapter.py`  
`server/tests/unit/normalizer/test_netlink_adapter.py`  
`server/tests/unit/normalizer/test_journald_adapter.py`  
`server/tests/unit/normalizer/test_syslog_adapter.py`  
`server/tests/unit/normalizer/test_udev_adapter.py`

Pour chaque fichier de test :
- `test_parse_minimal(adapter)` : payload minimal valide → vérifie `category`, `type`, `collector`
- `test_parse_full(adapter)` : payload complet → vérifie tous les champs spécifiques
- `test_parse_missing_fields(adapter)` : payload `{}` → ne doit pas lever d'exception, les champs optionnels ont des valeurs par défaut

---

## M19 — Auditd collector complet

**Branche :** `M19/auditd-collector`  
**Dépend de :** M14  
**Durée estimée :** 2-3 jours  
**Note :** Requiert libaudit2 installé sur le système de build.

### Fichiers à modifier / créer

#### 1. `agent/internal/platform/linux/auditd/collector.go` — REMPLACER le stub

**Approche :** `exec.CommandContext("auditctl")` + lecture de `/var/log/audit/audit.log` via `tail -f` (approche sans CGO). L'approche CGO via `libaudit` est plus robuste mais nécessite une dépendance C externe.

**Approche retenue : sans CGO — lecture fichier audit.log**

```go
//go:build linux

package auditd
```

**Struct :**
```go
type AuditdCollector struct {
    logPath    string
    stopCh     chan struct{}
    running    atomic.Bool
    eventCount atomic.Int64
    errorCount atomic.Int64
    lastError  atomic.Value
    throttle   atomic.Value
}
```

**Fonctions :**

`func New() *AuditdCollector`
- `logPath = "/var/log/audit/audit.log"`
- Initialise `stopCh`, `throttle = 1.0`

`func (c *AuditdCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error`
- Ouvre `/var/log/audit/audit.log` avec `os.Open`
- Si le fichier n'existe pas : retourne `nil` après avoir logué un warning (auditd non installé)
- `file.Seek(0, io.SeekEnd)` — tail depuis la fin (ne rejouer pas l'historique)
- Boucle de lecture :
  - Lire une ligne via `bufio.Scanner`
  - Si `scanner.Scan()` retourne `false` : attente 100ms (fichier non encore mis à jour)
  - Appeler `c.parseLine(line)` → `(RawEvent, bool)`
  - Si `bool` true : envoyer sur `out`

`func (c *AuditdCollector) parseLine(line string) (collector.RawEvent, bool)`
- Format audit.log : `type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=59 ...`
- Parser les champs `key=value` après le premier `:` 
- Extraire : `type`, `timestamp_ns` (depuis `msg=audit(ts.ms:serial)` : `ts * 1e9 + ms * 1e6`), `syscall`, `pid`, `ppid`, `uid`, `gid`, `exe`, `comm`
- Retourner un `RawEvent` avec JSON : `{"type": ..., "syscall": ..., "pid": ..., "ppid": ..., "uid": ..., "gid": ..., "exe": ..., "comm": ...}`
- Retourner `false` si la ligne n'est pas parseable (vide, commentaire, type inconnu)

`func (c *AuditdCollector) parseTimestamp(msg string) int64`
- `msg` format : `"audit(1234567890.123:456)"`
- Extraire la partie entre `(` et `)` : `"1234567890.123:456"`
- Split sur `.` : secondes `1234567890`, split sur `:` pour millisecondes `123`
- Retourne `seconds*1e9 + milliseconds*1e6`

#### 2. `agent/internal/platform/linux/auditd/collector_test.go` — NOUVEAU FICHIER

`func TestParseLine_Syscall(t *testing.T)` : ligne SYSCALL complète → vérifie les champs extraits

`func TestParseLine_Empty(t *testing.T)` : ligne vide → retourne `false`

`func TestParseLine_UnknownType(t *testing.T)` : `type=PROCTITLE msg=...` → retourne `false` (types non traités)

`func TestParseTimestamp(t *testing.T)` : vérifie la conversion `audit(1234567890.123:456)` → nanoseconds

`func TestStartFileNotFound(t *testing.T)` : `logPath = "/nonexistent"` → `Start()` retourne `nil` sans erreur fatale

---

## M20 — eBPF collector

**Branche :** `M20/ebpf-collector`  
**Dépend de :** M14  
**Durée estimée :** 3-4 jours  
**Note :** Nécessite kernel ≥ 5.8, headers Linux, clang/llvm. Build tag `linux` uniquement. Utilise `github.com/cilium/ebpf`.

### Fichiers à créer

#### 1. `agent/internal/platform/linux/ebpf/programs/execve.bpf.c`

Programme eBPF qui s'attache à `tracepoint/syscalls/sys_enter_execve`.

Champs capturés :
- `pid`, `ppid`, `uid`, `gid` depuis `task_struct` courant
- `filename` (pointeur vers le path, 256 bytes max via `bpf_probe_read_str`)
- `comm` via `bpf_get_current_comm`
- `timestamp_ns` via `bpf_ktime_get_ns`

Map perf event : `BPF_MAP_TYPE_PERF_EVENT_ARRAY` nommée `execve_events`

Struct kernel → userspace :
```c
struct execve_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char  comm[16];
    char  filename[256];
};
```

#### 2. `agent/internal/platform/linux/ebpf/programs/openat.bpf.c`

Programme eBPF attaché à `tracepoint/syscalls/sys_enter_openat`.

Champs : `pid`, `uid`, `filename` (256 bytes), `flags` (O_RDONLY/O_WRONLY/O_RDWR), `timestamp_ns`, `comm`

Map perf event : `openat_events`

#### 3. `agent/internal/platform/linux/ebpf/programs/connect.bpf.c`

Programme eBPF attaché à `tracepoint/syscalls/sys_enter_connect`.

Champs : `pid`, `uid`, `comm`, `timestamp_ns`, `family` (AF_INET/AF_INET6), `dst_ip` (4 ou 16 bytes), `dst_port`

Map perf event : `connect_events`

#### 4. `agent/internal/platform/linux/ebpf/loader.go` — NOUVEAU FICHIER

```go
//go:build linux

package ebpf
```

**Struct :**
```go
type EBPFLoader struct {
    execveObjs  *execveObjects   // généré par bpf2go
    openatObjs  *openatObjects
    connectObjs *connectObjects
    readers     []*perf.Reader
}
```

**Fonctions :**

`func NewLoader() (*EBPFLoader, error)`
- Appelle `loadExecveObjects(&execveObjs, nil)` — bpf2go génère cette fonction
- Attache le programme au tracepoint : `link.Tracepoint("syscalls", "sys_enter_execve", execveObjs.HandleExecve, nil)`
- Pareil pour openat et connect
- Crée un `perf.NewReader(execveObjs.ExecveEvents, 4096*os.Getpagesize())` pour chaque map
- Retourne `(*EBPFLoader, nil)` ou une erreur si l'attachement échoue (kernel trop ancien, pas de CAP_BPF)

`func (l *EBPFLoader) ReadEvents(ctx context.Context) (<-chan EBPFEvent, error)`
- Crée un channel `out` de type `EBPFEvent` (struct intermédiaire)
- Lance 3 goroutines (une par reader) : `perf.Reader.Read()` → parse → envoi sur `out`
- Les goroutines s'arrêtent sur `ctx.Done()` ou erreur reader

`func (l *EBPFLoader) Close() error`
- Ferme tous les readers, links, et objects

#### 5. `agent/internal/platform/linux/ebpf/collector.go` — NOUVEAU FICHIER

```go
//go:build linux

package ebpf
```

**Struct :**
```go
type EBPFCollector struct {
    loader     *EBPFLoader
    stopCh     chan struct{}
    running    atomic.Bool
    eventCount atomic.Int64
    errorCount atomic.Int64
    lastError  atomic.Value
    throttle   atomic.Value
}
```

**Fonctions :**

`func New() *EBPFCollector`
- Ne crée pas encore le loader (initialisation paresseuse dans `Start`)

`func (c *EBPFCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error`
- Appelle `NewLoader()` — si erreur (pas de CAP_BPF) : logguer + retourner `nil` (ne pas crasher l'agent)
- Récupère le channel `ebpfCh` depuis `l.ReadEvents(ctx)`
- Boucle : pour chaque `EBPFEvent` reçu sur `ebpfCh` :
  - Sérialiser en JSON : `{"source": "ebpf", "event_type": event.Type, "pid": ..., ...}`
  - Envoyer sur `out chan<- collector.RawEvent`

`func (c *EBPFCollector) Stop() error`
- Ferme `c.stopCh`, appelle `c.loader.Close()` si loader non nil

`func (c *EBPFCollector) Name() string` → `"ebpf"`

#### 6. `agent/internal/platform/linux/ebpf/collector_test.go` — NOUVEAU FICHIER

`func TestEBPFCollectorStopIdempotent(t *testing.T)` : `Stop()` appelé deux fois ne panique pas

`func TestEBPFCollectorHealthBeforeStart(t *testing.T)` : `Health()` retourne `Running: false` avant `Start()`

`func TestEBPFCollectorStartNoCapBPF(t *testing.T)` : sur un système sans `CAP_BPF`, `Start()` retourne `nil` (dégradation gracieuse)

`func TestEBPFLoaderRequiresKernel(t *testing.T)` : si kernel < 5.8, skip proprement

#### 7. `agent/go.mod` — MODIFIER

Ajouter `github.com/cilium/ebpf v0.16.0` (ou la version la plus récente disponible).

---

## M21 — Tests de résilience

**Branche :** `M21/tests-resilience`  
**Dépend de :** M14-M20  
**Durée estimée :** 2 jours

### Fichiers à créer

#### 1. `agent/tests/resilience/grpc_outage_test.go` — NOUVEAU FICHIER

```go
//go:build linux

package resilience_test
```

`func TestAgentBuffersEventsWhenServerDown(t *testing.T)` :
- Démarrer un `grpc.Server` sur bufconn
- Envoyer 100 events
- Couper le serveur (`grpc.Server.Stop()`)
- Envoyer 100 events supplémentaires — vérifier qu'ils arrivent dans le buffer SQLite
- Redémarrer le serveur
- Appeler `drainBuffer()` — vérifier que les 100 events sont reçus par le nouveau serveur

`func TestDrainBufferPreservesAllFields(t *testing.T)` :
- Construire un `UniversalEventPB` avec tous les 32 champs populés
- `proto.Marshal` → `buf.Push` → serveur down → `drainBuffer`
- Le serveur reçoit un event avec tous les champs identiques via `proto.Equal`

`func TestBatcherFlushesOnContextCancel(t *testing.T)` :
- Envoyer 50 events (batchSize = 100 → pas encore flushé)
- Annuler le contexte
- Vérifier que les 50 events ont été flushés avant la fin

#### 2. Mise à jour `docs/PROGRESS.md`

Ajouter les entrées M14-M21 dans le tableau Phase 2 une fois chaque module terminé.

---

## Checklist de validation par module

Avant de merger chaque branche :

- [ ] `go build ./...` passe sans erreur
- [ ] `go test ./...` passe, couverture ≥ 80% sur le package modifié
- [ ] `go vet ./...` : 0 warning
- [ ] `golangci-lint run` (timeout 5m) : 0 finding
- [ ] Race detector : `go test -race ./...` passe
- [ ] Pour M18 (Python) : `mypy --strict server/oseye/normalizer/` : 0 erreur
- [ ] Pour M18 (Python) : `ruff check server/oseye/normalizer/` : 0 erreur
- [ ] CI GitHub Actions verte

---

## Ordre de développement recommandé

```
Semaine 1 : M14 (câblage + mapper) → M15 (buffer proto)
Semaine 2 : M16 (watchdog) en parallèle de M18 (normalizers Python)
Semaine 2 : M17 (policy+commands) — peut démarrer en même temps que M16
Semaine 3 : M19 (auditd) — indépendant des semaines 1-2
Semaine 4 : M20 (eBPF) — le plus complexe
Semaine 5 : M21 (tests résilience) — requiert M14-M20
```

---

## M22 — Rule Engine Phase 3 `[x]` — mergé 2026-08-07

**Branche :** `M22/rule-engine`  
**Commit :** `314f1f1`  
**Dépend de :** Phase 2 complète

### Fichiers livrés

| Fichier | Description |
|---------|-------------|
| `server/oseye/rule_engine/models.py` | `RuleDefinition`, `RuleMatch` (dataclasses) |
| `server/oseye/rule_engine/parser.py` | Chargement YAML builtin+custom, override custom sur builtin, validation stricte |
| `server/oseye/rule_engine/evaluator.py` | Sandbox AST, `contains`, `re.match`, `count_events()` sliding window |
| `server/oseye/rule_engine/engine.py` | `RuleEngine` thread-safe, hot-reload polling, `evaluate()` → `list[RuleMatch]` |
| `server/oseye/workers/rule_worker.py` | Consomme `events:normalized`, publie `analysis:rules:{host}`, crée `Alert` en DB |
| `rules/builtin/credential_access.yaml` | 5 règles : shadow_read, passwd_write, ssh_key_theft, memory_dump, ssh_bruteforce |
| `rules/builtin/privilege_escalation.yaml` | 5 règles : suid, sudo_abuse, setcap, ptrace, polkit |
| `rules/builtin/persistence.yaml` | 5 règles : crontab, systemd_service, rc_local, authorized_keys, ld_preload |
| `rules/builtin/defense_evasion.yaml` | 5 règles : log_deletion, history_clear, timestomp, selinux_disable, rootkit |
| `rules/builtin/lateral_movement.yaml` | 5 règles : ssh_lateral, port_scan, rsync_exfil, nfs_smb_mount, rdp_tunneling |
| `rules/builtin/discovery.yaml` | 5 règles : recon_enum, network_discovery, process_discovery, sensitive_files, sudo_l |
| `rules/builtin/impact_c2.yaml` | 5 règles : reverse_shell, cryptomining, data_destruction, download_exec, c2_beaconing |
| `server/tests/unit/test_rule_engine.py` | 34 tests : parser, evaluator, temporal, engine, hot-reload, worker |

**Tests :** 34 py — 161 total (0 régression) · ruff 0 · mypy strict 0

---

## M23 — API Rules + WebSocket Alerts `[ ]` — à démarrer

**Branche :** `M23/api-rules-ws-alerts`  
**Dépend de :** M22

### Tâches (P3.09 à P3.11)

- [ ] `api/routers/rules.py` : `GET /rules`, `GET /rules/{id}`, `POST /rules/validate`, `POST /rules/reload`
- [ ] `api/routers/alerts.py` : enrichir l'existant — `POST /alerts/{id}/acknowledge`, `POST /alerts/{id}/false-positive`, `GET /alerts/stats`
- [ ] `api/ws/manager.py` : broadcast `WS /ws/alerts` quand une alerte est créée par le RuleWorker
- [ ] Câbler `RuleWorker` dans `main.py` server (démarrage au boot)
- [ ] Tests : ≥ 15 tests pour les nouveaux endpoints + WS
