# Skill : OSEye — Créer un nouveau Collector

## Quand utiliser ce skill
Invoquer avec `/oseye-collector` quand l'utilisateur demande d'ajouter un nouveau collecteur de données dans l'agent Go, que ce soit pour Linux (eBPF, auditd, fanotify...), Windows (ETW, WinLog...) ou macOS (EndpointSecurity, FSEvents...).

---

## Ce que tu dois faire

Tu crées un nouveau collector pour l'agent OSEye en respectant l'architecture définie dans `docs/ARCHITECTURE.md`.

### Étape 1 — Identifier l'OS cible et le nom du collector

Si non fournis par l'utilisateur, demander :
- L'OS cible : `linux` | `windows` | `darwin`
- Le nom du collector (snake_case, ex: `fanotify`, `etw`, `fsevents`)
- La source de données kernel/OS qu'il consomme

### Étape 2 — Créer les fichiers

**Structure :**
```
agent/internal/platform/<os>/<collector_name>/
├── collector.go     # implémentation principale
└── parser.go        # parsing du payload brut → RawEvent
```

**`collector.go` — template :**

```go
//go:build <os>

package <collector_name>

import (
    "context"
    "sync/atomic"
    "github.com/oseye/agent/internal/collector"
)

// Vérifie statiquement que <Name>Collector satisfait l'interface.
var _ collector.Collector = (*<Name>Collector)(nil)

type <Name>Collector struct {
    cfg        *Config
    stopCh     chan struct{}
    running    atomic.Bool
    eventCount atomic.Uint64
    errorCount atomic.Uint64
    lastError  atomic.Value // stores string
    throttle   atomic.Value // stores float64
}

func New(cfg *Config) *<Name>Collector {
    c := &<Name>Collector{cfg: cfg, stopCh: make(chan struct{})}
    c.throttle.Store(1.0)
    return c
}

// Name implémente collector.Collector
func (c *<Name>Collector) Name() string { return "<collector_name>" }

// Start implémente collector.Collector — bloque jusqu'à ctx.Done() ou Stop()
func (c *<Name>Collector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
    c.running.Store(true)
    defer c.running.Store(false)
    // TODO: initialiser la source kernel/OS
    for {
        select {
        case <-ctx.Done():
            return nil
        case <-c.stopCh:
            return nil
        default:
            // TODO: lire événements, parser, envoyer sur out
            // raw := c.parser.parse(kernelEvent)
            // out <- collector.RawEvent{
            //     Source:    c.Name(),
            //     OS:        "<os>",
            //     Timestamp: time.Now().UnixNano(),
            //     Raw:       raw,
            // }
            // c.eventCount.Add(1)
        }
    }
}

// Stop implémente collector.Collector — idempotent (anti double-close)
func (c *<Name>Collector) Stop() error {
    select {
    case <-c.stopCh:
        // déjà fermé
    default:
        close(c.stopCh)
    }
    return nil
}

// SetThrottle implémente collector.Collector — 0.0 = inactif, 1.0 = plein débit
func (c *<Name>Collector) SetThrottle(factor float64) {
    c.throttle.Store(factor)
    // TODO: propager au sous-système kernel si applicable
}

// Health implémente collector.Collector
func (c *<Name>Collector) Health() collector.CollectorHealth {
    lastErr, _ := c.lastError.Load().(string)
    throttlePct, _ := c.throttle.Load().(float64)
    return collector.CollectorHealth{
        Running:     c.running.Load(),
        EventsTotal: int64(c.eventCount.Load()),
        ErrorCount:  int64(c.errorCount.Load()),
        ThrottlePct: throttlePct,
        LastError:   lastErr,
    }
}
```

### Étape 3 — Enregistrer dans le PlatformDriver

Ajouter le collector dans `agent/internal/platform/<os>/driver.go` :

```go
func (d *<OS>Driver) Collectors(cfg *config.Config) ([]collector.Collector, error) {
    return []collector.Collector{
        // ... collectors existants ...
        <collector_name>.New(cfg),   // <-- ajouter ici
    }, nil
}
```

### Étape 4 — Créer l'adapter normalizer (Python)

Créer `server/oseye/normalizer/adapters/<os>/<collector_name>.py` :

```python
from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.base import BaseAdapter

class <Name>Adapter(BaseAdapter):
    """Normalize raw <collector_name> events to UniversalEvent."""

    def parse(self, raw_bytes: bytes, agent_meta: dict) -> UniversalEvent:
        # TODO: parser raw_bytes selon le format du collector
        payload = ...
        return UniversalEvent(
            category=...,   # "file" | "process" | "network" | "user" | "device"
            type=...,       # ex: "open", "exec", "connect"
            severity="info",
            collector="<collector_name>",
            hostname=agent_meta["hostname"],
            agent_id=agent_meta["agent_id"],
            timestamp_ns=payload.get("timestamp_ns"),
            uid=payload.get("uid", -1),
            gid=payload.get("gid", -1),
            pid=payload.get("pid", -1),
            ppid=payload.get("ppid", -1),
            process_name=payload.get("process_name", ""),
            executable=payload.get("executable", ""),
            cmdline=payload.get("cmdline", ""),
            resource=payload.get("resource", ""),
            result=payload.get("result", "success"),
            extra=payload,
        )
```

Enregistrer dans `NormalizerEngine.__init__` :
```python
# Stocker le callable directement (clé : (os_name, source))
from oseye.normalizer.adapters.<os>.<collector_name> import <Name>Adapter
_adapter = <Name>Adapter()
self._adapters[("<os>", "<collector_name>")] = _adapter.parse
```

### Étape 5 — Tests

Créer `agent/internal/platform/<os>/<collector_name>/collector_test.go` :
- Test `Start` avec mock de la source kernel
- Test `SetThrottle` : vérifier que le sampling est réduit
- Test `Stop` : vérifier l'arrêt propre (appeler deux fois — idempotent, ne doit pas paniquer)
- **Skip si CAP_SYS_ADMIN manquant** pour les collecteurs kernel (fanotify, eBPF, auditd) :
  ```go
  func requireCAP(t *testing.T) {
      if os.Getuid() != 0 {
          t.Skip("requires CAP_SYS_ADMIN — run as root or in privileged container")
      }
  }
  ```
- Pour inotify, vérifier la disponibilité avant de skip :
  ```go
  func requireInotify(t *testing.T) {
      fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
      if err != nil {
          t.Skipf("inotify unavailable: %v", err)
      }
      unix.Close(fd)
  }
  ```

Créer `server/tests/unit/normalizer/test_<collector_name>.py` :
- Test `parse` avec payload synthétique → vérifier chaque champ de `UniversalEvent`

### Étape 6 — Mettre à jour le plan d'action

Marquer la tâche correspondante `[x]` dans `docs/PLAN_ACTION.md`.

---

## Contraintes à respecter

- Le build tag `//go:build <os>` doit être en première ligne de chaque fichier Go
- `RawEvent.OS` doit toujours être positionné (`"linux"` | `"windows"` | `"darwin"`)
- Aucune logique métier dans le collector — il produit uniquement des `RawEvent` bruts
- Le collector ne doit jamais crasher silencieusement — les erreurs non-fatales se loggent avec le logger OTel structuré JSON
- CPU watchdog : `SetThrottle(0.0)` doit stopper toute activité kernel (pas juste ignorer les events)
- Référence : `docs/ARCHITECTURE.md` §3.1, §3.11
