# OSEye Plugin SDK

Python SDK for building OSEye plugins.

## Install

```bash
pip install oseye-sdk
```

Or in development (from the repo):

```bash
pip install -e sdk/
```

## Plugin types

| Class | Purpose |
|-------|---------|
| `AnalyzerPlugin` | Receives events, returns enrichments |
| `ExporterPlugin` | Sends events to external systems |
| `CollectorPlugin` | Produces custom events |

## Quick start

```python
from oseye_sdk.plugin import ExporterPlugin
from oseye_sdk.event import Event

class MyExporter(ExporterPlugin):
    name = "my_exporter"

    def on_start(self) -> None: ...
    def on_stop(self) -> None: ...

    def export(self, event: Event) -> None:
        if event.severity == "critical":
            print(f"ALERT: {event.hostname} — {event.category}/{event.type}")
```
