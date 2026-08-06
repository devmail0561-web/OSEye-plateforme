# Skill : OSEye — Créer un Worker de traitement

## Quand utiliser ce skill
Invoquer avec `/oseye-worker` quand l'utilisateur demande d'implémenter un des workers de traitement du pipeline OSEye (rule_worker, ml_worker, ti_worker, correlation_worker, decision_worker) ou un nouveau worker custom.

---

## Ce que tu dois faire

Tu crées un worker Python conforme au pattern `GracefulWorker` de `docs/ARCHITECTURE.md` §3.11 et §12.4.

### Étape 1 — Identifier le worker

Si non fourni :
- **Nom du worker** : ex `rule_worker`, `my_custom_worker`
- **Topic(s) consommés** : ex `events:normalized`
- **Topic(s) produits** : ex `analysis:rules:{host}`
- **Est-il stateful ?** (garde un état en mémoire entre les messages — comme ml_worker avec les modèles River)

### Étape 2 — Créer le fichier worker

```
server/oseye/workers/<worker_name>.py
```

**Template complet :**

```python
# server/oseye/workers/<worker_name>.py
import asyncio
import signal
import logging
from typing import AsyncIterator

from oseye.bus.interface import EventBus
from oseye.core.schema import UniversalEvent
from oseye.core.observability import get_logger
from oseye.config import Settings

logger = get_logger(__name__)
# NOTE: get_tracer n'est pas encore implémenté — ne pas importer


class <Name>Worker:
    """
    Consomme <input_topic>, traite, publie sur <output_topic>.
    Entry point : python -m oseye.workers.<worker_name>
    """

    CONSUME_TOPICS = ["<input_topic>"]
    PRODUCE_TOPIC  = "<output_topic>"
    DLQ_TOPIC      = "events:dlq:<worker_name>"
    MAX_RETRIES    = 3

    def __init__(self, bus: EventBus, settings: Settings):
        self._bus = bus
        self._settings = settings
        self._shutdown = asyncio.Event()

    # ------------------------------------------------------------------ #
    # Lifecycle                                                            #
    # ------------------------------------------------------------------ #

    async def run(self) -> None:
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGTERM, self._shutdown.set)
        loop.add_signal_handler(signal.SIGINT, self._shutdown.set)

        logger.info("worker_started", worker="<worker_name>")
        try:
            await asyncio.gather(
                self._consume_loop(),
                self._shutdown_monitor(),
            )
        finally:
            await self._flush()
            logger.info("worker_stopped", worker="<worker_name>")

    async def _shutdown_monitor(self) -> None:
        await self._shutdown.wait()

    async def _flush(self) -> None:
        """Flush tout état en attente avant l'arrêt."""
        pass  # override si stateful

    # ------------------------------------------------------------------ #
    # Consommation                                                         #
    # ------------------------------------------------------------------ #

    async def _consume_loop(self) -> None:
        async for topic, raw in self._bus.subscribe_pattern("<input_pattern>"):
            if self._shutdown.is_set():
                break
            await self._handle_with_retry(topic, raw)

    async def _handle_with_retry(self, topic: str, raw: bytes) -> None:
        for attempt in range(self.MAX_RETRIES):
            try:
                await self._handle(topic, raw)
                return
            except Exception as exc:
                if attempt == self.MAX_RETRIES - 1:
                    logger.error(
                        "dlq_sent",
                        worker="<worker_name>",
                        error=str(exc),
                        attempt=attempt + 1,
                    )
                    await self._send_to_dlq(raw, str(exc), attempt + 1)

    async def _handle(self, topic: str, raw: bytes) -> None:
        """Traitement principal — à implémenter."""
        # 1. Désérialiser — FAST PATH: Pydantic v2 Rust parser (~2x plus rapide)
        # Utiliser model_validate_json si le payload n'est pas modifié avant validation.
        # Utiliser model_validate(dict) SEULEMENT si une modification du payload est nécessaire.
        event = UniversalEvent.model_validate_json(raw)

        # 2. Traiter
        result = await self._process(event)
        if result is None:
            return

        # 3. Publier
        await self._bus.publish(
            self.PRODUCE_TOPIC,
            result.model_dump_json().encode(),
        )

    async def _process(self, event: UniversalEvent):
        """Logique métier pure — retourne l'objet à publier ou None."""
        raise NotImplementedError

    async def _send_to_dlq(self, raw: bytes, error: str, attempts: int) -> None:
        import json, datetime
        entry = {
            "original_topic": self.CONSUME_TOPICS[0],
            "original_message": raw.hex(),
            "error": error,
            "attempts": attempts,
            "last_failed_at": datetime.datetime.utcnow().isoformat(),
            "worker": "<worker_name>",
        }
        await self._bus.publish(self.DLQ_TOPIC, json.dumps(entry).encode())


# ------------------------------------------------------------------ #
# Entry point                                                          #
# ------------------------------------------------------------------ #

async def main() -> None:
    from oseye.config import get_settings  # lru_cache — ne pas appeler Settings() directement
    from oseye.bus import create_bus
    from oseye.core.observability import setup_observability

    settings = get_settings()
    setup_observability("<worker_name>", settings.OSEYE_OTEL_ENDPOINT)
    bus = await create_bus(settings)

    worker = <Name>Worker(bus, settings)
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
```

### Étape 3 — Implémenter `_process`

C'est la seule méthode à remplir pour un worker simple :

```python
async def _process(self, event: UniversalEvent):
    # Exemple pour rule_worker :
    matches = await self.rule_engine.evaluate(event)
    if not matches:
        return None
    return RuleAnalysis(
        event_id=event.event_id,
        hostname=event.hostname,
        matches=matches,
    )
```

### Étape 4 — Worker stateful (ex: ml_worker)

Pour les workers qui maintiennent un état (modèles ML, journal hash chain), override `_flush` :

```python
async def _flush(self) -> None:
    """Sauvegarde l'état avant shutdown — appelé par GracefulWorker."""
    await self.model_store.checkpoint_all()
    logger.info("models_checkpointed", count=len(self._models))
```

Et ajouter un checkpoint périodique en tâche de fond :

```python
async def run(self) -> None:
    # ...
    await asyncio.gather(
        self._consume_loop(),
        self._checkpoint_loop(),   # toutes les 15 min
        self._shutdown_monitor(),
    )

async def _checkpoint_loop(self) -> None:
    while not self._shutdown.is_set():
        await asyncio.sleep(900)  # 15 min
        await self.model_store.checkpoint_all()
```

### Étape 5 — Enregistrer dans le runner dev (monolithe)

```python
# server/oseye/core/runner.py
from oseye.workers.<worker_name> import <Name>Worker

async def run_all():
    await asyncio.gather(
        # ... workers existants ...
        <Name>Worker(bus, settings).run(),
    )
```

### Étape 6 — Ajouter le Deployment K8s

```yaml
# infra/k8s/server/<worker_name>-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oseye-worker-<worker_name>
  namespace: oseye-system
spec:
  replicas: 1   # 2 si stateless, 1 si stateful
  template:
    spec:
      containers:
        - name: worker
          image: ghcr.io/oseye/server:latest
          command: ["python", "-m", "oseye.workers.<worker_name>"]
          env:
            - name: OSEYE_BUS_BACKEND
              value: "redis"
```

### Étape 7 — Tests

```python
# server/tests/unit/workers/test_<worker_name>.py
import pytest
from unittest.mock import AsyncMock
from oseye.workers.<worker_name> import <Name>Worker

@pytest.mark.asyncio
async def test_process_produces_output(mock_bus, sample_event):
    worker = <Name>Worker(mock_bus, settings)
    result = await worker._process(sample_event)
    assert result is not None

@pytest.mark.asyncio
async def test_dlq_on_repeated_failure(mock_bus, bad_event):
    worker = <Name>Worker(mock_bus, settings)
    # Provoquer 3 échecs successifs
    await worker._handle_with_retry("topic", bad_event.model_dump_json().encode())
    mock_bus.publish.assert_called_with(worker.DLQ_TOPIC, ...)
```

---

## Contraintes à respecter

- **Hot path** : utiliser `model_validate_json(raw)` — jamais `json.loads(raw)` + `model_validate(dict)` sauf si le payload doit être modifié avant validation
- Imports au niveau module, jamais dans les fonctions (sauf cas exceptionnel documenté)
- Depuis un thread gRPC, publier sur le bus via `asyncio.get_running_loop().call_soon_threadsafe(asyncio.ensure_future, coro)`
- Toujours implémenter `_flush` pour les workers stateful (ML models, journal hash)
- La DLQ doit recevoir le message original intact (pas le parsé) — pour pouvoir rejouer
- `SIGTERM` → drain → flush → exit 0 sans exception non catchée
- Un worker ne doit **jamais** écrire directement en DB — il passe par le bus ou l'API
- Exception : `decision_worker` écrit le journal hash chain via `DecisionJournal` (composant dédié)
- Référence : `docs/ARCHITECTURE.md` §3.11, §12.1, §12.4
