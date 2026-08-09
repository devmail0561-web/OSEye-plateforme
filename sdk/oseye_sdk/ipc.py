from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Self

from oseye_sdk.event import Event

DEFAULT_SOCKET_PATH = "/var/run/oseye/plugin.sock"


class IPCClient:
    """Async Unix socket client used by plugins to receive events from the server.

    Protocol: newline-delimited JSON (NDJSON).  Each line sent by the server is
    one serialised event dict; each line sent by the client is one result dict.
    """

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH) -> None:
        self._socket_path = socket_path
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect(self) -> None:
        """Open the Unix socket connection."""
        self._reader, self._writer = await asyncio.open_unix_connection(
            self._socket_path
        )

    async def close(self) -> None:
        """Close the connection gracefully."""
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except OSError:
                pass
            self._writer = None
            self._reader = None

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def receive_events(self) -> AsyncGenerator[Event, None]:
        """Async generator: yield Event objects as they arrive from the server."""
        if self._reader is None:
            raise RuntimeError("IPCClient is not connected — call connect() first")
        while True:
            line = await self._reader.readline()
            if not line:
                break
            line = line.rstrip(b"\n")
            if not line:
                continue
            try:
                data = json.loads(line)
                yield Event.from_dict(data)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                # Malformed frame — skip silently to keep the stream alive
                continue

    async def send_result(self, result: dict) -> None:
        """Send an enrichment result back to the server (JSON + newline)."""
        if self._writer is None:
            raise RuntimeError("IPCClient is not connected — call connect() first")
        payload = json.dumps(result, default=str) + "\n"
        self._writer.write(payload.encode())
        await self._writer.drain()


# ---------------------------------------------------------------------------
# Server side
# ---------------------------------------------------------------------------


class IPCServer:
    """Async Unix socket server — server-side, sends events to plugins."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH) -> None:
        self._socket_path = socket_path
        self._server: asyncio.AbstractServer | None = None
        # Each entry: (reader, writer) for one connected plugin client
        self._clients: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        # Queue used by receive_results to surface inbound result dicts
        self._result_queue: asyncio.Queue[dict] = asyncio.Queue()

    async def start(self) -> None:
        """Start listening on the Unix socket."""
        socket_dir = Path(self._socket_path).parent
        socket_dir.mkdir(parents=True, exist_ok=True)
        # Remove stale socket file if present
        try:
            os.unlink(self._socket_path)
        except FileNotFoundError:
            pass
        self._server = await asyncio.start_unix_server(
            self._handle_client, path=self._socket_path
        )

    async def stop(self) -> None:
        """Stop accepting connections and close all client sockets."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for _, writer in list(self._clients):
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        self._clients.clear()
        try:
            os.unlink(self._socket_path)
        except FileNotFoundError:
            pass

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Background task: read result lines from one connected plugin."""
        entry = (reader, writer)
        self._clients.append(entry)
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                line = line.rstrip(b"\n")
                if not line:
                    continue
                try:
                    result = json.loads(line)
                    await self._result_queue.put(result)
                except (json.JSONDecodeError, ValueError):
                    continue
        finally:
            self._clients.remove(entry)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def broadcast_event(self, event: Event) -> None:
        """Send event to all connected plugin clients (NDJSON line)."""
        if not self._clients:
            return
        # Serialise Event to a plain dict
        payload = json.dumps(
            {
                "event_id": event.event_id,
                "timestamp_ns": event.timestamp_ns,
                "hostname": event.hostname,
                "category": event.category,
                "type": event.type,
                "severity": event.severity,
                "process_name": event.process_name,
                "pid": event.pid,
                "uid": event.uid,
                "resource": event.resource,
                "dst_ip": event.dst_ip,
                "dst_port": event.dst_port,
                "ml_score": event.ml_score,
                "mitre_techniques": list(event.mitre_techniques),
            }
        ) + "\n"
        encoded = payload.encode()
        dead: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        for reader, writer in list(self._clients):
            try:
                writer.write(encoded)
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                dead.append((reader, writer))
        for entry in dead:
            try:
                self._clients.remove(entry)
            except ValueError:
                pass

    async def receive_results(self) -> AsyncGenerator[dict, None]:
        """Async generator: yield result dicts sent back by plugin clients."""
        while True:
            result = await self._result_queue.get()
            yield result
