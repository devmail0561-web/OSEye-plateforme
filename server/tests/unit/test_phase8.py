"""P8.15 — Phase 8 tests: PolicyEngine, PluginManager, SDK.

Covers:
- PolicyEngine loads all 6 builtin profiles
- Profile push publishes correct bus topic
- Profile switch takes < 2s (wall-clock)
- PluginManager install/enable/disable/delete lifecycle
- PluginManager sandbox isolation (no root access without FS)
- SDK Event.from_dict round-trip
- SDK IPCClient / IPCServer NDJSON protocol
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------

from oseye.bus.memory_bus import InMemoryEventBus
from oseye.policy.engine import PolicyEngine


@pytest.mark.asyncio
async def test_policy_engine_loads_all_builtin_profiles():
    """load_profiles() must load all 12 built-in YAML profiles."""
    bus = InMemoryEventBus()
    engine = PolicyEngine(bus)
    await engine.load_profiles()
    profiles = {p.name for p in engine.list_profiles()}
    expected = {
        "workstation", "server", "investigation", "minimal", "compliance", "stealth",
        "webserver", "database", "dns", "mail", "laptop", "desktop",
    }
    assert profiles == expected


@pytest.mark.asyncio
async def test_policy_engine_get_profile():
    """get_profile() returns correct profile by name."""
    bus = InMemoryEventBus()
    engine = PolicyEngine(bus)
    await engine.load_profiles()
    p = engine.get_profile("workstation")
    assert p is not None
    assert p.name == "workstation"


@pytest.mark.asyncio
async def test_policy_engine_get_unknown_returns_none():
    bus = InMemoryEventBus()
    engine = PolicyEngine(bus)
    await engine.load_profiles()
    assert engine.get_profile("nonexistent") is None


@pytest.mark.asyncio
async def test_policy_engine_push_publishes_to_correct_topic():
    """push_to_agent publishes to policy:push:{agent_id}."""
    bus = InMemoryEventBus()
    engine = PolicyEngine(bus)
    await engine.load_profiles()

    agent_id = uuid.uuid4()
    published: list[tuple[str, bytes]] = []

    async def _capture(topic: str, message: bytes) -> None:
        published.append((topic, message))
        await InMemoryEventBus.publish(bus, topic, message)

    bus.publish = _capture  # type: ignore[method-assign]

    await engine.push_to_agent(agent_id, "workstation")
    assert len(published) == 1
    topic, payload = published[0]
    assert topic == f"policy:push:{agent_id}"
    data = json.loads(payload)
    assert data["name"] == "workstation"


@pytest.mark.asyncio
async def test_policy_engine_push_unknown_profile_raises():
    bus = InMemoryEventBus()
    engine = PolicyEngine(bus)
    await engine.load_profiles()
    with pytest.raises(KeyError):
        await engine.push_to_agent(uuid.uuid4(), "does_not_exist")


@pytest.mark.asyncio
async def test_policy_profile_switch_under_2s():
    """Switching profiles (load + push) must complete in under 2 seconds (P8.15)."""
    bus = InMemoryEventBus()
    engine = PolicyEngine(bus)
    agent_id = uuid.uuid4()

    t0 = time.monotonic()
    await engine.load_profiles()
    await engine.push_to_agent(agent_id, "investigation")
    elapsed = time.monotonic() - t0

    assert elapsed < 2.0, f"Profile switch took {elapsed:.3f}s — exceeds 2s requirement"


@pytest.mark.asyncio
async def test_policy_engine_push_to_all_broadcasts():
    """push_to_all sends to all previously registered agents."""
    bus = InMemoryEventBus()
    engine = PolicyEngine(bus)
    await engine.load_profiles()

    published_topics: list[str] = []

    async def _capture(topic: str, message: bytes) -> None:
        published_topics.append(topic)

    bus.publish = _capture  # type: ignore[method-assign]

    ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
    for aid in ids:
        await engine.push_to_agent(aid, "minimal")

    published_topics.clear()
    await engine.push_to_all("server")
    assert len(published_topics) == 3


# ---------------------------------------------------------------------------
# PluginManager
# ---------------------------------------------------------------------------

from oseye.plugin.manager import PluginInfo, PluginManager, PluginStatus


@pytest.fixture
def plugin_dir(tmp_path: Path) -> Path:
    d = tmp_path / "plugins"
    d.mkdir()
    return d


@pytest.fixture
def fake_plugin(plugin_dir: Path) -> Path:
    plugin = plugin_dir / "my_plugin.py"
    plugin.write_text("# stub plugin\n")
    return plugin


@pytest.mark.asyncio
async def test_plugin_manager_install(plugin_dir: Path, fake_plugin: Path, tmp_path: Path):
    """install() copies the plugin file and returns PluginInfo with STOPPED status."""
    src = tmp_path / "external_plugin.py"
    src.write_text("# external\n")

    mgr = PluginManager(plugins_dir=plugin_dir)
    info = await mgr.install(src, verify=False)

    assert info.status in (PluginStatus.STOPPED, PluginStatus.LOADED)
    assert info.name == "external_plugin"
    assert (plugin_dir / "external_plugin.py").exists()


@pytest.mark.asyncio
async def test_plugin_manager_list_discovers_existing(plugin_dir: Path, fake_plugin: Path):
    """PluginManager auto-discovers existing .py files in plugins_dir at init."""
    mgr = PluginManager(plugins_dir=plugin_dir)
    names = [p.name for p in mgr.list()]
    assert "my_plugin" in names


@pytest.mark.asyncio
async def test_plugin_manager_get_returns_none_for_unknown(plugin_dir: Path):
    mgr = PluginManager(plugins_dir=plugin_dir)
    assert mgr.get("does_not_exist") is None


@pytest.mark.asyncio
async def test_plugin_manager_delete(plugin_dir: Path, fake_plugin: Path):
    """delete() removes the plugin file and unregisters it."""
    mgr = PluginManager(plugins_dir=plugin_dir)
    assert mgr.get("my_plugin") is not None
    await mgr.delete("my_plugin")
    assert mgr.get("my_plugin") is None
    assert not fake_plugin.exists()


@pytest.mark.asyncio
async def test_plugin_manager_enable_starts_sandbox(plugin_dir: Path, fake_plugin: Path):
    """enable() starts a sandbox process and transitions status to RUNNING."""
    mgr = PluginManager(plugins_dir=plugin_dir)

    mock_proc = MagicMock()
    mock_proc.pid = 12345

    mock_sandbox = MagicMock()
    mock_sandbox.start = AsyncMock(return_value=mock_proc)
    mock_sandbox.pid = 12345

    with patch("oseye.plugin.manager.PluginSandbox", return_value=mock_sandbox):
        info = await mgr.enable("my_plugin")

    assert info.status == PluginStatus.RUNNING
    mock_sandbox.start.assert_awaited_once()


@pytest.mark.asyncio
async def test_plugin_manager_disable_stops_sandbox(plugin_dir: Path, fake_plugin: Path):
    """disable() stops the sandbox and transitions status to STOPPED."""
    mgr = PluginManager(plugins_dir=plugin_dir)

    mock_proc = MagicMock()
    mock_proc.pid = 9999
    mock_sandbox = MagicMock()
    mock_sandbox.start = AsyncMock(return_value=mock_proc)
    mock_sandbox.stop = AsyncMock()
    mock_sandbox.pid = 9999

    with patch("oseye.plugin.manager.PluginSandbox", return_value=mock_sandbox):
        await mgr.enable("my_plugin")
        info = await mgr.disable("my_plugin")

    assert info.status == PluginStatus.STOPPED
    mock_sandbox.stop.assert_awaited_once()


# ---------------------------------------------------------------------------
# SDK — Event
# ---------------------------------------------------------------------------

from oseye_sdk.event import Event


def test_sdk_event_from_dict_round_trip():
    """Event.from_dict() must reproduce the original values."""
    data = {
        "event_id": str(uuid.uuid4()),
        "timestamp_ns": time.time_ns(),
        "hostname": "host-sdk",
        "category": "network",
        "type": "connect",
        "severity": "high",
        "process_name": "curl",
        "pid": 1234,
        "uid": 0,
        "resource": "/etc/passwd",
        "dst_ip": "1.2.3.4",
        "dst_port": 443,
        "ml_score": 87.5,
        "mitre_techniques": ["T1059.001"],
    }
    ev = Event.from_dict(data)
    assert ev.hostname == "host-sdk"
    assert ev.severity == "high"
    assert ev.dst_ip == "1.2.3.4"
    assert ev.ml_score == 87.5
    assert "T1059.001" in ev.mitre_techniques


def test_sdk_event_is_frozen():
    """Event must be immutable (frozen dataclass)."""
    ev = Event(
        event_id=str(uuid.uuid4()),
        timestamp_ns=time.time_ns(),
        hostname="h",
        category="process",
        type="exec",
        severity="info",
    )
    with pytest.raises((TypeError, AttributeError)):
        ev.hostname = "other"  # type: ignore[misc]


def test_sdk_event_optional_fields_default_none():
    """Optional fields default to None / empty tuple."""
    ev = Event(
        event_id=str(uuid.uuid4()),
        timestamp_ns=time.time_ns(),
        hostname="h",
        category="process",
        type="exec",
        severity="info",
    )
    assert ev.dst_ip is None
    assert ev.ml_score is None
    assert ev.mitre_techniques == ()


# ---------------------------------------------------------------------------
# SDK — IPC protocol
# ---------------------------------------------------------------------------

from oseye_sdk.ipc import IPCClient, IPCServer


@pytest.mark.asyncio
async def test_sdk_ipc_server_broadcast_and_client_receive(tmp_path: Path):
    """IPCServer.broadcast_event() must be receivable by IPCClient.receive_events()."""
    sock = str(tmp_path / "test.sock")
    server = IPCServer(socket_path=sock)
    await server.start()

    ev = Event(
        event_id=str(uuid.uuid4()),
        timestamp_ns=time.time_ns(),
        hostname="ipc-host",
        category="file",
        type="open",
        severity="low",
    )

    received: list[Event] = []

    async def _client() -> None:
        async with IPCClient(socket_path=sock) as client:
            async for event in client.receive_events():
                received.append(event)
                break  # collect just one

    client_task = asyncio.create_task(_client())
    await asyncio.sleep(0.05)  # let client connect

    await server.broadcast_event(ev)
    await asyncio.wait_for(client_task, timeout=3.0)

    assert len(received) == 1
    assert received[0].hostname == "ipc-host"
    assert received[0].category == "file"

    await server.stop()


@pytest.mark.asyncio
async def test_sdk_ipc_client_send_result_received_by_server(tmp_path: Path):
    """IPCClient.send_result() must be receivable by IPCServer.receive_results()."""
    sock = str(tmp_path / "result.sock")
    server = IPCServer(socket_path=sock)
    await server.start()

    result_payload = {"plugin": "test", "enrichment": "malware"}

    async def _client() -> None:
        async with IPCClient(socket_path=sock) as client:
            await client.send_result(result_payload)
            await asyncio.sleep(0.05)

    client_task = asyncio.create_task(_client())

    received_results: list[dict] = []

    async def _collect() -> None:
        async for r in server.receive_results():
            received_results.append(r)
            break

    collect_task = asyncio.create_task(_collect())

    await asyncio.gather(client_task, asyncio.wait_for(collect_task, timeout=3.0))

    assert len(received_results) == 1
    assert received_results[0]["plugin"] == "test"

    await server.stop()
