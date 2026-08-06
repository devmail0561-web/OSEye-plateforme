"""
Benchmarks for hot-path server-side operations.

Run with pytest-benchmark:
    pytest server/tests/benchmarks/ -v --benchmark-sort=mean

Or standalone:
    python server/tests/benchmarks/bench_storage.py
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime

import pytest

from oseye.core.schema import UniversalEvent
from oseye.storage.backends.sqlite import SQLiteBackend
from oseye.storage.repositories.events import SQLEventRepository


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_event(i: int = 0) -> UniversalEvent:
    return UniversalEvent(
        event_id=uuid.uuid4(),
        timestamp_ns=time.time_ns() + i,
        hostname="bench-host",
        agent_id=uuid.uuid4(),
        category="process",
        type="exec",
        severity="info",
        collector="ebpf",
        hash_chain="a" * 64,
        pid=1000 + i,
        process_name="bash",
        executable="/bin/bash",
        cmdline=f"bash -c 'echo {i}'",
    )


async def _setup() -> tuple[SQLiteBackend, SQLEventRepository]:
    backend = SQLiteBackend("sqlite+aiosqlite:///:memory:")
    await backend.init()
    repo = SQLEventRepository(backend.session_factory)
    return backend, repo


# ---------------------------------------------------------------------------
# pytest-benchmark tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def event_loop_and_repo():
    """Module-scoped repo to avoid per-test setup overhead."""
    async def _init():
        return await _setup()
    loop = asyncio.new_event_loop()
    backend, repo = loop.run_until_complete(_init())
    yield loop, repo
    loop.close()


def test_bench_insert_batch_100(benchmark, event_loop_and_repo):
    """Benchmark: insert_batch of 100 events."""
    loop, repo = event_loop_and_repo
    events = [make_event(i) for i in range(100)]

    def run():
        loop.run_until_complete(repo.insert_batch(events))

    benchmark(run)


def test_bench_insert_batch_1000(benchmark, event_loop_and_repo):
    """Benchmark: insert_batch of 1000 events. Target: <200ms."""
    loop, repo = event_loop_and_repo
    events = [make_event(i) for i in range(1000)]

    def run():
        loop.run_until_complete(repo.insert_batch(events))

    benchmark(run)


def test_bench_event_to_row_conversion(benchmark):
    """Benchmark: Pydantic model → SQLAlchemy row (pure CPU, no IO)."""
    from oseye.storage.repositories.events import _event_to_row
    event = make_event()

    benchmark(lambda: _event_to_row(event))


def test_bench_row_to_event_conversion(benchmark):
    """Benchmark: SQLAlchemy row → Pydantic model (pure CPU, no IO)."""
    from oseye.storage.repositories.events import _event_to_row, _row_to_event
    row = _event_to_row(make_event())

    benchmark(lambda: _row_to_event(row))


# ---------------------------------------------------------------------------
# Standalone runner (no pytest-benchmark)
# ---------------------------------------------------------------------------

async def _standalone() -> None:
    backend, repo = await _setup()
    sizes = [1, 10, 100, 500, 1000]

    print(f"\n{'='*60}")
    print("OSEye — Storage benchmarks (SQLite :memory:)")
    print(f"{'='*60}")
    print(f"{'Batch size':>12} {'Iterations':>12} {'Mean (ms)':>12} {'Events/s':>12}")
    print("-" * 60)

    for n in sizes:
        iterations = max(5, 1000 // n)
        times = []
        for _ in range(iterations):
            events = [make_event(i) for i in range(n)]  # fresh UUIDs each iteration
            t0 = time.perf_counter()
            await repo.insert_batch(events)
            times.append(time.perf_counter() - t0)
        mean_ms = (sum(times) / len(times)) * 1000
        eps = n / (mean_ms / 1000)
        print(f"{n:>12} {iterations:>12} {mean_ms:>11.2f} {eps:>11,.0f}")

    print()

    # Conversion benchmark
    from oseye.storage.repositories.events import _event_to_row, _row_to_event
    event = make_event()
    row = _event_to_row(event)

    N = 100_000
    t0 = time.perf_counter()
    for _ in range(N):
        _event_to_row(event)
    dt = (time.perf_counter() - t0) / N * 1e6
    print(f"event → row  : {dt:.2f} µs/call  ({N/((time.perf_counter()-t0)):,.0f} ops/s)")

    t0 = time.perf_counter()
    for _ in range(N):
        _row_to_event(row)
    dt = (time.perf_counter() - t0) / N * 1e6
    print(f"row → event  : {dt:.2f} µs/call  ({N/((time.perf_counter()-t0)):,.0f} ops/s)")
    print()


if __name__ == "__main__":
    asyncio.run(_standalone())
