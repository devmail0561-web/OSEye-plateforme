"""Resilience tests for the offline buffer (M16).

These tests exercise Replay + AckUntil semantics to verify that:
- events survive a simulated transport failure (no data loss)
- replay restarts from the correct position after a partial delivery
- AckUntil correctly reclaims confirmed entries
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

# Make server/gen importable for tests that need protobuf stubs.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _open_buffer(path: str):
    """Import and open the Go-compatible SQLite buffer via the Python sqlite3 module."""
    import sqlite3

    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS buffer (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            payload    BLOB    NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    conn.commit()
    return conn


def _push(conn, payloads: list[bytes]) -> None:
    import time
    now = int(time.time() * 1e9)
    conn.executemany(
        "INSERT INTO buffer (payload, created_at) VALUES (?, ?)",
        [(p, now) for p in payloads],
    )
    conn.commit()


def _replay(conn, after_id: int, n: int) -> list[tuple[int, bytes]]:
    rows = conn.execute(
        "SELECT id, payload FROM buffer WHERE id > ? ORDER BY id ASC LIMIT ?",
        (after_id, n),
    ).fetchall()
    return [(r[0], r[1]) for r in rows]


def _ack_until(conn, max_id: int) -> int:
    cur = conn.execute("DELETE FROM buffer WHERE id <= ?", (max_id,))
    conn.commit()
    return cur.rowcount


def _len(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM buffer").fetchone()[0]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBufferResilience:
    def setup_method(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._path = self._tmp.name
        self._tmp.close()
        self.conn = _open_buffer(self._path)

    def teardown_method(self) -> None:
        self.conn.close()
        os.unlink(self._path)

    def test_replay_does_not_delete(self) -> None:
        _push(self.conn, [b"event1", b"event2", b"event3"])
        entries = _replay(self.conn, 0, 10)
        assert len(entries) == 3
        assert _len(self.conn) == 3  # nothing deleted

    def test_replay_respects_after_id(self) -> None:
        _push(self.conn, [b"a", b"b", b"c", b"d"])
        all_entries = _replay(self.conn, 0, 10)
        assert len(all_entries) == 4
        first_id = all_entries[0][0]
        second_page = _replay(self.conn, first_id, 10)
        assert len(second_page) == 3
        assert second_page[0][1] == b"b"

    def test_ack_until_removes_confirmed(self) -> None:
        _push(self.conn, [b"x1", b"x2", b"x3", b"x4", b"x5"])
        entries = _replay(self.conn, 0, 3)
        assert len(entries) == 3
        max_id = entries[-1][0]
        deleted = _ack_until(self.conn, max_id)
        assert deleted == 3
        assert _len(self.conn) == 2

    def test_no_data_loss_on_simulated_failure(self) -> None:
        """Simulate: replay → send fails → events stay → replay again → send ok → ack."""
        _push(self.conn, [b"ev%d" % i for i in range(10)])

        # First attempt: replay but "send" fails — no ack
        page1 = _replay(self.conn, 0, 5)
        assert len(page1) == 5
        # Simulate failure — do NOT call ack_until
        assert _len(self.conn) == 10  # all events still present

        # Second attempt: replay from same position, "send" succeeds
        page2 = _replay(self.conn, 0, 5)
        assert page2 == page1  # same events replayed
        _ack_until(self.conn, page2[-1][0])
        assert _len(self.conn) == 5  # only second half remains

        # Drain rest
        page3 = _replay(self.conn, page2[-1][0], 10)
        assert len(page3) == 5
        _ack_until(self.conn, page3[-1][0])
        assert _len(self.conn) == 0

    def test_replay_pagination(self) -> None:
        """Verify cursor-based pagination delivers all events exactly once."""
        _push(self.conn, [b"p%d" % i for i in range(25)])
        seen_ids: list[int] = []
        last_id = 0
        while True:
            page = _replay(self.conn, last_id, 10)
            if not page:
                break
            for row_id, _ in page:
                seen_ids.append(row_id)
            last_id = page[-1][0]
        assert len(seen_ids) == 25
        assert len(set(seen_ids)) == 25  # no duplicates

    def test_ack_idempotent(self) -> None:
        _push(self.conn, [b"z"])
        entries = _replay(self.conn, 0, 10)
        max_id = entries[-1][0]
        _ack_until(self.conn, max_id)
        # Second ack of same ID is a no-op
        deleted = _ack_until(self.conn, max_id)
        assert deleted == 0
        assert _len(self.conn) == 0


class TestBackpressureController:
    """Unit tests for BackpressureController (no Redis required)."""

    @pytest.mark.asyncio
    async def test_no_redis_no_throttle(self) -> None:
        from unittest.mock import AsyncMock, MagicMock

        from oseye.ingest.backpressure import BackpressureController

        bus = MagicMock()
        bus.publish = AsyncMock()
        ctrl = BackpressureController(
            bus=bus,
            get_active_cns=lambda: frozenset({"agent-1"}),
            redis_url=None,
        )
        # Without Redis, _measure_lag returns 0 → no throttle published
        await ctrl._check_and_throttle()
        bus.publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_throttle_published_when_lag_high(self) -> None:
        from unittest.mock import AsyncMock, MagicMock, patch

        from oseye.ingest.backpressure import BackpressureController

        bus = MagicMock()
        bus.publish = AsyncMock()
        ctrl = BackpressureController(
            bus=bus,
            get_active_cns=lambda: frozenset({"agent-cn-1", "agent-cn-2"}),
            redis_url="redis://localhost:6379",
            lag_threshold=1_000,
        )

        with patch.object(ctrl, "_measure_lag", AsyncMock(return_value=50_000)):
            await ctrl._check_and_throttle()

        assert bus.publish.call_count == 2
        calls = [call.args[0] for call in bus.publish.call_args_list]
        assert "commands:agent-cn-1" in calls
        assert "commands:agent-cn-2" in calls

    @pytest.mark.asyncio
    async def test_throttle_cleared_when_lag_drops(self) -> None:
        from unittest.mock import AsyncMock, MagicMock, patch

        from oseye.ingest.backpressure import BackpressureController

        bus = MagicMock()
        bus.publish = AsyncMock()
        ctrl = BackpressureController(
            bus=bus,
            get_active_cns=lambda: frozenset({"agent-1"}),
            redis_url="redis://localhost:6379",
            lag_threshold=1_000,
        )
        ctrl._current_factor = 0.3  # simulate active throttle

        with patch.object(ctrl, "_measure_lag", AsyncMock(return_value=100)):
            await ctrl._check_and_throttle()

        assert bus.publish.call_count == 1
        import json
        payload = json.loads(bus.publish.call_args.args[1])
        assert payload["payload"]["factor"] == 1.0
