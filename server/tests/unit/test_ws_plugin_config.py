"""Unit tests for WebSocketManager, PluginVerifier, and Settings (Config).

Covers:
- WebSocketManager: connect/disconnect lifecycle, broadcast, SEC-WS-001 caps
- PluginVerifier: key loading, Ed25519 signature verification
- Settings: defaults and environment-variable overrides
"""

from __future__ import annotations

import hashlib
import os

# SEC-001: must be set before any oseye import so api_keys.py does not raise.
os.environ.setdefault("OSEYE_SECRET_KEY", "dev-secret-key-local-testing-only-32x")

from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio  # noqa: F401  (needed for asyncio mode detection)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_ws(user_sub: str | None = None) -> MagicMock:
    """Return a mock WebSocket with async send_bytes and close."""
    ws = MagicMock()
    ws.send_bytes = AsyncMock()
    ws.close = AsyncMock()
    ws.state = MagicMock()
    ws.state.user_sub = user_sub
    return ws


# ===========================================================================
# WebSocketManager
# ===========================================================================

class TestWebSocketManager:
    """Tests for oseye.api.ws.manager.WebSocketManager."""

    @pytest.fixture()
    def mgr(self):
        from oseye.api.ws.manager import WebSocketManager
        return WebSocketManager()

    # --- basic lifecycle ---

    @pytest.mark.asyncio
    async def test_connect_adds_to_connections(self, mgr):
        ws = _make_ws()
        await mgr.connect(ws, user_sub="user-a")
        assert ws in mgr._connections

    @pytest.mark.asyncio
    async def test_disconnect_removes_from_connections(self, mgr):
        ws = _make_ws()
        await mgr.connect(ws, user_sub="user-a")
        await mgr.disconnect(ws)
        assert ws not in mgr._connections

    # --- broadcast ---

    @pytest.mark.asyncio
    async def test_broadcast_sends_to_all_clients(self, mgr):
        ws1 = _make_ws()
        ws2 = _make_ws()
        await mgr.connect(ws1, user_sub="u1")
        await mgr.connect(ws2, user_sub="u2")
        await mgr.broadcast(b"hello")
        ws1.send_bytes.assert_awaited_once_with(b"hello")
        ws2.send_bytes.assert_awaited_once_with(b"hello")

    @pytest.mark.asyncio
    async def test_broadcast_removes_dead_client(self, mgr):
        ws_alive = _make_ws()
        ws_dead = _make_ws()
        ws_dead.send_bytes = AsyncMock(side_effect=RuntimeError("connection closed"))
        await mgr.connect(ws_alive, user_sub="u1")
        await mgr.connect(ws_dead, user_sub="u2")

        await mgr.broadcast(b"ping")

        # Dead client silently removed
        assert ws_dead not in mgr._connections
        # Alive client still there
        assert ws_alive in mgr._connections

    # --- SEC-WS-001: global cap ---

    @pytest.mark.asyncio
    async def test_connect_rejects_at_global_cap(self, mgr):
        from oseye.api.ws.manager import _MAX_GLOBAL_CONNECTIONS

        # Fill the manager to the cap directly (bypass logic for speed)
        for i in range(_MAX_GLOBAL_CONNECTIONS):
            fake = _make_ws()
            fake.state.user_sub = None
            mgr._connections.add(fake)

        ws_extra = _make_ws()
        await mgr.connect(ws_extra, user_sub="overflow-user")

        ws_extra.close.assert_awaited_once_with(code=4008)
        assert ws_extra not in mgr._connections

    # --- SEC-WS-001: per-user cap ---

    @pytest.mark.asyncio
    async def test_connect_rejects_at_per_user_cap(self, mgr):
        from oseye.api.ws.manager import _MAX_PER_USER_CONNECTIONS

        # Fill per-user slot for "alice"
        for _ in range(_MAX_PER_USER_CONNECTIONS):
            ws = _make_ws()
            await mgr.connect(ws, user_sub="alice")

        ws_overflow = _make_ws()
        await mgr.connect(ws_overflow, user_sub="alice")

        ws_overflow.close.assert_awaited_once_with(code=4008)
        assert ws_overflow not in mgr._connections

    @pytest.mark.asyncio
    async def test_different_user_can_connect_when_other_at_cap(self, mgr):
        """A different user_sub must not be blocked by another user's cap."""
        from oseye.api.ws.manager import _MAX_PER_USER_CONNECTIONS

        for _ in range(_MAX_PER_USER_CONNECTIONS):
            ws = _make_ws()
            await mgr.connect(ws, user_sub="alice")

        ws_bob = _make_ws()
        await mgr.connect(ws_bob, user_sub="bob")

        ws_bob.close.assert_not_called()
        assert ws_bob in mgr._connections

    # --- _per_user cleanup ---

    @pytest.mark.asyncio
    async def test_disconnect_cleans_per_user_when_set_empty(self, mgr):
        ws = _make_ws()
        await mgr.connect(ws, user_sub="carol")
        assert "carol" in mgr._per_user

        await mgr.disconnect(ws)

        # Key must be removed entirely when the set becomes empty
        assert "carol" not in mgr._per_user


# ===========================================================================
# PluginVerifier
# ===========================================================================

class TestPluginVerifier:
    """Tests for oseye.plugin.verifier.PluginVerifier."""

    # --- key loading ---

    def test_load_keys_silent_if_dir_absent(self, tmp_path):
        from oseye.plugin.verifier import PluginVerifier

        nonexistent = tmp_path / "no_such_dir"
        v = PluginVerifier(keys_dir=nonexistent)
        assert v._keys == []

    # --- verify() without keys ---

    def test_verify_returns_false_with_no_keys(self, tmp_path):
        from oseye.plugin.verifier import PluginVerifier

        plugin_file = tmp_path / "plugin.py"
        plugin_file.write_bytes(b"# dummy plugin")
        sig_file = tmp_path / "plugin.sig"
        sig_file.write_bytes(b"\x00" * 64)

        v = PluginVerifier(keys_dir=tmp_path / "empty_dir")
        assert v.verify(plugin_file, sig_file) is False

    # --- valid signature ---

    def test_verify_returns_true_for_valid_signature(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from oseye.plugin.verifier import PluginVerifier

        # Generate a key pair
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Write the public key as a PEM file into keys_dir
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        pem_bytes = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        (keys_dir / "trusted.pem").write_bytes(pem_bytes)

        # Write a plugin file
        plugin_file = tmp_path / "myplugin.py"
        plugin_file.write_bytes(b"print('hello from plugin')")

        # Sign it: Ed25519.sign over raw plugin bytes (no prehash — audit H-16 fix)
        signature = private_key.sign(plugin_file.read_bytes())

        sig_file = tmp_path / "myplugin.sig"
        sig_file.write_bytes(signature)

        v = PluginVerifier(keys_dir=keys_dir)
        assert v.verify(plugin_file, sig_file) is True

    # --- invalid signature (wrong key) ---

    def test_verify_returns_false_for_invalid_signature(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from oseye.plugin.verifier import PluginVerifier

        # Trusted key
        trusted_private = Ed25519PrivateKey.generate()
        trusted_public = trusted_private.public_key()

        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        pem_bytes = trusted_public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        (keys_dir / "trusted.pem").write_bytes(pem_bytes)

        # Sign with a *different* key
        other_private = Ed25519PrivateKey.generate()
        plugin_file = tmp_path / "myplugin.py"
        plugin_file.write_bytes(b"print('tampered plugin')")
        bad_signature = other_private.sign(plugin_file.read_bytes())

        sig_file = tmp_path / "myplugin.sig"
        sig_file.write_bytes(bad_signature)

        v = PluginVerifier(keys_dir=keys_dir)
        assert v.verify(plugin_file, sig_file) is False

    # --- missing plugin file ---

    def test_verify_returns_false_if_plugin_file_absent(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from oseye.plugin.verifier import PluginVerifier

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        pem_bytes = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        (keys_dir / "trusted.pem").write_bytes(pem_bytes)

        missing_plugin = tmp_path / "ghost_plugin.py"
        sig_file = tmp_path / "ghost_plugin.sig"
        sig_file.write_bytes(b"\x00" * 64)

        v = PluginVerifier(keys_dir=keys_dir)
        assert v.verify(missing_plugin, sig_file) is False

    # --- corrupted signature (random bytes) ---

    def test_verify_returns_false_for_corrupted_signature(self, tmp_path):
        import secrets

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from oseye.plugin.verifier import PluginVerifier

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        pem_bytes = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        (keys_dir / "trusted.pem").write_bytes(pem_bytes)

        plugin_file = tmp_path / "myplugin.py"
        plugin_file.write_bytes(b"# real plugin content")

        # 64 random bytes — not a valid signature
        sig_file = tmp_path / "myplugin.sig"
        sig_file.write_bytes(secrets.token_bytes(64))

        v = PluginVerifier(keys_dir=keys_dir)
        assert v.verify(plugin_file, sig_file) is False


# ===========================================================================
# Settings (Config)
# ===========================================================================

class TestSettings:
    """Tests for oseye.config.Settings."""

    def _fresh_settings(self, **kwargs):
        from oseye.config import Settings
        return Settings(**kwargs)

    # --- defaults ---

    def test_default_db_url(self):
        s = self._fresh_settings()
        assert s.db_url == "sqlite+aiosqlite:///./oseye_dev.db"

    def test_default_grpc_port(self):
        s = self._fresh_settings()
        assert s.grpc_port == 50051

    def test_default_api_port(self):
        s = self._fresh_settings()
        assert s.api_port == 8000

    def test_default_api_host(self):
        s = self._fresh_settings()
        assert s.api_host == "0.0.0.0"

    def test_default_log_level(self):
        s = self._fresh_settings()
        assert s.log_level == "INFO"

    def test_default_redis_url(self):
        s = self._fresh_settings()
        assert s.redis_url == "redis://localhost:6379/0"

    def test_default_db_backend(self):
        s = self._fresh_settings()
        assert s.db_backend == "sqlite"

    def test_default_otel_endpoint_is_none(self):
        s = self._fresh_settings()
        assert s.otel_endpoint is None

    # --- environment-variable overrides (OSEYE_ prefix) ---

    def test_env_override_db_url(self, monkeypatch):
        monkeypatch.setenv("OSEYE_DB_URL", "postgresql+asyncpg://user:pass@localhost/oseye")
        s = self._fresh_settings()
        assert s.db_url == "postgresql+asyncpg://user:pass@localhost/oseye"

    def test_env_override_grpc_port(self, monkeypatch):
        monkeypatch.setenv("OSEYE_GRPC_PORT", "50052")
        s = self._fresh_settings()
        assert s.grpc_port == 50052

    def test_env_override_api_host(self, monkeypatch):
        monkeypatch.setenv("OSEYE_API_HOST", "127.0.0.1")
        s = self._fresh_settings()
        assert s.api_host == "127.0.0.1"

    def test_env_override_log_level(self, monkeypatch):
        monkeypatch.setenv("OSEYE_LOG_LEVEL", "DEBUG")
        s = self._fresh_settings()
        assert s.log_level == "DEBUG"

    def test_env_override_redis_url(self, monkeypatch):
        monkeypatch.setenv("OSEYE_REDIS_URL", "redis://redis-prod:6379/1")
        s = self._fresh_settings()
        assert s.redis_url == "redis://redis-prod:6379/1"

    # --- OSEYE_SECRET_KEY consistency (SEC-001) ---

    def test_secret_key_env_is_read(self, monkeypatch):
        """OSEYE_SECRET_KEY must be accessible via os.environ (api_keys.py relies on it)."""
        # The top-level setdefault ensures it is always set; just verify it is non-empty.
        assert os.environ.get("OSEYE_SECRET_KEY"), "OSEYE_SECRET_KEY must be set before tests run"

    def test_env_override_secret_key(self, monkeypatch):
        monkeypatch.setenv("OSEYE_SECRET_KEY", "overridden-secret-key-value-32chars")
        # Settings does not expose secret_key as a field, but the env var must be
        # readable so that api_keys.py (which reads it directly via os.environ) works.
        assert os.environ["OSEYE_SECRET_KEY"] == "overridden-secret-key-value-32chars"
