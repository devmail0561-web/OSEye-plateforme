"""Unit tests for the M6 ingest layer (validator + normalizer bridge)."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest

from oseye.ingest.validator import BatchValidator, ValidationResult
from oseye.ingest.normalizer_bridge import pb_to_event


# ---------------------------------------------------------------------------
# Helpers — build mock protobuf objects without importing server.gen
# ---------------------------------------------------------------------------


def _make_pb_event(
    *,
    category: str = "process",
    type: str = "exec",
    severity: str = "info",
    agent_id: bytes = b"\x00" * 16,
    event_id: bytes = b"",
    hostname: str = "host-1",
    hash_chain: bytes = b"",
    **kwargs: Any,
) -> MagicMock:
    ev = MagicMock()
    ev.category = category
    ev.type = type
    ev.severity = severity
    ev.agent_id = agent_id
    ev.event_id = event_id
    ev.hostname = hostname
    ev.hash_chain = hash_chain
    ev.collector = kwargs.get("collector", "test")
    ev.os = kwargs.get("os", "linux")
    ev.uid = kwargs.get("uid", 0)
    ev.gid = kwargs.get("gid", 0)
    ev.pid = kwargs.get("pid", 0)
    ev.ppid = kwargs.get("ppid", 0)
    ev.process_name = kwargs.get("process_name", "")
    ev.executable = kwargs.get("executable", "")
    ev.cmdline = kwargs.get("cmdline", "")
    ev.cwd = kwargs.get("cwd", "")
    ev.session_id = kwargs.get("session_id", 0)
    ev.resource = kwargs.get("resource", "")
    ev.result = kwargs.get("result", "success")
    ev.file_hash_before = kwargs.get("file_hash_before", "")
    ev.file_hash_after = kwargs.get("file_hash_after", "")
    ev.src_ip = kwargs.get("src_ip", "")
    ev.src_port = kwargs.get("src_port", 0)
    ev.dst_ip = kwargs.get("dst_ip", "")
    ev.dst_port = kwargs.get("dst_port", 0)
    ev.protocol = kwargs.get("protocol", "")
    ev.bytes_sent = kwargs.get("bytes_sent", 0)
    ev.bytes_recv = kwargs.get("bytes_recv", 0)
    ev.signature = kwargs.get("signature", b"")
    ev.extra_json = kwargs.get("extra_json", b"")
    ev.timestamp_ns = kwargs.get("timestamp_ns", 1_700_000_000_000_000_000)
    return ev


def _make_request(
    events: list[MagicMock],
    batch_signature: bytes = b"",
) -> MagicMock:
    req = MagicMock()
    req.events = events
    req.batch_signature = batch_signature
    return req


# ---------------------------------------------------------------------------
# BatchValidator tests
# ---------------------------------------------------------------------------


class TestBatchValidator:
    def setup_method(self) -> None:
        self.validator = BatchValidator()

    def test_validator_accepts_valid_batch(self) -> None:
        events = [
            _make_pb_event(category="process", type="exec", severity="info"),
            _make_pb_event(category="network", type="connect", severity="low"),
        ]
        req = _make_request(events)
        result = self.validator.validate(req)

        assert isinstance(result, ValidationResult)
        assert result.accepted == 2
        assert result.rejected == 0
        assert result.errors == []

    def test_validator_rejects_missing_fields(self) -> None:
        """An event without 'category' must be rejected."""
        bad_event = _make_pb_event(category="", type="exec", severity="info")
        good_event = _make_pb_event(category="file", type="write", severity="medium")
        req = _make_request([bad_event, good_event])

        result = self.validator.validate(req)

        assert result.rejected == 1
        assert result.accepted == 1
        assert len(result.errors) == 1
        assert "category" in result.errors[0]

    def test_validator_rejects_missing_type(self) -> None:
        ev = _make_pb_event(category="process", type="", severity="high")
        req = _make_request([ev])
        result = self.validator.validate(req)

        assert result.rejected == 1
        assert result.accepted == 0
        assert "type" in result.errors[0]

    def test_validator_rejects_missing_severity(self) -> None:
        ev = _make_pb_event(category="user", type="login", severity="")
        req = _make_request([ev])
        result = self.validator.validate(req)

        assert result.rejected == 1
        assert "severity" in result.errors[0]

    def test_validator_skip_signature_if_no_key(self) -> None:
        """When agent_public_key is None, signature verification is skipped."""
        events = [_make_pb_event()]
        req = _make_request(events, batch_signature=b"definitely-invalid-sig")

        # Should NOT raise and should accept the event
        result = self.validator.validate(req, agent_public_key=None)

        assert result.accepted == 1
        assert result.rejected == 0

    def test_validator_rejects_all_on_bad_signature(self) -> None:
        """When a public key is provided but signature is wrong, all events rejected."""
        import os
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        private_key = Ed25519PrivateKey.generate()
        public_key_der = private_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )

        events = [_make_pb_event()]
        req = _make_request(events, batch_signature=os.urandom(64))

        result = self.validator.validate(req, agent_public_key=public_key_der)

        assert result.rejected == 1
        assert result.accepted == 0
        assert "signature verification failed" in result.errors[0]

    def test_validator_empty_batch(self) -> None:
        req = _make_request([])
        result = self.validator.validate(req)
        assert result.accepted == 0
        assert result.rejected == 0
        assert result.errors == []


# ---------------------------------------------------------------------------
# pb_to_event conversion tests
# ---------------------------------------------------------------------------


class TestPbToEvent:
    def test_pb_to_event_conversion(self) -> None:
        """Basic field mapping from protobuf to Pydantic model."""
        agent_uuid = uuid.uuid4()
        event_uuid = uuid.uuid4()

        pb = _make_pb_event(
            event_id=event_uuid.bytes,
            agent_id=agent_uuid.bytes,
            category="process",
            type="exec",
            severity="info",
            hostname="my-host",
            collector="auditd",
            os="linux",
            pid=1234,
            ppid=1,
            process_name="bash",
            executable="/bin/bash",
            cmdline="bash -c ls",
            cwd="/tmp",
        )

        event = pb_to_event(pb)

        assert event.event_id == event_uuid
        assert event.agent_id == agent_uuid
        assert event.category == "process"
        assert event.type == "exec"
        assert event.severity == "info"
        assert event.hostname == "my-host"
        assert event.collector == "auditd"
        assert event.os == "linux"
        assert event.pid == 1234
        assert event.ppid == 1
        assert event.process_name == "bash"
        assert event.executable == "/bin/bash"
        assert event.cmdline == "bash -c ls"
        assert event.cwd == "/tmp"

    def test_pb_to_event_agent_id_override(self) -> None:
        """CN override must replace pb.agent_id (SEC-PREV-001)."""
        original_uuid = uuid.uuid4()
        cn_uuid = uuid.uuid4()

        pb = _make_pb_event(agent_id=original_uuid.bytes)
        event = pb_to_event(pb, agent_id_override=str(cn_uuid))

        # agent_id must come from CN, not from pb.agent_id
        assert event.agent_id == cn_uuid
        assert event.agent_id != original_uuid

    def test_pb_to_event_cn_non_uuid_override(self) -> None:
        """CN that is not a UUID string should produce a deterministic UUID-5."""
        pb = _make_pb_event()
        cn = "my-sensor-host.corp.example.com"
        event = pb_to_event(pb, agent_id_override=cn)

        expected = uuid.uuid5(uuid.NAMESPACE_DNS, cn)
        assert event.agent_id == expected

    def test_pb_to_event_missing_event_id_generates_uuid(self) -> None:
        """Empty event_id bytes → a fresh UUID is generated."""
        pb = _make_pb_event(event_id=b"")
        event = pb_to_event(pb)
        assert isinstance(event.event_id, uuid.UUID)

    def test_pb_to_event_network_fields(self) -> None:
        pb = _make_pb_event(
            category="network",
            type="connect",
            severity="low",
            src_ip="192.168.1.10",
            src_port=55432,
            dst_ip="10.0.0.1",
            dst_port=443,
            protocol="tcp",
            bytes_sent=1024,
            bytes_recv=2048,
        )
        event = pb_to_event(pb)

        assert event.src_ip == "192.168.1.10"
        assert event.src_port == 55432
        assert event.dst_ip == "10.0.0.1"
        assert event.dst_port == 443
        assert event.protocol == "tcp"
        assert event.bytes_sent == 1024
        assert event.bytes_recv == 2048

    def test_pb_to_event_extra_json_parsed(self) -> None:
        import json as _json

        payload = _json.dumps({"key": "value", "count": 42}).encode("utf-8")
        pb = _make_pb_event(extra_json=payload)
        event = pb_to_event(pb)

        assert event.extra == {"key": "value", "count": 42}

    def test_pb_to_event_hash_chain_hex(self) -> None:
        raw = b"\xde\xad\xbe\xef"
        pb = _make_pb_event(hash_chain=raw)
        event = pb_to_event(pb)
        assert event.hash_chain == "deadbeef"

    def test_pb_to_event_zero_ports_become_none(self) -> None:
        pb = _make_pb_event(src_port=0, dst_port=0)
        event = pb_to_event(pb)
        assert event.src_port is None
        assert event.dst_port is None
