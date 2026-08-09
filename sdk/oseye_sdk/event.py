from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Event:
    """Read-only event view exposed to plugins."""

    event_id: str
    timestamp_ns: int
    hostname: str
    category: str       # "file", "process", "network", "user", "device", "log", "audit"
    type: str
    severity: str       # "info", "low", "medium", "high", "critical"
    process_name: str = ""
    pid: int = 0
    uid: int = 0
    resource: str = ""
    dst_ip: str | None = None
    dst_port: int | None = None
    ml_score: float | None = None
    mitre_techniques: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, d: dict) -> Event:
        """Construct from a JSON-deserialized dict (from the IPC stream)."""
        mitre_raw = d.get("mitre_techniques") or []
        return cls(
            event_id=str(d["event_id"]),
            timestamp_ns=int(d["timestamp_ns"]),
            hostname=str(d["hostname"]),
            category=str(d["category"]),
            type=str(d["type"]),
            severity=str(d["severity"]),
            process_name=str(d.get("process_name") or ""),
            pid=int(d.get("pid") or 0),
            uid=int(d.get("uid") or 0),
            resource=str(d.get("resource") or ""),
            dst_ip=d.get("dst_ip"),
            dst_port=int(d["dst_port"]) if d.get("dst_port") is not None else None,
            ml_score=float(d["ml_score"]) if d.get("ml_score") is not None else None,
            mitre_techniques=tuple(str(t) for t in mitre_raw),
        )
