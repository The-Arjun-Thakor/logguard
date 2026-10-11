"""Data models shared by parsers, detectors and the report writer."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class AuthEvent:
    """A single SSH authentication event."""

    timestamp: datetime
    host: str
    outcome: str  # "failed" or "accepted"
    method: str  # password, publickey, ...
    user: str
    ip: str
    port: int
    invalid_user: bool = False


@dataclass(frozen=True)
class WebEvent:
    """A single HTTP request from a web server access log."""

    timestamp: datetime
    ip: str
    method: str
    path: str
    protocol: str
    status: int
    size: int
    referrer: str
    user_agent: str


@dataclass
class Alert:
    """A detection result."""

    rule: str
    severity: str
    title: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    mitre_id: str
    mitre_name: str
    recommendation: str
    details: Dict[str, Any] = field(default_factory=dict)
    alert_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["first_seen"] = self.first_seen.isoformat()
        data["last_seen"] = self.last_seen.isoformat()
        return data
