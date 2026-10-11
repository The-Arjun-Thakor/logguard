"""Log parsers.

Two formats are supported:

* OpenSSH messages in a syslog-style ``auth.log`` / ``secure`` file
* Apache/Nginx "combined" access log format

Lines that do not match are counted and skipped rather than raising, because
real logs always contain noise.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable, Iterator, List, Optional, Tuple

from .models import AuthEvent, WebEvent

# --- SSH auth log ---------------------------------------------------------

_SYSLOG_PREFIX = (
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\ssshd\[\d+\]:\s"
)

_FAILED_RE = re.compile(
    _SYSLOG_PREFIX
    + r"Failed (?P<method>[\w-]+) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)"
)

_ACCEPTED_RE = re.compile(
    _SYSLOG_PREFIX
    + r"Accepted (?P<method>[\w-]+) for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)"
)


def _parse_syslog_ts(ts: str, year: int) -> datetime:
    # Syslog pads single-digit days with two spaces ("Oct  1"); normalise first.
    normalised = " ".join(ts.split())
    return datetime.strptime(f"{year} {normalised}", "%Y %b %d %H:%M:%S")


def parse_auth_line(line: str, year: int) -> Optional[AuthEvent]:
    """Parse one auth.log line. Returns None if it is not an SSH auth event."""
    m = _FAILED_RE.match(line)
    if m:
        return AuthEvent(
            timestamp=_parse_syslog_ts(m.group("ts"), year),
            host=m.group("host"),
            outcome="failed",
            method=m.group("method"),
            user=m.group("user"),
            ip=m.group("ip"),
            port=int(m.group("port")),
            invalid_user=bool(m.group("invalid")),
        )
    m = _ACCEPTED_RE.match(line)
    if m:
        return AuthEvent(
            timestamp=_parse_syslog_ts(m.group("ts"), year),
            host=m.group("host"),
            outcome="accepted",
            method=m.group("method"),
            user=m.group("user"),
            ip=m.group("ip"),
            port=int(m.group("port")),
        )
    return None


def parse_auth_log(lines: Iterable[str], year: int) -> Tuple[List[AuthEvent], int]:
    """Parse many lines. Returns (events, skipped_line_count)."""
    events: List[AuthEvent] = []
    skipped = 0
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        try:
            event = parse_auth_line(line, year)
        except ValueError:
            event = None
        if event is None:
            skipped += 1
        else:
            events.append(event)
    return events, skipped


# --- Web access log (combined format) -------------------------------------

_WEB_RE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r"(?P<status>\d{3}) (?P<size>\d+|-) "
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_web_line(line: str) -> Optional[WebEvent]:
    m = _WEB_RE.match(line)
    if not m:
        return None
    ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
    # Normalise to naive UTC so every timestamp in the tool is comparable.
    ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    size = m.group("size")
    return WebEvent(
        timestamp=ts,
        ip=m.group("ip"),
        method=m.group("method"),
        path=m.group("path"),
        protocol=m.group("proto"),
        status=int(m.group("status")),
        size=0 if size == "-" else int(size),
        referrer=m.group("ref"),
        user_agent=m.group("ua"),
    )


def parse_web_log(lines: Iterable[str]) -> Tuple[List[WebEvent], int]:
    events: List[WebEvent] = []
    skipped = 0
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        try:
            event = parse_web_line(line)
        except ValueError:
            event = None
        if event is None:
            skipped += 1
        else:
            events.append(event)
    return events, skipped
