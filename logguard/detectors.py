"""Detection rules.

Each rule is a plain function that takes parsed events and returns alerts.
Rules are mapped to MITRE ATT&CK techniques so findings can be communicated in
the language used by SOC and incident-response teams.

All thresholds are configurable via :class:`Thresholds` because the right
values depend on the environment - there is no universally correct number.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Sequence, TypeVar
from urllib.parse import unquote_plus

from .models import Alert, AuthEvent, SEVERITY_ORDER, WebEvent

T = TypeVar("T")


@dataclass
class Thresholds:
    # SSH
    brute_force_failures: int = 5
    brute_force_window: int = 300  # seconds
    spray_usernames: int = 5
    spray_window: int = 600
    compromise_prior_failures: int = 3
    compromise_window: int = 600
    # Web
    web_scan_errors: int = 20
    web_scan_window: int = 60
    web_flood_requests: int = 200
    web_flood_window: int = 10


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _seconds(a, b) -> float:
    return (b - a).total_seconds()


def find_bursts(events: Sequence[T], window: int, threshold: int) -> List[List[T]]:
    """Find bursts of at least ``threshold`` events inside a sliding ``window``.

    ``events`` must be sorted by ``timestamp``. Once a burst is detected it is
    extended while consecutive events stay within ``window`` seconds of each
    other, so a long attack produces one alert instead of many.
    """
    bursts: List[List[T]] = []
    n = len(events)
    left = 0
    i = 0
    while i < n:
        while _seconds(events[left].timestamp, events[i].timestamp) > window:  # type: ignore[attr-defined]
            left += 1
        if i - left + 1 >= threshold:
            end = i
            while end + 1 < n and _seconds(
                events[end].timestamp, events[end + 1].timestamp  # type: ignore[attr-defined]
            ) <= window:
                end += 1
            bursts.append(list(events[left : end + 1]))
            i = end + 1
            left = i
            continue
        i += 1
    return bursts


def _group_by_ip(events: Iterable[T]) -> Dict[str, List[T]]:
    grouped: Dict[str, List[T]] = defaultdict(list)
    for e in events:
        grouped[e.ip].append(e)  # type: ignore[attr-defined]
    for lst in grouped.values():
        lst.sort(key=lambda e: e.timestamp)  # type: ignore[attr-defined]
    return grouped


# --------------------------------------------------------------------------
# SSH rules
# --------------------------------------------------------------------------

def detect_ssh_brute_force(events: Sequence[AuthEvent], th: Thresholds) -> List[Alert]:
    """Many failed logins from one IP in a short time (T1110)."""
    failures = [e for e in events if e.outcome == "failed"]
    alerts: List[Alert] = []
    for ip, evs in _group_by_ip(failures).items():
        for burst in find_bursts(evs, th.brute_force_window, th.brute_force_failures):
            users = Counter(e.user for e in burst)
            alerts.append(
                Alert(
                    rule="ssh_brute_force",
                    severity="high",
                    title=f"SSH brute-force attempt from {ip}",
                    source_ip=ip,
                    first_seen=burst[0].timestamp,
                    last_seen=burst[-1].timestamp,
                    count=len(burst),
                    mitre_id="T1110",
                    mitre_name="Brute Force",
                    recommendation=(
                        "Block or rate-limit the source IP (fail2ban / firewall), "
                        "disable password authentication in favour of keys, and "
                        "confirm none of the targeted accounts were accessed."
                    ),
                    details={
                        "targeted_users": dict(users.most_common(5)),
                        "distinct_users": len(users),
                    },
                )
            )
    return alerts


def detect_ssh_password_spray(events: Sequence[AuthEvent], th: Thresholds) -> List[Alert]:
    """One IP trying many different usernames (T1110.003)."""
    failures = [e for e in events if e.outcome == "failed"]
    alerts: List[Alert] = []
    for ip, evs in _group_by_ip(failures).items():
        i = 0
        while i < len(evs):
            window_events = [
                e for e in evs[i:] if _seconds(evs[i].timestamp, e.timestamp) <= th.spray_window
            ]
            users = {e.user for e in window_events}
            if len(users) >= th.spray_usernames:
                alerts.append(
                    Alert(
                        rule="ssh_password_spray",
                        severity="high",
                        title=f"Password spraying / user enumeration from {ip}",
                        source_ip=ip,
                        first_seen=window_events[0].timestamp,
                        last_seen=window_events[-1].timestamp,
                        count=len(window_events),
                        mitre_id="T1110.003",
                        mitre_name="Brute Force: Password Spraying",
                        recommendation=(
                            "Block the source IP, review authentication logs for any "
                            "successful login by the targeted usernames, and enforce "
                            "MFA / account lockout policies."
                        ),
                        details={
                            "distinct_users": len(users),
                            "sample_users": sorted(users)[:8],
                            "invalid_user_attempts": sum(1 for e in window_events if e.invalid_user),
                        },
                    )
                )
                i += len(window_events)
            else:
                i += 1
    return alerts


def detect_success_after_failures(events: Sequence[AuthEvent], th: Thresholds) -> List[Alert]:
    """A successful login right after repeated failures from the same IP (T1078).

    This is the most important SSH finding: it suggests the attacker guessed a
    valid credential.
    """
    by_ip = _group_by_ip(events)
    alerts: List[Alert] = []
    for ip, evs in by_ip.items():
        for idx, ev in enumerate(evs):
            if ev.outcome != "accepted":
                continue
            prior = [
                p
                for p in evs[:idx]
                if p.outcome == "failed"
                and 0 <= _seconds(p.timestamp, ev.timestamp) <= th.compromise_window
            ]
            if len(prior) >= th.compromise_prior_failures:
                alerts.append(
                    Alert(
                        rule="ssh_success_after_failures",
                        severity="critical",
                        title=f"Successful SSH login for '{ev.user}' from {ip} after {len(prior)} failures",
                        source_ip=ip,
                        first_seen=prior[0].timestamp,
                        last_seen=ev.timestamp,
                        count=len(prior) + 1,
                        mitre_id="T1078",
                        mitre_name="Valid Accounts",
                        recommendation=(
                            "Treat the account as compromised: terminate the session, "
                            "reset credentials and keys, review commands run and files "
                            "changed after the login time, and check for persistence."
                        ),
                        details={
                            "account": ev.user,
                            "auth_method": ev.method,
                            "failures_before_success": len(prior),
                            "login_time": ev.timestamp.isoformat(),
                        },
                    )
                )
    return alerts

def detect_root_login(events: Sequence[AuthEvent], th: Thresholds) -> List[Alert]:
    """Successful direct SSH login as root (T1078.003).

    Admins should log in as a named user and use sudo, so every action is
    traceable to a person. A root login is not always malicious, but it is
    always worth a look.
    """
    root_logins = [e for e in events if e.outcome == "accepted" and e.user == "root"]
    alerts: List[Alert] = []
    for ip, evs in _group_by_ip(root_logins).items():
        alerts.append(
            Alert(
                rule="ssh_root_login",
                severity="medium",
                title=f"Direct root SSH login from {ip}",
                source_ip=ip,
                first_seen=evs[0].timestamp,
                last_seen=evs[-1].timestamp,
                count=len(evs),
                mitre_id="T1078.003",
                mitre_name="Valid Accounts: Local Accounts",
                recommendation=(
                    "Confirm the login was expected. Disable direct root login "
                    "(PermitRootLogin no) and use named accounts with sudo."
                ),
                details={"auth_methods": sorted({e.method for e in evs})},
            )
        )
    return alerts


# --------------------------------------------------------------------------
# Web rules
# --------------------------------------------------------------------------

_SIGNATURES: Dict[str, Dict] = {
    "sql_injection": {
        "severity": "high",
        "mitre": ("T1190", "Exploit Public-Facing Application"),
        "patterns": [
            r"union(\s|/\*.*?\*/)+(all\s+)?select",
            r"\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"'\s*(or|and)\s+'",
            r"sleep\s*\(\s*\d+\s*\)",
            r"information_schema",
            r"benchmark\s*\(",
            r";\s*drop\s+table",
        ],
        "advice": "Use parameterised queries, validate input, and review database logs for the targeted endpoint.",
    },
    "xss": {
        "severity": "medium",
        "mitre": ("T1190", "Exploit Public-Facing Application"),
        "patterns": [
            r"<\s*script",
            r"javascript\s*:",
            r"\bon(error|load|click|mouseover)\s*=",
        ],
        "advice": "Apply output encoding and a Content-Security-Policy; review the reflected parameter.",
    },
    "path_traversal": {
        "severity": "high",
        "mitre": ("T1190", "Exploit Public-Facing Application"),
        "patterns": [
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"boot\.ini|win\.ini",
        ],
        "advice": "Canonicalise and whitelist file paths; run the web process with minimal filesystem rights.",
    },
    "command_injection": {
        "severity": "high",
        "mitre": ("T1190", "Exploit Public-Facing Application"),
        "patterns": [
            r"[;|&`]\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b",
            r"\$\([^)]*\)",
            r"/bin/(ba)?sh",
        ],
        "advice": "Never pass user input to a shell; use safe APIs and strict allow-lists.",
    },
}
_COMPILED = {
    name: [re.compile(p, re.IGNORECASE) for p in spec["patterns"]]
    for name, spec in _SIGNATURES.items()
}

_SUSPICIOUS_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|wpscan|zgrab|nuclei",
    re.IGNORECASE,
)

_DISPLAY_NAMES = {
    "sql_injection": "SQL injection",
    "xss": "Cross-site scripting (XSS)",
    "path_traversal": "Path traversal / local file access",
    "command_injection": "Command injection",
}

_BUMP = {"medium": "high", "high": "critical", "low": "medium", "critical": "critical"}


def _decode(path: str) -> str:
    """Decode twice so double-encoded payloads (%252e%252e) are still caught."""
    return unquote_plus(unquote_plus(path))


def detect_web_attack_patterns(events: Sequence[WebEvent], th: Thresholds) -> List[Alert]:
    """Known attack payloads in request URLs (T1190)."""
    hits: Dict[tuple, List[WebEvent]] = defaultdict(list)
    for e in events:
        decoded = _decode(e.path)
        for category, regexes in _COMPILED.items():
            if any(r.search(decoded) for r in regexes):
                hits[(e.ip, category)].append(e)

    alerts: List[Alert] = []
    for (ip, category), evs in hits.items():
        evs.sort(key=lambda e: e.timestamp)
        spec = _SIGNATURES[category]
        ok_responses = sum(1 for e in evs if e.status == 200)
        severity = spec["severity"]
        if ok_responses:
            # Heuristic: the server answered a malicious request normally.
            # That does not prove exploitation, but it deserves escalation.
            severity = _BUMP[severity]
        alerts.append(
            Alert(
                rule=f"web_{category}",
                severity=severity,
                title=f"{_DISPLAY_NAMES[category]} attempts from {ip}",
                source_ip=ip,
                first_seen=evs[0].timestamp,
                last_seen=evs[-1].timestamp,
                count=len(evs),
                mitre_id=spec["mitre"][0],
                mitre_name=spec["mitre"][1],
                recommendation=spec["advice"]
                + (
                    " The server returned HTTP 200 to at least one payload - "
                    "verify manually whether it was exploited."
                    if ok_responses
                    else ""
                ),
                details={
                    "sample_requests": [e.path[:120] for e in evs[:3]],
                    "http_200_responses": ok_responses,
                    "user_agent": evs[0].user_agent[:80],
                },
            )
        )
    return alerts


def detect_web_scanning(events: Sequence[WebEvent], th: Thresholds) -> List[Alert]:
    """Many 4xx responses from one IP: directory/file brute-forcing (T1595.003)."""
    errors = [e for e in events if e.status in (400, 401, 403, 404, 405)]
    alerts: List[Alert] = []
    for ip, evs in _group_by_ip(errors).items():
        for burst in find_bursts(evs, th.web_scan_window, th.web_scan_errors):
            alerts.append(
                Alert(
                    rule="web_content_scanning",
                    severity="medium",
                    title=f"Content discovery / directory brute-forcing from {ip}",
                    source_ip=ip,
                    first_seen=burst[0].timestamp,
                    last_seen=burst[-1].timestamp,
                    count=len(burst),
                    mitre_id="T1595.003",
                    mitre_name="Active Scanning: Wordlist Scanning",
                    recommendation=(
                        "Rate-limit or block the source IP at the WAF/reverse proxy and "
                        "confirm no sensitive paths (backups, admin panels) are exposed."
                    ),
                    details={
                        "distinct_paths": len({e.path for e in burst}),
                        "sample_paths": [e.path for e in burst[:3]],
                    },
                )
            )
    return alerts


def detect_scanner_user_agents(events: Sequence[WebEvent], th: Thresholds) -> List[Alert]:
    """Requests made by well-known offensive tooling (T1595.002)."""
    hits: Dict[str, List[WebEvent]] = defaultdict(list)
    for e in events:
        if _SUSPICIOUS_UA.search(e.user_agent):
            hits[e.ip].append(e)
    alerts: List[Alert] = []
    for ip, evs in hits.items():
        evs.sort(key=lambda e: e.timestamp)
        tool = _SUSPICIOUS_UA.search(evs[0].user_agent).group(0).lower()  # type: ignore[union-attr]
        alerts.append(
            Alert(
                rule="web_scanner_user_agent",
                severity="medium",
                title=f"Security scanner '{tool}' detected from {ip}",
                source_ip=ip,
                first_seen=evs[0].timestamp,
                last_seen=evs[-1].timestamp,
                count=len(evs),
                mitre_id="T1595.002",
                mitre_name="Active Scanning: Vulnerability Scanning",
                recommendation=(
                    "Confirm the traffic is not an authorised assessment. If it is not, "
                    "block the source and review other alerts from the same IP."
                ),
                details={"user_agent": evs[0].user_agent[:100]},
            )
        )
    return alerts


def detect_request_flood(events: Sequence[WebEvent], th: Thresholds) -> List[Alert]:
    """Unusually high request rate from a single IP (T1499)."""
    alerts: List[Alert] = []
    for ip, evs in _group_by_ip(events).items():
        for burst in find_bursts(evs, th.web_flood_window, th.web_flood_requests):
            alerts.append(
                Alert(
                    rule="web_request_flood",
                    severity="medium",
                    title=f"High request rate from {ip}",
                    source_ip=ip,
                    first_seen=burst[0].timestamp,
                    last_seen=burst[-1].timestamp,
                    count=len(burst),
                    mitre_id="T1499",
                    mitre_name="Endpoint Denial of Service",
                    recommendation="Apply rate limiting and check service health and capacity.",
                    details={"window_seconds": th.web_flood_window},
                )
            )
    return alerts


# --------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------

AUTH_RULES: List[Callable[..., List[Alert]]] = [
    detect_ssh_brute_force,
    detect_ssh_password_spray,
    detect_success_after_failures,
    detect_root_login,
]
WEB_RULES: List[Callable[..., List[Alert]]] = [
    detect_web_attack_patterns,
    detect_web_scanning,
    detect_scanner_user_agents,
    detect_request_flood,
]


def run_all(
    auth_events: Sequence[AuthEvent],
    web_events: Sequence[WebEvent],
    thresholds: Thresholds | None = None,
) -> List[Alert]:
    """Run every rule, sort by severity (worst first) then time, assign IDs."""
    th = thresholds or Thresholds()
    alerts: List[Alert] = []
    for rule in AUTH_RULES:
        alerts.extend(rule(auth_events, th))
    for rule in WEB_RULES:
        alerts.extend(rule(web_events, th))
    alerts.sort(key=lambda a: (-SEVERITY_ORDER[a.severity], a.first_seen))
    for i, alert in enumerate(alerts, start=1):
        alert.alert_id = f"LG-{i:04d}"
    return alerts
