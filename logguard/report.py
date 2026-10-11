"""Report generation: JSON for machines, Markdown for humans."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from .models import Alert, SEVERITY_ORDER


def summarise(alerts: List[Alert]) -> Dict[str, object]:
    by_sev = Counter(a.severity for a in alerts)
    by_ip = Counter(a.source_ip for a in alerts)
    return {
        "total_alerts": len(alerts),
        "by_severity": {s: by_sev.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
        "top_source_ips": by_ip.most_common(5),
    }


def write_json(alerts: List[Alert], path: Path, meta: Dict[str, object]) -> None:
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "meta": meta,
        "summary": summarise(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def write_markdown(alerts: List[Alert], path: Path, meta: Dict[str, object]) -> None:
    summary = summarise(alerts)
    lines: List[str] = []
    lines.append("# Security Log Analysis Report")
    lines.append("")
    lines.append(f"_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} by logguard_")
    lines.append("")
    lines.append("## 1. Scope")
    lines.append("")
    for key, value in meta.items():
        lines.append(f"- **{key}:** {value}")
    lines.append("")
    lines.append("## 2. Executive summary")
    lines.append("")
    sev = summary["by_severity"]
    assert isinstance(sev, dict)
    if not alerts:
        lines.append("No detections were raised for the analysed period.")
    else:
        lines.append(
            f"{summary['total_alerts']} alert(s) were raised: "
            f"**{sev['critical']} critical**, {sev['high']} high, "
            f"{sev['medium']} medium, {sev['low']} low."
        )
        if sev["critical"]:
            lines.append("")
            lines.append(
                "> **Immediate action required.** At least one alert indicates a "
                "possible successful compromise or exploitation. Start with the "
                "critical findings below."
            )
        lines.append("")
        lines.append("Top source IPs by number of alerts:")
        lines.append("")
        lines.append("| Source IP | Alerts |")
        lines.append("|---|---|")
        for ip, n in summary["top_source_ips"]:  # type: ignore[union-attr]
            lines.append(f"| `{ip}` | {n} |")
    lines.append("")
    lines.append("## 3. Findings")
    lines.append("")
    lines.append("| ID | Severity | Rule | Source IP | Events | First seen | MITRE ATT&CK |")
    lines.append("|---|---|---|---|---|---|---|")
    for a in alerts:
        lines.append(
            f"| {a.alert_id} | {a.severity.upper()} | {a.rule} | `{a.source_ip}` | "
            f"{a.count} | {_fmt(a.first_seen)} | {a.mitre_id} {a.mitre_name} |"
        )
    lines.append("")
    lines.append("## 4. Details and recommended actions")
    for a in alerts:
        lines.append("")
        lines.append(f"### {a.alert_id} - {a.title}")
        lines.append("")
        lines.append(f"- **Severity:** {a.severity.upper()}")
        lines.append(f"- **Window:** {_fmt(a.first_seen)} -> {_fmt(a.last_seen)}")
        lines.append(f"- **Events:** {a.count}")
        lines.append(f"- **MITRE ATT&CK:** {a.mitre_id} - {a.mitre_name}")
        for k, v in a.details.items():
            lines.append(f"- **{k.replace('_', ' ').capitalize()}:** `{v}`")
        lines.append(f"- **Recommendation:** {a.recommendation}")
    lines.append("")
    blockable = sorted(
        {a.source_ip for a in alerts if SEVERITY_ORDER[a.severity] >= SEVERITY_ORDER["high"]}
    )
    lines.append("## 5. Suggested containment list")
    lines.append("")
    if blockable:
        lines.append(
            "Source IPs behind high/critical alerts. Review before blocking - "
            "shared NAT/proxy addresses can cause collateral impact:"
        )
        lines.append("")
        for ip in blockable:
            lines.append(f"- `{ip}`")
    else:
        lines.append("None.")
    lines.append("")
    lines.append("## 6. Limitations")
    lines.append("")
    lines.append(
        "Detections are rule-based heuristics over the supplied logs only. They can "
        "miss low-and-slow attacks and can produce false positives (for example a "
        "legitimate user mistyping a password repeatedly, or a vulnerability scanner "
        "run by your own team). Every alert should be validated by an analyst."
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
