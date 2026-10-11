#!/usr/bin/env python3
"""Generate synthetic, deterministic sample logs containing known attacks.

All IP addresses come from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so they are guaranteed not to
belong to a real host. No real data is used.

Usage:
    python scripts/generate_sample_logs.py [output_dir]
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

random.seed(27001)  # deterministic output

BASE = datetime(2026, 10, 10, 8, 0, 0)
HOST = "web01"

BRUTE_IP = "203.0.113.50"       # classic SSH brute force against root/admin
SPRAY_IP = "198.51.100.77"      # many usernames, one attempt each
COMPROMISE_IP = "192.0.2.99"    # failures followed by a successful login
SQLI_IP = "203.0.113.99"        # sqlmap + SQL injection
SCAN_IP = "198.51.100.23"       # directory brute forcing
XSS_IP = "192.0.2.45"           # XSS + path traversal


def syslog_ts(dt: datetime) -> str:
    return f"{dt.strftime('%b')} {dt.day:>2} {dt.strftime('%H:%M:%S')}"


def web_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def build_auth() -> list[str]:
    lines: list[tuple[datetime, str]] = []

    def add(dt: datetime, msg: str) -> None:
        lines.append((dt, f"{syslog_ts(dt)} {HOST} sshd[{random.randint(1000, 9999)}]: {msg}"))

    # Legitimate activity, including one harmless typo.
    for hour, user, ip in [(0, "alice", "198.51.100.10"), (2, "bob", "198.51.100.11"),
                           (5, "alice", "198.51.100.10"), (7, "carol", "198.51.100.12")]:
        add(BASE + timedelta(hours=hour), f"Accepted publickey for {user} from {ip} port {random.randint(30000, 60000)} ssh2")
    add(BASE + timedelta(hours=3), "Failed password for bob from 198.51.100.11 port 41122 ssh2")
    add(BASE + timedelta(hours=3, seconds=9), "Accepted password for bob from 198.51.100.11 port 41124 ssh2")

    # 1) Brute force: 40 failures in ~2 minutes.
    t = BASE + timedelta(hours=1)
    for i in range(40):
        user = random.choice(["root", "admin", "ubuntu"])
        invalid = "" if user == "root" else "invalid user "
        add(t + timedelta(seconds=i * 3), f"Failed password for {invalid}{user} from {BRUTE_IP} port {random.randint(30000, 60000)} ssh2")

    # 2) Password spray: one attempt each against 12 usernames.
    t = BASE + timedelta(hours=4)
    for i, user in enumerate(["test", "oracle", "postgres", "git", "jenkins", "ftp",
                              "deploy", "support", "user", "guest", "www", "backup"]):
        add(t + timedelta(seconds=i * 20), f"Failed password for invalid user {user} from {SPRAY_IP} port {random.randint(30000, 60000)} ssh2")

    # 3) Compromise: 6 failures then success on a real account.
    t = BASE + timedelta(hours=6)
    for i in range(6):
        add(t + timedelta(seconds=i * 7), f"Failed password for carol from {COMPROMISE_IP} port {random.randint(30000, 60000)} ssh2")
    add(t + timedelta(seconds=50), f"Accepted password for carol from {COMPROMISE_IP} port 50222 ssh2")

    lines.sort(key=lambda x: x[0])
    out = [text for _, text in lines]
    out.insert(3, f"{syslog_ts(BASE)} {HOST} CRON[1234]: pam_unix(cron:session): session opened for user root")
    return out


def build_web() -> list[str]:
    lines: list[tuple[datetime, str]] = []

    def add(dt, ip, method, path, status, ua="Mozilla/5.0 (X11; Linux x86_64) Firefox/118.0"):
        lines.append((dt, f'{ip} - - [{web_ts(dt)}] "{method} {path} HTTP/1.1" {status} {random.randint(200, 5000)} "-" "{ua}"'))

    # Normal traffic.
    paths = ["/", "/products", "/products?category=books&sort=price", "/about", "/contact", "/static/app.css"]
    for i in range(150):
        add(BASE + timedelta(seconds=i * 90), f"198.51.100.{random.randint(100, 140)}", "GET", random.choice(paths), 200)

    # SQL injection with sqlmap (some answered 200).
    t = BASE + timedelta(hours=2)
    payloads = ["/products?id=1'%20OR%20'1'='1", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
                "/products?id=1;%20DROP%20TABLE%20users", "/search?q=1%20AND%20SLEEP(5)", "/products?id=1%20AND%201=1"]
    for i, p in enumerate(payloads * 3):
        add(t + timedelta(seconds=i * 2), SQLI_IP, "GET", p, 200 if i % 4 == 0 else 500, "sqlmap/1.7.2#stable (https://sqlmap.org)")

    # Directory brute forcing: 60 x 404 inside 30 seconds.
    t = BASE + timedelta(hours=3)
    for i, name in enumerate(["admin", "backup", "config", "db", "old", "test", "login", "wp-admin"] * 8):
        add(t + timedelta(milliseconds=i * 400), SCAN_IP, "GET", f"/{name}{i}.php", 404, "Mozilla/5.0 (compatible; scanner)")

    # XSS and path traversal.
    t = BASE + timedelta(hours=5)
    add(t, XSS_IP, "GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200)
    add(t + timedelta(seconds=5), XSS_IP, "GET", "/download?file=../../../../etc/passwd", 404)
    add(t + timedelta(seconds=9), XSS_IP, "GET", "/download?file=%252e%252e%252f%252e%252e%252fetc/passwd", 404)

    lines.sort(key=lambda x: x[0])
    return [text for _, text in lines]


def main() -> None:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("sample_logs")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "auth.log").write_text("\n".join(build_auth()) + "\n", encoding="utf-8")
    (out_dir / "access.log").write_text("\n".join(build_web()) + "\n", encoding="utf-8")
    print(f"Wrote {out_dir / 'auth.log'} and {out_dir / 'access.log'}")


if __name__ == "__main__":
    main()
