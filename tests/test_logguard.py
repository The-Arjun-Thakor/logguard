"""Unit tests. Run with:  python -m unittest discover -s tests -v   (or pytest)."""

import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logguard.detectors import (  # noqa: E402
    Thresholds,
    detect_request_flood,
    detect_root_login,
    detect_scanner_user_agents,
    detect_ssh_brute_force,
    detect_ssh_password_spray,
    detect_success_after_failures,
    detect_web_attack_patterns,
    detect_web_scanning,
    find_bursts,
    run_all,
)
from logguard.models import AuthEvent, WebEvent  # noqa: E402
from logguard.parsers import parse_auth_line, parse_web_line  # noqa: E402

T0 = datetime(2026, 10, 10, 8, 0, 0)


def fail(sec, user="root", ip="203.0.113.5", invalid=False):
    return AuthEvent(T0 + timedelta(seconds=sec), "h", "failed", "password", user, ip, 22, invalid)


def ok(sec, user="alice", ip="203.0.113.5"):
    return AuthEvent(T0 + timedelta(seconds=sec), "h", "accepted", "password", user, ip, 22)


def req(sec, path="/", status=200, ip="203.0.113.7", ua="Mozilla/5.0"):
    return WebEvent(T0 + timedelta(seconds=sec), ip, "GET", path, "HTTP/1.1", status, 100, "-", ua)


class ParserTests(unittest.TestCase):
    def test_failed_password_valid_user(self):
        line = "Oct 10 08:15:32 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2"
        e = parse_auth_line(line, 2026)
        self.assertEqual((e.outcome, e.user, e.ip, e.port, e.invalid_user), ("failed", "root", "203.0.113.5", 52341, False))
        self.assertEqual(e.timestamp, datetime(2026, 10, 10, 8, 15, 32))

    def test_failed_password_invalid_user(self):
        line = "Oct  1 08:15:32 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2"
        e = parse_auth_line(line, 2026)  # single-digit day is padded with two spaces
        self.assertTrue(e.invalid_user)
        self.assertEqual(e.user, "admin")
        self.assertEqual(e.timestamp.day, 1)

    def test_accepted(self):
        line = "Oct 10 08:15:32 web01 sshd[1234]: Accepted publickey for alice from 198.51.100.10 port 40000 ssh2"
        e = parse_auth_line(line, 2026)
        self.assertEqual((e.outcome, e.method, e.user), ("accepted", "publickey", "alice"))

    def test_non_ssh_line_ignored(self):
        self.assertIsNone(parse_auth_line("Oct 10 08:00:00 web01 CRON[1]: session opened", 2026))

    def test_web_line(self):
        line = '203.0.113.7 - - [10/Oct/2026:08:00:01 +0200] "GET /a?b=1 HTTP/1.1" 404 512 "-" "curl/8.0"'
        e = parse_web_line(line)
        self.assertEqual((e.ip, e.status, e.path, e.user_agent), ("203.0.113.7", 404, "/a?b=1", "curl/8.0"))
        self.assertEqual(e.timestamp, datetime(2026, 10, 10, 6, 0, 1))  # normalised to UTC

    def test_web_line_garbage(self):
        self.assertIsNone(parse_web_line("not a log line"))


class BurstTests(unittest.TestCase):
    def test_burst_extends_to_one_alert(self):
        evs = [fail(i * 3) for i in range(40)]
        bursts = find_bursts(evs, 300, 5)
        self.assertEqual(len(bursts), 1)
        self.assertEqual(len(bursts[0]), 40)

    def test_below_threshold_no_burst(self):
        self.assertEqual(find_bursts([fail(i) for i in range(4)], 300, 5), [])

    def test_slow_attempts_outside_window(self):
        self.assertEqual(find_bursts([fail(i * 400) for i in range(10)], 300, 5), [])


class SshRuleTests(unittest.TestCase):
    th = Thresholds()

    def test_brute_force_detected(self):
        alerts = detect_ssh_brute_force([fail(i) for i in range(8)], self.th)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].mitre_id, "T1110")
        self.assertEqual(alerts[0].count, 8)

    def test_typo_is_not_brute_force(self):
        self.assertEqual(detect_ssh_brute_force([fail(0, "bob"), ok(9, "bob")], self.th), [])

    def test_separate_ips_not_combined(self):
        evs = [fail(i, ip=f"203.0.113.{i}") for i in range(10)]
        self.assertEqual(detect_ssh_brute_force(evs, self.th), [])

    def test_password_spray(self):
        evs = [fail(i * 10, user=f"user{i}", invalid=True) for i in range(6)]
        alerts = detect_ssh_password_spray(evs, self.th)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].mitre_id, "T1110.003")

    def test_same_user_is_not_spray(self):
        self.assertEqual(detect_ssh_password_spray([fail(i) for i in range(10)], self.th), [])

    def test_success_after_failures_is_critical(self):
        evs = [fail(i * 5, user="carol") for i in range(4)] + [ok(40, user="carol")]
        alerts = detect_success_after_failures(evs, self.th)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "critical")
        self.assertEqual(alerts[0].details["account"], "carol")

    def test_success_from_other_ip_not_flagged(self):
        evs = [fail(i * 5) for i in range(5)] + [ok(40, ip="198.51.100.9")]
        self.assertEqual(detect_success_after_failures(evs, self.th), [])

    def test_root_login_flagged(self):
        alerts = detect_root_login([ok(0, user="root", ip="203.0.113.9")], self.th)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].mitre_id, "T1078.003")
        self.assertEqual(alerts[0].source_ip, "203.0.113.9")

    def test_normal_user_login_not_flagged_as_root(self):
        self.assertEqual(detect_root_login([ok(0, user="alice")], self.th), [])

    def test_failed_root_login_not_flagged_as_root_login(self):
        self.assertEqual(detect_root_login([fail(0, user="root")], self.th), [])


class WebRuleTests(unittest.TestCase):
    th = Thresholds()

    def test_sql_injection(self):
        alerts = detect_web_attack_patterns([req(0, "/p?id=1%20UNION%20SELECT%20a,b%20FROM%20users", 500)], self.th)
        self.assertEqual(alerts[0].rule, "web_sql_injection")
        self.assertEqual(alerts[0].severity, "high")

    def test_http_200_escalates_severity(self):
        alerts = detect_web_attack_patterns([req(0, "/p?id=1'%20OR%20'1'='1", 200)], self.th)
        self.assertEqual(alerts[0].severity, "critical")

    def test_double_encoded_traversal(self):
        alerts = detect_web_attack_patterns([req(0, "/d?f=%252e%252e%252f%252e%252e%252fetc/passwd", 404)], self.th)
        self.assertEqual(alerts[0].rule, "web_path_traversal")

    def test_xss(self):
        alerts = detect_web_attack_patterns([req(0, "/s?q=%3Cscript%3Ealert(1)%3C/script%3E", 200)], self.th)
        self.assertEqual(alerts[0].rule, "web_xss")

    def test_benign_requests_no_alert(self):
        evs = [req(0, "/products?category=books&sort=price"), req(1, "/search?q=union+station"), req(2, "/about")]
        self.assertEqual(detect_web_attack_patterns(evs, self.th), [])

    def test_content_scanning(self):
        evs = [req(i, f"/x{i}.php", 404) for i in range(25)]
        alerts = detect_web_scanning(evs, self.th)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].mitre_id, "T1595.003")

    def test_few_404s_not_scanning(self):
        self.assertEqual(detect_web_scanning([req(i, "/x", 404) for i in range(5)], self.th), [])

    def test_scanner_user_agent(self):
        alerts = detect_scanner_user_agents([req(0, ua="sqlmap/1.7")], self.th)
        self.assertEqual(len(alerts), 1)
        self.assertIn("sqlmap", alerts[0].title)

    def test_flood(self):
        evs = [req(i * 0.01) for i in range(250)]
        self.assertEqual(len(detect_request_flood(evs, self.th)), 1)


class IntegrationTests(unittest.TestCase):
    def test_clean_traffic_produces_no_alerts(self):
        auth = [ok(0, "alice", "198.51.100.10"), ok(100, "bob", "198.51.100.11")]
        web = [req(i * 60, "/products") for i in range(20)]
        self.assertEqual(run_all(auth, web), [])

    def test_alerts_sorted_worst_first_and_numbered(self):
        auth = [fail(i, ip="203.0.113.5") for i in range(6)] + [ok(30, ip="203.0.113.5")]
        alerts = run_all(auth, [])
        self.assertEqual(alerts[0].severity, "critical")
        self.assertEqual(alerts[0].alert_id, "LG-0001")


if __name__ == "__main__":
    unittest.main()
