# logguard - Log Analysis & Threat Detection Tool

A small, dependency-free Python tool that reads **SSH authentication logs** and **web server access logs**, detects common attacks with rules mapped to **MITRE ATT&CK**, and produces a **JSON alert file** and a **Markdown incident report**.

It is a learning/portfolio project that models what a SOC analyst or security engineer does with central logs: ingest, normalise, detect, triage, report. It is **not** a replacement for a real SIEM (Wazuh, Splunk, QRadar, Elastic).

## What it detects

| Rule | Log | Severity | MITRE ATT&CK |
|---|---|---|---|
| SSH brute force (N failures from one IP in a time window) | auth.log | High | T1110 |
| Password spraying / username enumeration | auth.log | High | T1110.003 |
| **Successful login after repeated failures** (likely compromise) | auth.log | Critical | T1078 |
| SQL injection, XSS, path traversal, command injection payloads | access.log | Medium-High (escalated if server returned HTTP 200) | T1190 |
| Directory / content brute-forcing (many 4xx) | access.log | Medium | T1595.003 |
| Known scanner tools (sqlmap, nikto, nmap, ...) in User-Agent | access.log | Medium | T1595.002 |
| Request flood from one IP | access.log | Medium | T1499 |

Design notes worth knowing:

- **Sliding-window bursts.** A 40-attempt attack raises *one* alert, not eight. See `find_bursts()` in `detectors.py`.
- **Double URL-decoding** catches payloads such as `%252e%252e%252f` (encoded twice) that simple filters miss.
- **Severity escalation heuristic.** If the server answered a malicious request with HTTP 200, the alert is raised one level. That does not prove exploitation, but it tells the analyst where to look first.
- **Rules can overlap.** One IP can trigger both "brute force" and "password spray". Correlating overlapping alerts into one case is a natural extension.
- All thresholds are configurable, because the right numbers depend on the environment.

## Quick start

Requires Python 3.9+ and nothing else. (Developed and tested on 3.13; the CI workflow in `.github/workflows/tests.yml` also runs the tests on 3.9 and 3.11.)

```bash
# 1. Generate synthetic logs that contain known attacks
python scripts/generate_sample_logs.py sample_logs

# 2. Analyse them
python -m logguard --auth sample_logs/auth.log --web sample_logs/access.log --year 2026 --out reports

# 3. Read the results
cat reports/incident_report.md      # human-readable report
cat reports/alerts.json             # machine-readable alerts
```

Useful options:

```text
--brute-threshold 10      failures that trigger a brute-force alert (default 5)
--brute-window 600        window in seconds (default 300)
--fail-on high            exit code 2 if any alert >= high  (use in CI / cron / scripts)
--year 2026               auth.log has no year; set it explicitly
```

The sample logs use only RFC 5737 documentation IP addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so no real host or person is involved.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

27 tests cover the parsers, the burst algorithm, every rule, false-positive cases (a user mistyping a password once, benign search terms like `union station`) and an end-to-end run.

## Project structure

```text
logguard/
  models.py      dataclasses: AuthEvent, WebEvent, Alert
  parsers.py     regex parsers for sshd syslog lines and combined access logs
  detectors.py   detection rules + sliding-window helper + MITRE mapping
  report.py      JSON and Markdown report writers
  cli.py         argparse command line
scripts/generate_sample_logs.py   deterministic synthetic attack data
tests/test_logguard.py            unit + integration tests
```

## Limitations (be honest about these in an interview)

- Rule-based heuristics only; no baselining or machine learning. Low-and-slow attacks that stay under the thresholds will be missed.
- Possible false positives: a user mistyping a password repeatedly, an authorised vulnerability scan, many users behind one NAT address.
- Only two log formats are supported, and logs are processed in batch rather than streamed.
- Source IPs are not enriched (no GeoIP or threat-intelligence lookups).

## Ideas for extending it

- Enrich IPs with threat-intelligence feeds (AbuseIPDB) and GeoIP.
- Stream logs (`tail -f`) and emit alerts to Slack/email or a webhook.
- Correlate alerts into incidents per source IP.
- Add Windows Event Log (4625/4624) support.
- Export alerts in a SIEM-friendly format (CEF / ECS JSON) and forward to Elastic or Wazuh.
- Add a Dockerfile, and a scheduled GitHub Actions run that analyses real (anonymised) logs.
- Added detect_root_login (T1078.003), with 3 tests.

## Author

Built as a hands-on security engineering practice project. MIT-style use for learning purposes.
