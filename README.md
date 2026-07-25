# LogHawk

A detection-as-code engine for security event logs. Point it at a log file and a
folder of YAML detection rules, and it raises structured alerts mapped to MITRE
ATT&CK, then writes an HTML report you can hand to an analyst.

The point of this project is to show that detection logic belongs in version
control, tested and reviewable, the same way application code is. That is the
core idea behind modern detection engineering, and it is how SOC and detection
teams at larger shops actually operate.

## What it detects out of the box

| Rule | Technique | Type |
|------|-----------|------|
| Brute force against a single account | T1110.001 | threshold |
| Password spray from one source | T1110.003 | threshold |
| Successful login from a blocked country | T1078 | match |
| Encoded PowerShell execution | T1059.001 | match |
| certutil used to download a file (LOLBin) | T1105 | match |
| Command shell spawned by an Office app | T1204.002 | match |
| Account added to a privileged group | T1098 | match |
| Login to a disabled account | T1078.002 | match |

## Quick start

```bash
pip install -r requirements.txt
python -m loghawk --logs sample_logs/auth_events.json --rules rules --html report.html
```

You will see a console summary and a `report.html` you can open in any browser.
The bundled sample log has seven attacks seeded into normal traffic, so every
rule fires and you can confirm the engine works before writing your own rules.

## How it works

1. **Normalize.** Every raw log is mapped onto one common event schema
   (`loghawk/events.py`) so rules never care about the source format. Real
   pipelines normalize Windows, Linux, and cloud logs the same way.
2. **Load rules.** YAML files in `rules/` are parsed and validated
   (`loghawk/rules.py`). A missing required field fails loudly instead of
   silently disabling a detection.
3. **Evaluate.** The engine (`loghawk/engine.py`) runs two rule types:
   - `match` rules fire on a single event that satisfies a set of field
     conditions, using Sigma-style operators (`contains`, `startswith`, `in`).
   - `threshold` rules aggregate events by a group key inside a rolling time
     window, which is what catches brute force and spraying.
4. **Report.** Alerts are ranked by severity and rendered to console and to a
   self-contained HTML file (`loghawk/report.py`).

## Writing your own rule

A single-event rule:

```yaml
- id: PROC-ENCODED-POWERSHELL
  title: Encoded PowerShell command execution
  severity: high
  mitre: T1059.001
  type: match
  selection:
    process|contains: powershell
    command_line|contains: "-enc"
```

A volume-based rule:

```yaml
- id: AUTH-BRUTE-FORCE-USER
  title: Brute force against a single account
  severity: high
  mitre: T1110.001
  type: threshold
  filter:
    action: login_failed
  group_by: [user, source_ip]
  threshold: 5
  window_minutes: 5
```

## Wiring into CI

`--fail-on high` makes LogHawk exit non-zero if anything at or above `high`
fires. Drop it into a pipeline and a log full of attacks fails the build, which
is one way teams test detections against known-bad sample data automatically.

```bash
python -m loghawk --logs sample_logs/auth_events.json --rules rules --fail-on high
```

## Tests

```bash
python tests/test_engine.py      # no dependencies
# or
python -m pytest -q              # if pytest is installed
```

## Layout

```
loghawk/        engine, event normalization, rule loader, reporting, CLI
rules/          YAML detection rules grouped by category
sample_logs/    JSONL sample with seeded attacks
tests/          unit tests for the matching and threshold logic
```

## Honest scope

This is a portfolio-scale engine, not a SIEM. It reads a static file rather than
a live stream, ships a small rule set, and resolves geoIP from a field already
present in the log instead of a real database. The design leaves obvious room to
grow: streaming input, a larger rule library, and enrichment lookups.
