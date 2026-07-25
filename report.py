"""Turn a list of alerts into a console summary and a self-contained HTML report."""

import html
from collections import Counter


def console_summary(alerts):
    """Return a plain-text summary suitable for terminal output or a log file."""
    if not alerts:
        return "No detections. 0 alerts raised."

    lines = []
    counts = Counter(a["severity"] for a in alerts)
    header = "  ".join("%s=%d" % (sev, counts[sev]) for sev in
                       ("critical", "high", "medium", "low", "info") if counts[sev])
    lines.append("%d alert(s) raised   [%s]" % (len(alerts), header))
    lines.append("-" * 68)

    for alert in alerts:
        lines.append("[%s] %s" % (alert["severity"].upper(), alert["title"]))
        lines.append("    rule:   %s   mitre: %s" % (alert["rule_id"], alert["mitre"] or "n/a"))
        detail = "    when:   %s   user: %s   src: %s   host: %s" % (
            alert["timestamp"] or "n/a",
            alert["user"] or "n/a",
            alert["source_ip"] or "n/a",
            alert["host"] or "n/a",
        )
        lines.append(detail)
        if alert["event_count"] > 1:
            lines.append("    events: %d matched inside the detection window" % alert["event_count"])
        lines.append("")
    return "\n".join(lines)


_SEV_COLORS = {
    "critical": "#7b1113",
    "high": "#b3261e",
    "medium": "#c77700",
    "low": "#3b7a57",
    "info": "#4a5568",
}


def html_report(alerts, source_name=""):
    """Return a single HTML string. No external files, so it opens anywhere."""
    counts = Counter(a["severity"] for a in alerts)
    cards = "".join(
        '<div class="stat"><span class="num">%d</span><span class="lbl">%s</span></div>'
        % (counts.get(sev, 0), sev)
        for sev in ("critical", "high", "medium", "low", "info")
    )

    rows = []
    for alert in alerts:
        color = _SEV_COLORS.get(alert["severity"], "#4a5568")
        rows.append(
            "<tr>"
            '<td><span class="pill" style="background:%s">%s</span></td>'
            "<td><strong>%s</strong><br><span class=\"muted\">%s</span></td>"
            "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "</tr>"
            % (
                color,
                html.escape(alert["severity"]),
                html.escape(alert["title"]),
                html.escape(alert["description"] or ""),
                html.escape(alert["mitre"] or "n/a"),
                html.escape(alert["timestamp"] or "n/a"),
                html.escape(alert["user"] or "n/a"),
                html.escape(alert["source_ip"] or "n/a"),
                html.escape(str(alert["event_count"])),
            )
        )
    table_body = "".join(rows) if rows else '<tr><td colspan="7">No detections.</td></tr>'

    return _TEMPLATE % {
        "source": html.escape(source_name),
        "total": len(alerts),
        "cards": cards,
        "rows": table_body,
    }


_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LogHawk Detection Report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #f4f5f7; color: #1a202c; }
  header { background: #12233b; color: #fff; padding: 24px 32px; }
  header h1 { margin: 0; font-size: 22px; }
  header p { margin: 6px 0 0; color: #9fb3c8; font-size: 13px; }
  .stats { display: flex; gap: 16px; padding: 24px 32px; }
  .stat { background: #fff; border-radius: 8px; padding: 16px 22px; box-shadow: 0 1px 3px rgba(0,0,0,.08); text-align: center; }
  .stat .num { display: block; font-size: 26px; font-weight: 700; }
  .stat .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #718096; }
  table { width: calc(100%% - 64px); margin: 0 32px 40px; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  th, td { text-align: left; padding: 11px 14px; font-size: 13px; border-bottom: 1px solid #edf2f7; vertical-align: top; }
  th { background: #edf2f7; text-transform: uppercase; font-size: 11px; letter-spacing: .04em; color: #4a5568; }
  .pill { color: #fff; padding: 3px 9px; border-radius: 20px; font-size: 11px; text-transform: uppercase; }
  .muted { color: #718096; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>LogHawk Detection Report</h1>
  <p>Source: %(source)s &nbsp;|&nbsp; Total alerts: %(total)d</p>
</header>
<div class="stats">%(cards)s</div>
<table>
  <thead><tr>
    <th>Severity</th><th>Detection</th><th>MITRE</th><th>First seen</th>
    <th>User</th><th>Source IP</th><th>Events</th>
  </tr></thead>
  <tbody>%(rows)s</tbody>
</table>
</body>
</html>
"""
