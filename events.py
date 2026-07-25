"""
Event loading and normalization.

LogHawk works on a single normalized event schema so that detection rules do not
have to care where a log came from. Real SOC pipelines do the same thing: raw
Windows Security events, sshd auth logs, and cloud audit trails all get mapped
onto a common shape before detection runs.

Normalized fields used by the rules in this project:

    timestamp     ISO 8601 string, e.g. "2024-11-02T14:03:11Z"
    event_type    "authentication" | "process" | "account"
    action        "login_failed" | "login_success" | "process_start" | ...
    user          account name the event is about
    source_ip     originating IP (may be empty for local events)
    host          the machine that produced the event
    process       process name for process events
    command_line  full command line for process events
    country       resolved country code for source_ip (optional)
"""

import json
from datetime import datetime, timezone


# Fields every event is guaranteed to have after normalization, so rules can
# reference them without KeyErrors.
_DEFAULTS = {
    "timestamp": "",
    "event_type": "",
    "action": "",
    "user": "",
    "source_ip": "",
    "host": "",
    "process": "",
    "command_line": "",
    "country": "",
}


def parse_timestamp(value):
    """Turn an ISO 8601 string into a timezone-aware datetime.

    Returns None if the value cannot be parsed, which lets the engine skip
    malformed records instead of crashing on a single bad line.
    """
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def normalize(raw):
    """Fill in missing fields and coerce everything to strings LogHawk expects."""
    event = dict(_DEFAULTS)
    for key, default in _DEFAULTS.items():
        if key in raw and raw[key] is not None:
            event[key] = str(raw[key])
    event["_dt"] = parse_timestamp(event["timestamp"])
    return event


def load_events(path):
    """Load events from a JSON file.

    Two formats are accepted:
      1. A JSON array of event objects.
      2. JSON Lines (one event object per line), which is closer to how real
         log shippers emit data.
    """
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read().strip()

    records = []
    if text.startswith("["):
        records = json.loads(text)
    else:
        for line in text.splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))

    events = [normalize(record) for record in records]
    # Sort by parsed time so threshold windows behave predictably. Events with
    # unparseable timestamps sink to the end rather than breaking the sort.
    events.sort(key=lambda e: (e["_dt"] is None, e["_dt"] or datetime.max.replace(tzinfo=timezone.utc)))
    return events
