"""
The detection engine.

Two rule types are supported, which together cover a large share of what an
entry-level SOC actually alerts on:

  match      Single-event rules. Fire when one event matches a set of field
             conditions. Good for "this specific bad thing happened once",
             e.g. an encoded PowerShell command or a login from a blocked
             country. This is the same idea as a Sigma detection block.

  threshold  Stateful rules. Fire when the count of matching events for a
             group (say, same user + same source IP) crosses a threshold inside
             a rolling time window. Good for brute force, password spraying, and
             other volume-based behavior that a single event cannot reveal.

Field conditions support a few operators borrowed from Sigma:

    field: value            exact, case-insensitive match
    field|contains: value   substring match
    field|startswith: value
    field|endswith: value
    field|in: [a, b, c]     match any value in the list
"""

from collections import defaultdict
from datetime import timedelta


def _match_condition(event, field, operator, expected):
    """Evaluate one field condition against one event."""
    actual = str(event.get(field, "")).lower()

    if operator is None:
        return actual == str(expected).lower()
    if operator == "contains":
        return str(expected).lower() in actual
    if operator == "startswith":
        return actual.startswith(str(expected).lower())
    if operator == "endswith":
        return actual.endswith(str(expected).lower())
    if operator == "in":
        return actual in [str(item).lower() for item in expected]

    raise ValueError("Unsupported operator: %s" % operator)


def _event_matches(event, selection):
    """An event matches a selection when every condition in it is true (AND)."""
    for raw_field, expected in selection.items():
        if "|" in raw_field:
            field, operator = raw_field.split("|", 1)
        else:
            field, operator = raw_field, None
        if not _match_condition(event, field, operator, expected):
            return False
    return True


def _run_match_rule(rule, events):
    """Return one alert per event that satisfies the rule's selection block."""
    alerts = []
    selection = rule.get("selection", {})
    for event in events:
        if _event_matches(event, selection):
            alerts.append(_build_alert(rule, [event]))
    return alerts


def _run_threshold_rule(rule, events):
    """Fire when a group produces >= threshold matches inside the window."""
    alerts = []
    selection = rule.get("filter", {})
    group_fields = rule.get("group_by", [])
    threshold = int(rule.get("threshold", 1))
    window = timedelta(minutes=int(rule.get("window_minutes", 5)))

    # Bucket matching events by their group key, preserving time order.
    buckets = defaultdict(list)
    for event in events:
        if event["_dt"] is None:
            continue
        if _event_matches(event, selection):
            key = tuple(event.get(field, "") for field in group_fields)
            buckets[key].append(event)

    # Slide a window across each bucket. When enough events fall inside one
    # window, raise a single alert and skip past them so one burst does not
    # generate a flood of duplicate alerts.
    for key, bucket in buckets.items():
        i = 0
        while i < len(bucket):
            window_events = [bucket[i]]
            j = i + 1
            while j < len(bucket) and (bucket[j]["_dt"] - bucket[i]["_dt"]) <= window:
                window_events.append(bucket[j])
                j += 1
            if len(window_events) >= threshold:
                alerts.append(_build_alert(rule, window_events))
                i = j  # move past the burst we just alerted on
            else:
                i += 1
    return alerts


def _build_alert(rule, events):
    """Assemble a structured alert from a rule and its triggering events."""
    first = events[0]
    return {
        "rule_id": rule.get("id", "UNKNOWN"),
        "title": rule.get("title", "Untitled rule"),
        "severity": rule.get("severity", "medium"),
        "mitre": rule.get("mitre", ""),
        "description": rule.get("description", ""),
        "event_count": len(events),
        "timestamp": first.get("timestamp", ""),
        "user": first.get("user", ""),
        "source_ip": first.get("source_ip", ""),
        "host": first.get("host", ""),
        "sample_events": events[:5],  # cap the evidence attached to an alert
    }


# Severity order used when ranking alerts in reports.
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def run_rules(rules, events):
    """Run every rule against every event and return a sorted list of alerts."""
    alerts = []
    for rule in rules:
        rule_type = rule.get("type", "match")
        if rule_type == "match":
            alerts.extend(_run_match_rule(rule, events))
        elif rule_type == "threshold":
            alerts.extend(_run_threshold_rule(rule, events))
        else:
            raise ValueError("Unknown rule type '%s' in rule %s" % (rule_type, rule.get("id")))

    alerts.sort(key=lambda a: (SEVERITY_RANK.get(a["severity"], 9), a["timestamp"]))
    return alerts
