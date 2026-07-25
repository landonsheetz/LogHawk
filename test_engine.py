"""
Unit tests for the LogHawk engine.

Run from the project root with:
    python -m pytest -q
or, without pytest installed:
    python tests/test_engine.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loghawk.events import normalize
from loghawk.engine import run_rules, _event_matches


def _evt(**kwargs):
    return normalize(kwargs)


def test_exact_match_is_case_insensitive():
    event = _evt(process="PowerShell.exe")
    assert _event_matches(event, {"process": "powershell.exe"})


def test_contains_operator():
    event = _evt(command_line="powershell -enc ABC123")
    assert _event_matches(event, {"command_line|contains": "-enc"})
    assert not _event_matches(event, {"command_line|contains": "-decode"})


def test_in_operator():
    event = _evt(country="RU")
    assert _event_matches(event, {"country|in": ["RU", "KP"]})
    assert not _event_matches(event, {"country|in": ["US", "CA"]})


def test_match_rule_fires_once_per_event():
    rule = {
        "id": "T", "title": "t", "type": "match",
        "severity": "high", "selection": {"action": "login_success"},
    }
    events = [_evt(action="login_success"), _evt(action="login_failed")]
    alerts = run_rules([rule], events)
    assert len(alerts) == 1


def test_threshold_rule_requires_enough_events_in_window():
    rule = {
        "id": "BF", "title": "brute", "type": "threshold", "severity": "high",
        "filter": {"action": "login_failed"},
        "group_by": ["user"], "threshold": 3, "window_minutes": 5,
    }
    # Three failures within five minutes -> one alert.
    events = [
        _evt(action="login_failed", user="bob", timestamp="2024-01-01T00:00:00Z"),
        _evt(action="login_failed", user="bob", timestamp="2024-01-01T00:01:00Z"),
        _evt(action="login_failed", user="bob", timestamp="2024-01-01T00:02:00Z"),
    ]
    assert len(run_rules([rule], events)) == 1


def test_threshold_rule_below_count_stays_quiet():
    rule = {
        "id": "BF", "title": "brute", "type": "threshold", "severity": "high",
        "filter": {"action": "login_failed"},
        "group_by": ["user"], "threshold": 5, "window_minutes": 5,
    }
    events = [
        _evt(action="login_failed", user="bob", timestamp="2024-01-01T00:00:00Z"),
        _evt(action="login_failed", user="bob", timestamp="2024-01-01T00:01:00Z"),
    ]
    assert run_rules([rule], events) == []


def _run_all():
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok  -", name)
            passed += 1
    print("\n%d tests passed" % passed)


if __name__ == "__main__":
    _run_all()
