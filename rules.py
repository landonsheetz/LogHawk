"""Load detection rules from a directory of YAML files."""

import os
import yaml


REQUIRED_FIELDS = ("id", "title", "type")


def load_rules(rules_dir):
    """Read every .yml / .yaml file in a directory into a list of rule dicts.

    Each file may hold a single rule (a mapping) or several rules (a list).
    Rules missing required fields are rejected loudly so a typo does not
    silently disable detection.
    """
    rules = []
    for name in sorted(os.listdir(rules_dir)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(rules_dir, name)
        with open(path, "r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle)

        if loaded is None:
            continue
        candidates = loaded if isinstance(loaded, list) else [loaded]

        for rule in candidates:
            missing = [field for field in REQUIRED_FIELDS if field not in rule]
            if missing:
                raise ValueError(
                    "Rule in %s is missing required fields: %s" % (name, ", ".join(missing))
                )
            rules.append(rule)
    return rules
