#!/usr/bin/env python3
"""Render the rule catalogue as docs/RULES.md. Run from the repository root:
    python scripts/gen_rules_doc.py > docs/RULES.md
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from releasefence.model import RULE_DOCS, RULES  # noqa: E402

CATALOGUE = dict(RULES, RF400=("error", "file matches a policy forbidden glob"))

print("# ReleaseFence rules")
print()
print("Generated from `releasefence/model.py` by `scripts/gen_rules_doc.py`. Do not edit by hand.")
print()
print("Errors block: `scan` exits 1 and `manifest` refuses to write. Warnings are reported "
      "but do not block. A policy can suppress any rule for named paths; suppressions are "
      "listed in the JSON report.")
print()
print("| ID | Severity | Title |")
print("|---|---|---|")
for rule_id in sorted(CATALOGUE):
    severity, title = CATALOGUE[rule_id]
    print(f"| [{rule_id}](#{rule_id.lower()}) | {severity} | {title} |")
print()
for rule_id in sorted(CATALOGUE):
    severity, title = CATALOGUE[rule_id]
    description, remediation = RULE_DOCS[rule_id]
    print(f"## {rule_id}")
    print()
    print(f"**{title[0].upper() + title[1:]}** ({severity})")
    print()
    print(description)
    print()
    print(f"**Fix:** {remediation}")
    print()
