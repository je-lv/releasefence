"""Stable policy-aware report construction."""
from dataclasses import asdict
from fnmatch import fnmatchcase
from .inventory import scan_inventory
from .policy import Policy

def scan(path, policy=None):
    policy = policy or Policy()
    records, raw_findings = scan_inventory(path, policy.limits)
    files = sorted((asdict(r) for r in records), key=lambda r: r['path'])
    findings = [asdict(f) for f in raw_findings]
    for record in files:
        if any(fnmatchcase(record['path'], glob) for glob in policy.forbidden_globs):
            findings.append(dict(rule_id='RF400', severity='error', path=record['path'],
                                 message='File matches a policy forbidden glob.', blocking=True))
    active, suppressed = [], []
    for finding in findings:
        matches = [i for i in policy.ignore if i['rule_id'] == finding['rule_id'] and fnmatchcase(finding['path'], i['path_glob'])]
        if matches:
            suppressed.append(dict(finding, suppression=matches))
        else:
            active.append(finding)
    key = lambda f: (f['path'], f['rule_id'], f['message'])
    return dict(schema_version=1, files=files, findings=sorted(active, key=key),
                suppressions=sorted(suppressed, key=key), blocking=any(f['blocking'] for f in active))
