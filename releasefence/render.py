"""Text report for people: findings grouped by file, verdict last.

Standard library only. Colour is used when stdout is a terminal, unless
NO_COLOR is set or TERM is "dumb"; FORCE_COLOR turns it on for pipes.
Output is deterministic: no timings, no absolute paths beyond the target
the user typed.
"""
import os
import textwrap
import unicodedata

from .detectors import safe_path
from .model import HINTS, RULE_DOCS

# 24-bit colours; terminals without truecolor approximate them.
_SGR = {
    "error": "1;38;2;255;51;102",
    "warning": "38;2;255;149;0",
    "rule": "38;2;122;162;247",
    "count": "38;2;0;240;255",
    "ok": "38;2;0;255;136",
    "dim": "38;5;245",
    "bold": "1",
    "error_badge": "1;7;38;2;255;51;102",
    "ok_badge": "1;7;38;2;0;255;136",
}

_CHANGE_STYLE = {"added": "ok", "removed": "error", "changed": "warning"}


def use_color(stream, environ=None):
    env = os.environ if environ is None else environ
    if env.get("NO_COLOR"):
        return False
    if env.get("FORCE_COLOR", "") not in ("", "0"):
        return True
    if env.get("TERM") == "dumb":
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def _clean(text):
    # Paths and messages are already escaped by the scanner; escaping again is
    # a no-op for clean text and keeps control characters off the terminal.
    return safe_path(str(text))[0]


def _width(text):
    """Terminal columns: wide East Asian characters take two."""
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in text)


class _Painter:
    def __init__(self, color):
        self.color = color

    def __call__(self, text, style):
        if not self.color or not style:
            return text
        return f"\x1b[{_SGR[style]}m{text}\x1b[0m"


def _size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _explain(rule_id, p):
    """Verbose lines under a finding: what the rule means and how to fix it."""
    doc = RULE_DOCS.get(rule_id)
    if not doc:
        return []
    description, fix = (text.replace("`", "") for text in doc)
    out = [p(line, "dim") for line in textwrap.wrap(description, 74,
                                                       initial_indent=" " * 22, subsequent_indent=" " * 22,
                                                       break_on_hyphens=False)]
    out += [p(line, "dim") for line in textwrap.wrap("fix: " + fix, 74,
                                                       initial_indent=" " * 22, subsequent_indent=" " * 27,
                                                       break_on_hyphens=False)]
    return out


def _finding_lines(found, p, verbose):
    lines = []
    for f in found:
        sev = f["severity"]
        lines.append(f"      {p(f'{sev:<8}', sev)} {p(f['rule_id'], 'rule')}  {_clean(f['message'])}")
        if verbose:
            lines.extend(_explain(f["rule_id"], p))
    return lines


def _ordered(items):
    groups = {}
    for f in items:
        groups.setdefault(f["path"], []).append(f)
    # Files with blocking findings first, then warning-only files; by path within each.
    order = sorted(groups, key=lambda path: (not any(f["blocking"] for f in groups[path]), path))
    return [(path, sorted(groups[path], key=lambda f: (not f["blocking"], f["rule_id"], f["message"])))
            for path in order]


def render_text(report, command, target, color=False, manifest_written=None, verbose=False):
    """Return the text report as one string ending in a newline.

    command is "scan", "manifest" or "verify". manifest_written is the output
    path when a manifest was written, or False when it was refused. verbose
    adds rule explanations, suppressed findings and the clean files.
    """
    p = _Painter(color)
    findings = report["findings"]
    suppressions = report["suppressions"]
    changes = report.get("changes", [])
    files = report["files"]
    lines = []

    verb = {"scan": "scanned", "manifest": "scanned", "verify": "verified"}[command]
    lines.append(f"{p('releasefence', 'bold')}  {p(verb, 'dim')} {_clean(target)}  "
                 f"{p(str(len(files)), 'count')} {'file' if len(files) == 1 else 'files'}")

    groups = _ordered(findings)
    hidden = _ordered(suppressions) if verbose else []
    flagged = {f["path"] for f in findings} | {f["path"] for f in suppressions}
    clean = [r for r in files if r["path"] not in flagged] if verbose else []
    # Pad paths so the [n findings] counts line up; very long paths do not
    # push the column out for everyone else.
    widths = (_width(_clean(path)) for path in [g[0] for g in groups + hidden] + [r["path"] for r in clean])
    column = max((w for w in widths if w <= 40), default=0)

    def head(marker, path, label, style="bold"):
        shown = _clean(path)
        pad = " " * max(column - _width(shown), 0)
        return f"{marker} {p(shown, style)}{pad}   {label}"

    def count(n, word):
        return f"[{p(str(n), 'count')} {word if n == 1 else word + 's'}]"

    for path, found in groups:
        blocking = any(f["blocking"] for f in found)
        marker = p("[x]", "error") if blocking else p("[!]", "warning")
        lines.append("")
        lines.append(head(marker, path, count(len(found), "finding")))
        lines.extend(_finding_lines(found, p, verbose))

    for path, found in hidden:
        lines.append("")
        lines.append(head(p("[s]", "dim"), path, f"[{p(str(len(found)), 'count')} suppressed]", "dim"))
        for f in found:
            sev = f["severity"]
            lines.append(p(f"      {sev:<8} {f['rule_id']}  {_clean(f['message'])}", "dim"))
            for entry in f.get("suppression", []):
                lines.append(p(f"                      suppressed by policy: {_clean(entry['rule_id'])} "
                               f"{_clean(entry['path_glob'])}", "dim"))

    if changes:
        lines.append("")
        lines.append(f"{p('[~]', 'warning')} {p('changes since the manifest', 'bold')}   "
                     f"{count(len(changes), 'change')}")
        for c in changes:
            kind = c["change"]
            lines.append(f"      {p(f'{kind:<8}', _CHANGE_STYLE[kind])} {_clean(c['path'])}")

    if clean:
        lines.append("")
        for r in clean:
            digest = f"sha256 {r['sha256'][:12]}" if r["sha256"] else "not read"
            lines.append(head(p("[-]", "ok"), r["path"], p(f"{_size(r['size']):>9}  {digest}", "dim"), None))

    if not verbose:
        hints = []
        for rule_id in sorted({f["rule_id"] for f in findings}):
            hint = HINTS.get(rule_id)
            if hint and hint not in hints:
                hints.append(hint)
        if hints:
            lines.append("")
            lines.extend(p(h, "dim") for h in hints)

    errors = sum(1 for f in findings if f["blocking"])
    warnings = len(findings) - errors
    if report["blocking"]:
        badge = p(" BLOCKED ", "error_badge") if color else "BLOCKED"
    else:
        badge = p(" OK ", "ok_badge") if color else "OK"
    counts = []
    if not findings and not changes:
        counts.append("no findings" if command != "verify" else "matches the manifest")
    if errors:
        counts.append(f"{p(str(errors), 'count')} {'error' if errors == 1 else 'errors'}")
    if warnings:
        counts.append(f"{p(str(warnings), 'count')} {'warning' if warnings == 1 else 'warnings'}")
    if changes:
        counts.append(f"{p(str(len(changes)), 'count')} {'change' if len(changes) == 1 else 'changes'}")
    if suppressions:
        more = "" if verbose else " (see -v)"
        counts.append(f"{p(str(len(suppressions)), 'count')} suppressed by policy{more}")
    lines.append("")
    lines.append(f"{badge}  " + "  ".join(counts))

    if manifest_written:
        lines.append(f"{p('wrote', 'ok')} {_clean(manifest_written)}  "
                     f"{p(str(len(files)), 'count')} {'file' if len(files) == 1 else 'files'}")
    elif manifest_written is False:
        lines.append(p("manifest not written: fix the errors above first", "error"))
    return "\n".join(lines) + "\n"
