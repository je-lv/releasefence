"""Shared data model: findings, file records, size limits and rule catalogue."""

from dataclasses import dataclass
from typing import Optional

ERROR = "error"
WARNING = "warning"

# rule_id -> (severity, short title).  IDs are stable; never renumber or reuse.
RULES = {
    "RF101": (ERROR, "symbolic link"),
    "RF102": (ERROR, "special file type (device, socket, FIFO or unknown)"),
    "RF103": (ERROR, "path escapes the input root"),
    "RF104": (ERROR, "absolute archive member path"),
    "RF105": (ERROR, "'..' traversal in archive member path"),
    "RF106": (ERROR, "backslash in path"),
    "RF107": (ERROR, "duplicate archive member name"),
    "RF108": (ERROR, "encrypted archive member"),
    "RF109": (ERROR, "file changed while being read"),
    "RF110": (ERROR, "file exceeds per-file size limit"),
    "RF111": (ERROR, "input exceeds total size limit"),
    "RF112": (ERROR, "unreadable or corrupt entry"),
    "RF113": (ERROR, "control, bidi or undecodable characters in path"),
    "RF114": (ERROR, "directory nesting too deep"),
    "RF115": (WARNING, "hard-linked file"),
    "RF116": (ERROR, "archive member name normalizes to the archive root"),
    "RF201": (ERROR, "private key PEM block"),
    "RF202": (ERROR, "Glassboard bearer token"),
    "RF203": (ERROR, "GitHub token"),
    "RF204": (ERROR, "OpenAI API key"),
    "RF301": (ERROR, "environment (.env) file"),
    "RF302": (ERROR, "credential-like file name"),
    "RF303": (ERROR, "version-control internals"),
    "RF304": (WARNING, "editor, OS or build junk"),
    "RF305": (WARNING, "unexpectedly large file"),
    "RF307": (WARNING, "possible credential file"),
}


# Advice printed once under the findings, for the rules present. Never part of
# a finding, so JSON stays compact.
_SECRET_HINT = "Secret values are never printed. Remove each secret and rotate it."
HINTS = {
    "RF101": "Symbolic links are never followed. Replace them with the files they point to.",
    "RF103": "Symbolic links are never followed. Replace them with the files they point to.",
    "RF201": _SECRET_HINT,
    "RF202": _SECRET_HINT,
    "RF203": _SECRET_HINT,
    "RF204": _SECRET_HINT,
    "RF301": "Publish a template such as .env.example instead of .env.",
}


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 10 * 1024 * 1024
    max_total_bytes: int = 100 * 1024 * 1024
    large_file_bytes: int = 5 * 1024 * 1024


@dataclass(frozen=True)
class FileRecord:
    """An ordinary file. sha256 is None when content was not fully read
    (size limit, encryption, read failure or change during read); every such
    case also produces an error finding."""

    path: str
    size: int
    sha256: Optional[str]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    message: str
    blocking: bool

    @classmethod
    def make(cls, rule_id, path, message):
        severity = RULES[rule_id][0]
        return cls(rule_id, severity, path, message, severity == ERROR)


# Rule documentation: rule_id -> (what it means, what to do). Rendered into
# docs/RULES.md by scripts/gen_rules_doc.py; a test keeps the two in sync.
RULE_DOCS = {
    "RF101": ("A directory entry or ZIP member is a symbolic link. ReleaseFence never follows links, so "
              "the content behind it was not inspected, and an extractor may write through it.",
              "Replace the link with the file it points to, or remove it."),
    "RF102": ("A device, socket, FIFO or other non-regular file. These have no place in a source release "
              "and some extractors recreate them.",
              "Remove it from the release."),
    "RF103": ("A path or symbolic link target resolves outside the input root.",
              "Remove the entry; a release must be self-contained."),
    "RF104": ("A ZIP member name is absolute, so a naive extractor writes it anywhere on disk.",
              "Rebuild the archive with relative member names."),
    "RF105": ("A ZIP member name contains a `..` segment (path traversal, \"zip slip\").",
              "Rebuild the archive without `..` in member names."),
    "RF106": ("A path contains a backslash: a separator on Windows, an ordinary character on POSIX. "
              "The same archive extracts to different trees on different systems.",
              "Use forward slashes only."),
    "RF107": ("Two ZIP members normalize to the same path, or a path is both a file and a directory. "
              "Extractors disagree on which copy wins, so a reviewer may inspect a different file "
              "from the one that gets installed.",
              "Rebuild the archive so every normalized path appears once."),
    "RF108": ("An encrypted ZIP member. Its content cannot be inspected.",
              "Publish without encryption, or inspect the content separately."),
    "RF109": ("A file or directory changed while it was being read: its size, metadata or type differed "
              "between checks. The report cannot vouch for it.",
              "Scan again when nothing is writing to the input."),
    "RF110": ("A file exceeds the per-file size limit and was not read. Default 10 MiB; set "
              "`max_file_bytes` in a policy.",
              "Check whether the file belongs in the release, or raise the limit."),
    "RF111": ("The input exceeds the total size limit; scanning stopped. Default 100 MiB; set "
              "`max_total_bytes` in a policy.",
              "Check the input, or raise the limit."),
    "RF112": ("An entry could not be listed, opened or read, or a ZIP entry is corrupt.",
              "Fix permissions or rebuild the archive, then scan again."),
    "RF113": ("A path contains control, bidirectional-override or undecodable characters. These can hide "
              "or disguise names in terminals and code review. The path is shown escaped.",
              "Rename the file."),
    "RF114": ("Directories are nested deeper than 256 levels; deeper levels were not scanned.",
              "Flatten the tree."),
    "RF115": ("A file has more than one hard link, so its content may be shared with a file outside "
              "the release.",
              "Confirm the content is meant to ship, or copy the file instead of linking it."),
    "RF116": ("A ZIP member name normalizes to the archive root (for example `.` or `/`) and names no file.",
              "Rebuild the archive without that member."),
    "RF201": ("A PEM `PRIVATE KEY` block. The report gives the line number, never the key.",
              "Remove the key from the release and rotate it."),
    "RF202": ("A bearer token in an `Authorization` header or the `gbt_` token format. The report gives "
              "the line number, never the token.",
              "Remove the token and revoke it."),
    "RF203": ("A GitHub token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` or `github_pat_`). The report "
              "gives the line number, never the token.",
              "Remove the token and revoke it in GitHub."),
    "RF204": ("An OpenAI API key. The report gives the line number, never the key.",
              "Remove the key and revoke it."),
    "RF301": ("A `.env` file (or `.env.*`, `*.env`). These usually hold real settings and secrets. "
              "Templates such as `.env.example` are allowed.",
              "Publish a template such as `.env.example` instead."),
    "RF302": ("A file name that is almost always a credential: SSH private keys, `.netrc`, "
              "`.git-credentials`, `credentials.json`, keystores, `.p12`, `.pfx` and similar.",
              "Remove it from the release."),
    "RF303": ("Version-control internals such as `.git`, `.hg` or `.svn`. They can carry full history, "
              "including removed secrets.",
              "Package from an export, not from the working copy."),
    "RF304": ("Editor, operating-system or build leftovers: `.DS_Store`, swap files, `__pycache__`, "
              "backup files and similar.",
              "Remove them, or add them to the packaging ignore list."),
    "RF305": ("A file larger than the large-file threshold. Default 5 MiB; set `large_file_bytes` in a policy.",
              "Confirm it belongs in the release."),
    "RF307": ("A `.pem` or `.key` file, or a tool config that often holds credentials (`.npmrc`, "
              "`.pypirc`). Public certificates are fine; private keys are not.",
              "Open it and confirm it is meant to be public."),
    "RF400": ("A file matches a `forbidden_globs` pattern in your policy.",
              "Remove the file, or change the policy."),
}
