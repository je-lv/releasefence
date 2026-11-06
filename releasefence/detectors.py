"""Name and content detectors.  Detectors only see bytes and path strings;
secret values are matched but never stored or returned."""

import re
import unicodedata

from .model import Finding

# Bytes of the previous chunk kept so a pattern spanning a chunk boundary matches.
OVERLAP = 1024

CONTENT_RULES = [
    (
        "RF201",
        re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
        "private key PEM block",
    ),
    (
        "RF202",
        re.compile(
            rb"(?i:authorization)[\"']?\s*[:=]\s*[\"']?(?i:bearer)\s+[A-Za-z0-9._~+/-]{20,}=*"
            rb"|\bgbt?_[A-Za-z0-9_-]{24,}"
        ),
        "Glassboard bearer token",
    ),
    (
        "RF203",
        re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
        "GitHub token",
    ),
    (
        "RF204",
        re.compile(
            rb"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}"
            rb"|\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"
            rb"|\bsk-[A-Za-z0-9]{48}\b"
        ),
        "OpenAI API key",
    ),
]


class ContentScanner:
    """Feed content chunk by chunk; reports the first line of each rule hit."""

    def __init__(self):
        self._tail = b""
        self._lines_before_tail = 0
        self._hits = {}

    def feed(self, chunk):
        if len(self._hits) == len(CONTENT_RULES):
            return
        buf = self._tail + chunk
        for rule_id, pattern, _ in CONTENT_RULES:
            if rule_id not in self._hits:
                match = pattern.search(buf)
                if match:
                    self._hits[rule_id] = self._lines_before_tail + buf.count(b"\n", 0, match.start()) + 1
        keep = buf[-OVERLAP:]
        self._lines_before_tail += buf.count(b"\n", 0, len(buf) - len(keep))
        self._tail = keep

    def findings(self, path):
        return [
            Finding.make(
                rule_id, path,
                f"{label}, line {self._hits[rule_id]}",
            )
            for rule_id, _, label in CONTENT_RULES
            if rule_id in self._hits
        ]


_ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults"}
_CREDENTIAL_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
    ".netrc", "_netrc", ".pgpass", ".git-credentials", ".htpasswd",
    "credentials", "credentials.json", "credentials.yml", "credentials.yaml", "credentials.xml",
    "secrets.json", "secrets.yml", "secrets.yaml", "secrets.toml",
    ".dockercfg", "token.json", "client_secret.json",
}
_CREDENTIAL_SUFFIXES = (".p12", ".pfx", ".ppk", ".kdbx", ".jks", ".keystore", ".gpg")
_POSSIBLE_CREDENTIAL_NAMES = {".npmrc", ".pypirc", ".dockerconfigjson"}
_POSSIBLE_CREDENTIAL_SUFFIXES = (".pem", ".key")
_VCS_DIRS = {".git", ".hg", ".svn", ".bzr", "CVS"}
_JUNK_NAMES = {".ds_store", "thumbs.db", "ehthumbs.db", "desktop.ini", "icon\r", ".directory"}
_JUNK_DIRS = {"__macosx", ".idea", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox"}
_JUNK_SUFFIXES = (".swp", ".swo", ".swn", ".pyc", ".pyo", ".orig", ".rej")


def name_findings(path, is_dir=False):
    """Findings for a normalized POSIX relative path.  Directory-level rules
    (VCS internals, junk directories) are reported on the directory prefix;
    callers deduplicate identical findings."""
    found = []
    parts = path.split("/")
    dir_parts = parts if is_dir else parts[:-1]
    for i, part in enumerate(dir_parts):
        prefix = "/".join(parts[: i + 1])
        if part in _VCS_DIRS:
            found.append(Finding.make("RF303", prefix, f"version-control directory '{part}' must not be published"))
        elif part.lower() in _JUNK_DIRS:
            found.append(Finding.make("RF304", prefix, f"editor/OS/build directory '{part}' is usually accidental"))
    if is_dir:
        return found

    name = parts[-1]
    lower = name.lower()
    if name == ".git":
        found.append(Finding.make("RF303", path, "'.git' pointer file must not be published"))
    if (lower == ".env" or lower.startswith(".env.") or lower.endswith(".env")) and lower not in _ENV_TEMPLATES:
        found.append(Finding.make("RF301", path, "environment file, likely holds secrets"))
    if lower in _CREDENTIAL_NAMES or lower.endswith(_CREDENTIAL_SUFFIXES) or lower.startswith("service-account"):
        found.append(Finding.make("RF302", path, "file name suggests credentials or key material"))
    elif lower in _POSSIBLE_CREDENTIAL_NAMES or lower.endswith(_POSSIBLE_CREDENTIAL_SUFFIXES):
        found.append(Finding.make("RF307", path, "may hold credentials or a private key"))
    if (
        lower in _JUNK_NAMES
        or lower.endswith(_JUNK_SUFFIXES)
        or name.startswith("._")
        or name.endswith("~")
        or name.startswith(".#")
        or (len(name) > 1 and name.startswith("#") and name.endswith("#"))
    ):
        found.append(Finding.make("RF304", path, "editor, OS or build junk file"))
    return found


_BIDI = {0x200E, 0x200F, 0x061C} | set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


def safe_path(raw):
    """Escape characters that could spoof a report: control and bidi
    characters and undecodable bytes (surrogate escapes from os.fsdecode).
    Returns (text, was_escaped)."""
    out = []
    escaped = False
    for ch in raw:
        code = ord(ch)
        if 0xDC80 <= code <= 0xDCFF:
            out.append(f"\\x{code - 0xDC00:02x}")
            escaped = True
        elif code < 0x20 or code == 0x7F or code in _BIDI or unicodedata.category(ch) in ("Cc", "Cs"):
            out.append(f"\\u{code:04x}")
            escaped = True
        else:
            out.append(ch)
    return "".join(out), escaped
