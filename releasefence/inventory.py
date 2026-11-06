"""Streaming inventory of a directory or ZIP archive.

Content is only read as bytes: nothing is extracted, executed, imported or
rendered, and symlinks are never followed.  Directory traversal uses
directory file descriptors with O_NOFOLLOW so an entry swapped for a symlink
during the scan is detected rather than followed.
"""

import errno
import hashlib
import os
import re
import stat
import zipfile
import zlib

from .detectors import ContentScanner, name_findings, safe_path
from .model import FileRecord, Finding, Limits

CHUNK_SIZE = 64 * 1024
MAX_DEPTH = 256

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)


class ScanInputError(ValueError):
    """The input itself cannot be scanned (exit status 2)."""


class _State:
    def __init__(self, limits):
        self.limits = limits
        self.records = []
        self.findings = []
        self.total_read = 0
        self.total_exceeded = False

    def add(self, rule_id, path, message):
        self.findings.append(Finding.make(rule_id, path, message))

    def note_path(self, raw, is_dir=False):
        """Validate a relative path, emit name findings, return display path."""
        path, escaped = safe_path(raw)
        if escaped:
            self.add("RF113", path, "path contains control, bidi or undecodable characters (shown escaped)")
        if "\\" in raw:
            self.add("RF106", path, "backslash in path is ambiguous across platforms")
        self.findings.extend(name_findings(path, is_dir))
        return path

    def record(self, path, size, sha):
        if size > self.limits.large_file_bytes:
            self.add("RF305", path, f"size {size} bytes exceeds large-file threshold {self.limits.large_file_bytes}")
        self.records.append(FileRecord(path, size, sha))

    def stream(self, path, read, declared_size, stop_beyond_declared=False):
        """Hash and scan content from read(n) within the limits.
        Returns (sha256 hex or None if not fully read, bytes read).

        Each read request is bounded by the remaining per-file and total
        budgets (+1 byte to detect overflow), and every returned byte counts
        toward the total, including bytes of files that end up rejected."""
        limits = self.limits
        if self.total_exceeded:
            return None, 0
        if declared_size > limits.max_file_bytes:
            self.add("RF110", path, f"size {declared_size} exceeds per-file limit {limits.max_file_bytes}; not read")
            return None, 0
        digest = hashlib.sha256()
        scanner = ContentScanner()
        count = 0
        sha = None
        while True:
            budget = min(CHUNK_SIZE, limits.max_file_bytes - count + 1, limits.max_total_bytes - self.total_read + 1)
            if stop_beyond_declared:
                budget = min(budget, declared_size - count + 1)
            chunk = read(budget)
            if not chunk:
                sha = digest.hexdigest()
                break
            count += len(chunk)
            self.total_read += len(chunk)
            scanner.feed(chunk)
            if self.total_read > limits.max_total_bytes:
                # Latched first so no later read gets a zero budget and
                # mistakes an empty read for an empty file.
                self.total_exceeded = True
                self.add("RF111", path,
                         f"total streamed size exceeds limit {limits.max_total_bytes}; remaining content not read")
                break
            if stop_beyond_declared and count > declared_size:
                break  # grew while being read; the caller reports RF109
            if count > limits.max_file_bytes:
                self.add("RF110", path, f"streamed size exceeds per-file limit {limits.max_file_bytes}; reading stopped")
                break
            digest.update(chunk)
        self.findings.extend(scanner.findings(path))
        return sha, count


def scan_inventory(path, limits=None):
    """Inventory a directory or ZIP file.

    Returns (records, findings): FileRecords sorted by path and Findings
    sorted by (path, rule_id, message) with duplicates removed.
    Raises ScanInputError if the input cannot be scanned at all.
    """
    state = _State(limits or Limits())
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise ScanInputError(f"cannot access input: {_why(exc)}") from None
    if stat.S_ISLNK(st.st_mode):
        raise ScanInputError("input path is a symbolic link; refusing to follow it")
    if stat.S_ISDIR(st.st_mode):
        _scan_directory(state, path, st)
    elif stat.S_ISREG(st.st_mode):
        _scan_zip(state, path, st)
    else:
        raise ScanInputError("input must be a directory or a ZIP file")
    records = sorted(state.records, key=lambda r: (r.path, r.sha256 or "", r.size))
    findings = sorted(set(state.findings), key=lambda f: (f.path, f.rule_id, f.message))
    return records, findings


# --------------------------------------------------------------------------
# Directory input
# --------------------------------------------------------------------------

def _same_file(a, b):
    return (
        a.st_dev == b.st_dev
        and a.st_ino == b.st_ino
        and a.st_size == b.st_size
        and a.st_mtime_ns == b.st_mtime_ns
        and stat.S_IFMT(a.st_mode) == stat.S_IFMT(b.st_mode)
    )


def _kind(mode):
    for test, label in (
        (stat.S_ISSOCK, "socket"), (stat.S_ISFIFO, "FIFO"),
        (stat.S_ISBLK, "block device"), (stat.S_ISCHR, "character device"),
    ):
        if test(mode):
            return label
    return f"mode {stat.S_IFMT(mode):#o}"


def _symlink_escapes(root_real, link_dir_real, target):
    base = "/" if os.path.isabs(target) else link_dir_real
    resolved = os.path.normpath(os.path.join(base, target))
    return os.path.commonpath([root_real, resolved]) != root_real


def _open_input(path, initial, flags):
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_BINARY | flags)
    except OSError as exc:
        raise ScanInputError(f"cannot open input: {_why(exc)}") from None
    st = os.fstat(fd)
    if (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode)) != (initial.st_dev, initial.st_ino, stat.S_IFMT(initial.st_mode)):
        os.close(fd)
        raise ScanInputError("input was replaced while opening it")
    return fd


def _scan_directory(state, root, initial):
    fd = _open_input(root, initial, _O_DIRECTORY)
    try:
        root_real = os.path.realpath(root)
        _walk(state, fd, "", root_real, root_real, 0)
    finally:
        os.close(fd)


def _walk(state, dir_fd, rel_dir, real_dir, root_real, depth):
    if depth > MAX_DEPTH:
        state.add("RF114", safe_path(rel_dir)[0], f"nesting deeper than {MAX_DEPTH} levels; not descended")
        return
    try:
        with os.scandir(dir_fd) as it:
            entries = sorted(it, key=lambda e: os.fsencode(e.name))
    except OSError as exc:
        state.add("RF112", safe_path(rel_dir)[0] or ".", f"cannot list directory: {_why(exc)}")
        return
    for entry in entries:
        raw_rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError as exc:
            state.add("RF112", safe_path(raw_rel)[0], f"cannot stat: {_why(exc)}")
            continue
        mode = st.st_mode
        rel = state.note_path(raw_rel, is_dir=stat.S_ISDIR(mode))
        if stat.S_ISLNK(mode):
            state.add("RF101", rel, "symbolic link, not followed")
            try:
                target = os.readlink(entry.name, dir_fd=dir_fd)
            except OSError:
                continue
            if _symlink_escapes(root_real, real_dir, target):
                state.add("RF103", rel, "link target is outside the input")
        elif stat.S_ISDIR(mode):
            _descend(state, dir_fd, entry.name, raw_rel, rel, st, real_dir, root_real, depth)
        elif stat.S_ISREG(mode):
            _scan_file(state, dir_fd, entry.name, rel, st)
        else:
            state.add("RF102", rel, f"special file type ({_kind(mode)}) is not allowed")


def _descend(state, dir_fd, name, raw_rel, rel, st, real_dir, root_real, depth):
    try:
        sub_fd = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            state.add("RF109", rel, "directory was replaced while scanning")
        else:
            state.add("RF112", rel, f"cannot open directory: {_why(exc)}")
        return
    try:
        sub_st = os.fstat(sub_fd)
        if (sub_st.st_dev, sub_st.st_ino) != (st.st_dev, st.st_ino):
            state.add("RF109", rel, "directory was replaced while scanning")
            return
        _walk(state, sub_fd, raw_rel, os.path.join(real_dir, name), root_real, depth + 1)
    finally:
        os.close(sub_fd)


def _scan_file(state, dir_fd, name, rel, st):
    try:
        fd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_BINARY, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            state.add("RF109", rel, "file was replaced by a symlink while scanning")
        else:
            state.add("RF112", rel, f"cannot open file: {_why(exc)}")
        return
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not _same_file(st, before):
            state.add("RF109", rel, "file was replaced while scanning")
            return
        if before.st_nlink > 1:
            state.add("RF115", rel, f"file has {before.st_nlink} hard links and may alias content outside the release")
        try:
            sha, count = state.stream(rel, lambda n: os.read(fd, n), before.st_size, stop_beyond_declared=True)
        except OSError as exc:
            state.add("RF112", rel, f"read failed: {_why(exc)}")
            state.record(rel, before.st_size, None)
            return
        after = os.fstat(fd)
        changed = not _same_file(before, after) or after.st_ctime_ns != before.st_ctime_ns
        if changed or count > before.st_size or (sha is not None and count != before.st_size):
            state.add("RF109", rel,
                      f"file changed while being read (stat size {before.st_size}, streamed {count} bytes)")
            sha = None
        state.record(rel, before.st_size, sha)
    finally:
        os.close(fd)


# --------------------------------------------------------------------------
# ZIP input
# --------------------------------------------------------------------------

_DRIVE = re.compile(r"^[A-Za-z]:")


def _normalize_member(name):
    """Return (normalized POSIX path, problem rule IDs) for a member name."""
    problems = []
    if name.startswith(("/", "\\")) or _DRIVE.match(name):
        problems.append("RF104")
    parts = re.split(r"[/\\]", name)
    if ".." in parts:
        problems.append("RF105")
    clean = [p for p in parts if p not in ("", ".")]
    if clean and _DRIVE.match(clean[0]):
        clean[0] = clean[0][2:]
        if not clean[0]:
            del clean[0]
    return "/".join(clean), problems


def _scan_zip(state, archive, initial):
    fd = _open_input(archive, initial, 0)
    if _O_NONBLOCK:
        os.set_blocking(fd, True)
    with os.fdopen(fd, "rb") as fh:
        before = os.fstat(fh.fileno())
        try:
            zf = zipfile.ZipFile(fh)
        except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, EOFError, OSError):
            raise ScanInputError("input file is not a readable ZIP archive") from None
        with zf:
            seen = {}  # normalized path -> "file" or "directory"; one namespace for both
            for info in zf.infolist():
                _scan_member(state, zf, info, seen)
        _check_prefix_conflicts(state, seen)
        after = os.fstat(fh.fileno())
        if not _same_file(before, after) or before.st_ctime_ns != after.st_ctime_ns:
            state.add("RF109", ".", "archive changed while being read")


def _scan_member(state, zf, info, seen):
    raw = info.orig_filename  # zipfile may rewrite .filename; inspect the stored name
    norm, problems = _normalize_member(raw)
    mode = (info.external_attr >> 16) & 0xFFFF if info.create_system == 3 else 0
    ftype = stat.S_IFMT(mode)  # 0 when the creator stored permissions only
    is_dir = ftype == stat.S_IFDIR or (ftype == 0 and raw.endswith(("/", "\\")))
    if not norm:
        # "", ".", "./", "/" and similar name the extraction root itself.
        shown = safe_path(raw)[0] or "."
        state.add("RF116", shown, "member name normalizes to the archive root; it names no file")
        if "RF104" in problems:
            state.add("RF104", shown, "member name has an absolute path; extraction could write outside the target")
        return
    path = state.note_path(norm, is_dir=is_dir)
    if "\\" in raw:
        state.add("RF106", path, "backslash in member name is a separator on Windows but not on POSIX")
    for rule_id in problems:
        label = "an absolute path" if rule_id == "RF104" else "'..' traversal"
        state.add(rule_id, path, f"member name has {label}; extraction could write outside the target")
    kind = "directory" if is_dir else "file"
    if path in seen:
        if seen[path] == kind == "directory":
            state.add("RF107", path, "directory entry appears more than once after normalization")
        elif seen[path] == kind:
            state.add("RF107", path, "member name appears more than once after normalization; extractors disagree on which copy wins")
        else:
            state.add("RF107", path, "path is both a file and a directory after normalization; extractors disagree on which wins")
        if kind == "file":
            seen[path] = kind
    else:
        seen[path] = kind
    if is_dir:
        if info.flag_bits & 0x1:
            state.add("RF108", path, "encrypted directory entry")
        if info.file_size or info.compress_size:
            state.add("RF112", path, "directory entry carries data")
        return
    if ftype == stat.S_IFLNK:
        state.add("RF101", path, "archive member is a symbolic link")
        return
    if ftype not in (0, stat.S_IFREG):
        state.add("RF102", path, f"archive member has a special file type ({_kind(mode)})")
        return
    if info.flag_bits & 0x1:
        state.add("RF108", path, "encrypted member cannot be inspected")
        state.record(path, info.file_size, None)
        return
    try:
        with zf.open(info) as member:
            sha, count = state.stream(path, member.read, info.file_size)
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError, EOFError, ValueError, zlib.error) as exc:
        state.add("RF112", path, f"member cannot be read ({type(exc).__name__})")
        state.record(path, info.file_size, None)
        return
    if sha is not None and count != info.file_size:
        state.add("RF109", path, f"declared size {info.file_size} differs from streamed {count} bytes")
        sha = None
    state.record(path, info.file_size, sha)


def _check_prefix_conflicts(state, seen):
    """A file path that is also an ancestor of another member collides with
    the implicit directory extraction would create (e.g. 'a' and 'a/b')."""
    files = {p for p, kind in seen.items() if kind == "file"}
    reported = set()
    for path in seen:
        parts = path.split("/")
        for i in range(1, len(parts)):
            prefix = "/".join(parts[:i])
            if prefix in files and prefix not in reported:
                reported.add(prefix)
                state.add("RF107", prefix, "file path is also used as a parent directory of another member")


def _why(exc):
    """OS error reason without the file name the exception may carry."""
    return getattr(exc, "strerror", None) or type(exc).__name__
