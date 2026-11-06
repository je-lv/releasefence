import hashlib
import json
import os
import socket
import tempfile
import unittest
import zipfile
from dataclasses import asdict
from pathlib import Path
from unittest import mock

from releasefence import inventory
from releasefence.detectors import CONTENT_RULES, ContentScanner, name_findings
from releasefence.inventory import ScanInputError, scan_inventory
from releasefence.model import RULES, Limits

from helpers import bind_unix_socket

# Synthetic secrets assembled at runtime so this file never contains a literal one.
PEM = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
GITHUB = "ghp_" + "A1b2C3d4" * 5
GITHUB_PAT = "github_pat_" + "Z9" * 20
OPENAI = "sk-proj-" + "q" * 40
OPENAI_LEGACY = "sk-" + "a" * 20 + "T3BlbkFJ" + "b" * 20
GLASSBOARD = "gbt_" + "x7" * 16
BEARER = "Authorization: Bearer " + "e" * 32


def rules(findings, path=None):
    return sorted({f.rule_id for f in findings if path is None or f.path == path})


def write_zip(path, members):
    """members: list of (ZipInfo-or-name, bytes)."""
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)


class Tmp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.root = self.tmp / "release"
        self.root.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def put(self, rel, data=b"x"):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
        return p


class DirectoryInventoryTests(Tmp):
    def test_clean_tree_is_sorted_hashed_and_deterministic(self):
        self.put("b.txt", b"bee")
        self.put("a/z.py", b"print(1)\n")
        self.put("a/b.py", b"")
        records, findings = scan_inventory(self.root)
        self.assertEqual(findings, [])
        self.assertEqual([r.path for r in records], ["a/b.py", "a/z.py", "b.txt"])
        self.assertEqual(records[2].size, 3)
        self.assertEqual(records[2].sha256, hashlib.sha256(b"bee").hexdigest())
        self.assertEqual(scan_inventory(self.root), (records, findings))

    def test_symlinks_not_followed_and_escape_reported(self):
        outside = self.tmp / "outside.txt"
        outside.write_text(PEM)
        self.put("in.txt")
        os.symlink(outside, self.root / "abs-link")
        os.symlink("../outside.txt", self.root / "rel-link")
        os.symlink("in.txt", self.root / "inner-link")
        os.symlink(self.tmp, self.root / "dir-link")
        records, findings = scan_inventory(self.root)
        self.assertEqual([r.path for r in records], ["in.txt"])
        self.assertEqual(rules(findings, "abs-link"), ["RF101", "RF103"])
        self.assertEqual(rules(findings, "rel-link"), ["RF101", "RF103"])
        self.assertEqual(rules(findings, "inner-link"), ["RF101"])
        self.assertEqual(rules(findings, "dir-link"), ["RF101", "RF103"])
        self.assertNotIn("RF201", rules(findings))

    def test_fifo_and_socket_are_special(self):
        os.mkfifo(self.root / "pipe")
        with socket.socket(socket.AF_UNIX) as sock:
            bind_unix_socket(sock, self.root, "s", self)
            _, findings = scan_inventory(self.root)
        self.assertEqual(rules(findings, "pipe"), ["RF102"])
        self.assertEqual(rules(findings, "s"), ["RF102"])

    def test_root_symlink_missing_and_non_zip_are_input_errors(self):
        os.symlink(self.root, self.tmp / "alias")
        (self.tmp / "plain.txt").write_text("not a zip")
        for bad in (self.tmp / "alias", self.tmp / "missing", self.tmp / "plain.txt"):
            with self.assertRaises(ScanInputError):
                scan_inventory(bad)

    def test_control_and_undecodable_names_are_escaped(self):
        self.put("evil\nname.txt")
        self.put("rtl\u202etxt.exe")
        bad = os.fsencode(self.root) + b"/bad\xff.txt"
        with open(bad, "wb") as fh:
            fh.write(b"x")
        records, findings = scan_inventory(self.root)
        paths = [r.path for r in records]
        self.assertIn("evil\\u000aname.txt", paths)
        self.assertIn("rtl\\u202etxt.exe", paths)
        self.assertIn("bad\\xff.txt", paths)
        self.assertEqual(sum(f.rule_id == "RF113" for f in findings), 3)
        json.dumps([asdict(r) for r in records], ensure_ascii=False).encode("utf-8")

    def test_change_during_read_is_detected(self):
        target = self.put("grow.txt", b"a" * 100)
        real_read = os.read

        def growing_read(fd, n):
            data = real_read(fd, n)
            if data:
                with open(target, "ab") as fh:
                    fh.write(b"more")
            return data

        with mock.patch.object(inventory.os, "read", growing_read):
            records, findings = scan_inventory(self.root)
        self.assertEqual(rules(findings, "grow.txt"), ["RF109"])
        self.assertIsNone(records[0].sha256)

    def test_size_limits(self):
        self.put("a.bin", b"1" * 50)
        self.put("b.bin", b"2" * 50)
        self.put("c.bin", b"3" * 200)
        limits = Limits(max_file_bytes=100, max_total_bytes=1000, large_file_bytes=40)
        records, findings = scan_inventory(self.root, limits)
        self.assertEqual(rules(findings, "c.bin"), ["RF110", "RF305"])
        self.assertEqual(rules(findings, "a.bin"), ["RF305"])
        self.assertIsNone({r.path: r for r in records}["c.bin"].sha256)

        records, findings = scan_inventory(self.root, Limits(100, 80, 1000))
        self.assertEqual(rules(findings, "b.bin"), ["RF111"])
        by_path = {r.path: r for r in records}
        self.assertIsNotNone(by_path["a.bin"].sha256)
        self.assertIsNone(by_path["b.bin"].sha256)

    def test_hard_link_warning(self):
        self.put("a.txt")
        os.link(self.root / "a.txt", self.root / "b.txt")
        _, findings = scan_inventory(self.root)
        self.assertEqual(rules(findings), ["RF115"])
        self.assertTrue(all(not f.blocking for f in findings))

    def test_publication_mistakes_by_name(self):
        for rel in (".env", "config/prod.env", ".env.example", ".git/config", "sub/.git",
                    ".DS_Store", "notes.txt~", "x.swp", "id_rsa", "id_rsa.pub", "certs/server.pem",
                    "__pycache__/m.cpython-311.pyc", "keys/store.p12"):
            self.put(rel)
        _, findings = scan_inventory(self.root)
        got = {(f.path, f.rule_id) for f in findings}
        expected = {
            (".env", "RF301"), ("config/prod.env", "RF301"), (".git", "RF303"),
            ("sub/.git", "RF303"), (".DS_Store", "RF304"), ("notes.txt~", "RF304"),
            ("x.swp", "RF304"), ("id_rsa", "RF302"), ("certs/server.pem", "RF307"),
            ("__pycache__", "RF304"), ("__pycache__/m.cpython-311.pyc", "RF304"),
            ("keys/store.p12", "RF302"),
        }
        self.assertEqual(got, expected)


class ContentTests(Tmp):
    def test_each_secret_rule_and_value_never_reported(self):
        samples = {
            "pem.txt": ("RF201", PEM), "gh.txt": ("RF203", GITHUB), "pat.txt": ("RF203", GITHUB_PAT),
            "oai.txt": ("RF204", OPENAI), "oai2.txt": ("RF204", OPENAI_LEGACY),
            "gb.txt": ("RF202", GLASSBOARD), "bearer.txt": ("RF202", BEARER),
        }
        for name, (_, secret) in samples.items():
            self.put(name, f"line1\nvalue = {secret}\n")
        self.put("benign.txt", "sk-learn is a package; ghp_short; Bearer token docs; BEGIN PUBLIC KEY")
        _, findings = scan_inventory(self.root)
        for name, (rule_id, secret) in samples.items():
            self.assertEqual(rules(findings, name), [rule_id], name)
            self.assertIn("line 2", [f for f in findings if f.path == name][0].message)
        self.assertEqual(rules(findings, "benign.txt"), [])
        dump = json.dumps([asdict(f) for f in findings])
        for _, secret in samples.values():
            self.assertNotIn(secret, dump)
            self.assertNotIn(secret[-12:], dump)

    def test_match_across_chunk_boundary_and_line_numbers(self):
        prefix = b"a" * (inventory.CHUNK_SIZE - 10) + b"\n" * 3
        self.put("split.bin", prefix + PEM.encode() + b"\n")
        _, findings = scan_inventory(self.root)
        self.assertEqual(rules(findings), ["RF201"])
        self.assertIn("line 4", findings[0].message)

    def test_scanner_line_counting_over_many_chunks(self):
        scanner = ContentScanner()
        for _ in range(5):
            scanner.feed(b"x\n" * 1000)
        scanner.feed(b"token " + GITHUB.encode())
        (finding,) = scanner.findings("p")
        self.assertIn("line 5001", finding.message)

    def test_rule_catalogue_is_consistent(self):
        for rule_id, _, _ in CONTENT_RULES:
            self.assertIn(rule_id, RULES)
        for f in name_findings(".git/x/.env"):
            self.assertIn(f.rule_id, RULES)


class ZipInventoryTests(Tmp):
    def zip(self, members):
        path = self.tmp / "in.zip"
        write_zip(path, members)
        return path

    def test_clean_zip_matches_directory_inventory(self):
        self.put("pkg/a.py", b"A")
        self.put("README", b"R")
        archive = self.zip([("pkg/", b""), ("pkg/a.py", b"A"), ("README", b"R")])
        self.assertEqual(scan_inventory(archive), scan_inventory(self.root))

    def test_structural_member_problems(self):
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        fifo = zipfile.ZipInfo("fifo")
        fifo.create_system = 3
        fifo.external_attr = 0o010644 << 16
        with mock.patch("warnings.warn"):
            archive = self.zip([
                ("dup.txt", b"1"), ("dup.txt", b"2"), ("/etc/abs", b"x"), ("C:/win/abs", b"x"),
                ("../../up", b"x"), ("a\\b.txt", b"x"), (link, b"/etc/passwd"), (fifo, b""),
            ])
        records, findings = scan_inventory(archive)
        got = {(f.path, f.rule_id) for f in findings}
        for item in [("dup.txt", "RF107"), ("etc/abs", "RF104"), ("win/abs", "RF104"),
                     ("../../up", "RF105"), ("a/b.txt", "RF106"), ("link", "RF101"), ("fifo", "RF102")]:
            self.assertIn(item, got)
        self.assertNotIn("link", [r.path for r in records])

    def test_encrypted_member_is_not_read(self):
        archive = self.zip([("secret.txt", PEM.encode())])
        data = bytearray(archive.read_bytes())
        for sig, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = data.find(sig)
            data[i + offset] |= 0x01
        archive.write_bytes(bytes(data))
        records, findings = scan_inventory(archive)
        self.assertEqual(rules(findings), ["RF108"])
        self.assertIsNone(records[0].sha256)

    def test_zip_limits_stream_without_extracting(self):
        archive = self.zip([("big.txt", b"0" * 5000), ("a.txt", b"1" * 60), ("b.txt", b"2" * 60)])
        cwd = sorted(os.listdir(self.tmp))
        _, findings = scan_inventory(archive, Limits(1000, 100, 1000))
        self.assertEqual(rules(findings, "big.txt"), ["RF110", "RF305"])
        self.assertEqual(rules(findings, "b.txt"), ["RF111"])
        self.assertEqual(sorted(os.listdir(self.tmp)), cwd)

    def test_lying_size_header_is_caught_while_streaming(self):
        archive = self.zip([("bomb.txt", b"0" * 100000)])
        data = bytearray(archive.read_bytes())
        for sig, offset in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
            i = data.find(sig)
            data[i + offset:i + offset + 4] = (10).to_bytes(4, "little")
        archive.write_bytes(bytes(data))
        records, findings = scan_inventory(archive, Limits(1000, 10000, 1000))
        self.assertTrue({"RF110", "RF112"} & set(rules(findings)))
        self.assertIsNone(records[0].sha256)

    def test_corrupt_member_is_reported(self):
        archive = self.zip([("a.txt", b"hello world")])
        data = bytearray(archive.read_bytes())
        i = data.find(b"hello world")
        data[i] ^= 0xFF
        archive.write_bytes(bytes(data))
        _, findings = scan_inventory(archive)
        self.assertEqual(rules(findings), ["RF112"])

    def test_secret_and_name_rules_apply_inside_zip(self):
        archive = self.zip([(".env", b"K=" + OPENAI.encode()), ("repo/.git/HEAD", b"ref")])
        _, findings = scan_inventory(archive)
        self.assertEqual({(f.path, f.rule_id) for f in findings},
                         {(".env", "RF204"), (".env", "RF301"), ("repo/.git", "RF303")})


class ReviewRegressionTests(Tmp):
    """Regressions found in early review: trailing slashes, encryption flags and limits."""

    def test_trailing_slash_does_not_hide_symlink_or_encryption(self):
        link = zipfile.ZipInfo("looks-like-dir/")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        path = self.tmp / "in.zip"
        write_zip(path, [(link, b"/etc")])
        _, findings = scan_inventory(path)
        self.assertEqual(rules(findings), ["RF101"])

    def test_bytes_of_rejected_files_count_toward_total(self):
        self.put("a.bin", b"1" * 60)
        self.put("b.bin", b"2" * 60)
        self.put("c.bin", b"3" * 60)
        requested = []
        real_read = os.read

        def spy(fd, n):
            requested.append(n)
            return real_read(fd, n)

        with mock.patch.object(inventory.os, "read", spy):
            _, findings = scan_inventory(self.root, Limits(max_file_bytes=1000, max_total_bytes=100, large_file_bytes=1000))
        self.assertEqual(rules(findings, "b.bin"), ["RF111"])
        self.assertEqual(rules(findings, "c.bin"), [])  # not read at all after the total limit
        self.assertLessEqual(max(requested), 61)  # bounded by declared size + 1

    def test_simultaneous_file_and_total_overflow_latches_total(self):
        # A file at exactly the per-file limit grows during the read, so one
        # chunk overflows both limits; the next file must not hash as empty.
        target = self.put("a.txt", b"a" * 10)
        self.put("b.txt", b"b" * 5)
        real_read = os.read
        grown = []

        def grow_once(fd, n):
            if not grown:
                grown.append(1)
                with open(target, "ab") as fh:
                    fh.write(b"x" * 100)
            return real_read(fd, n)

        with mock.patch.object(inventory.os, "read", grow_once):
            records, findings = scan_inventory(self.root, Limits(10, 10, 1000))
        self.assertIn("RF111", rules(findings, "a.txt"))
        self.assertIsNone({r.path: r for r in records}["b.txt"].sha256)

    def test_growing_file_hitting_total_limit_latches(self):
        target = self.put("a.txt", b"a" * 10)
        self.put("b.txt", b"b" * 5)
        real_read = os.read
        grown = []

        def grow_once(fd, n):
            if not grown:
                grown.append(1)
                with open(target, "ab") as fh:
                    fh.write(b"x" * 100)
            return real_read(fd, n)

        with mock.patch.object(inventory.os, "read", grow_once):
            records, findings = scan_inventory(self.root, Limits(1000, 10, 1000))
        self.assertIn("RF111", rules(findings, "a.txt"))
        self.assertIsNone({r.path: r for r in records}["b.txt"].sha256)

    def test_input_swapped_after_lstat_is_refused(self):
        self.put("a.txt")
        archive = self.tmp / "in.zip"
        write_zip(archive, [("a.txt", b"x")])
        wrong = os.lstat(self.root)
        with mock.patch.object(inventory.os, "lstat", return_value=wrong):
            with self.assertRaises(ScanInputError):
                scan_inventory(archive)

    def test_error_messages_do_not_echo_member_names(self):
        name = "evil\u001b[31m.txt".encode().decode("unicode_escape")
        archive = self.tmp / "in.zip"
        write_zip(archive, [(name, b"hello world")])
        data = bytearray(archive.read_bytes())
        i = data.find(b"hello world")
        data[i] ^= 0xFF
        archive.write_bytes(bytes(data))
        _, findings = scan_inventory(archive)
        for f in findings:
            self.assertNotIn("\x1b", f.message)
            self.assertNotIn("evil", f.message)

class ZipNamespaceTests(Tmp):
    """Normalized ZIP paths are one namespace, and names that normalize to the
    archive root are rejected."""

    def zip(self, members):
        path = self.tmp / "ns.zip"
        with mock.patch("warnings.warn"):
            write_zip(path, members)
        return path

    def cli_json(self, archive):
        import contextlib, io
        from releasefence.cli import main
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main(["scan", str(archive), "--format", "json"])
        return code, json.loads(out.getvalue())

    def test_human_repro_file_and_directory_same_name(self):
        for members in ([("same", b"x"), ("same/", b"")], [("same/", b""), ("same", b"x")]):
            code, report = self.cli_json(self.zip(members))
            self.assertEqual(code, 1)
            self.assertIn(("same", "RF107"), {(f["path"], f["rule_id"]) for f in report["findings"]})

    def test_human_repro_single_dot_member(self):
        code, report = self.cli_json(self.zip([(".", b"x")]))
        self.assertEqual(code, 1)
        self.assertEqual([(f["path"], f["rule_id"]) for f in report["findings"]], [(".", "RF116")])
        self.assertEqual(report["files"], [])

    def test_root_like_names_are_rejected_and_not_inventoried(self):
        for name in (".", "./", "/", "./.", "//", "\\"):
            records, findings = scan_inventory(self.zip([(name, b"x")]))
            self.assertIn("RF116", rules(findings), name)
            self.assertEqual(records, [], name)

    def test_dot_segments_alias_the_same_path(self):
        _, findings = scan_inventory(self.zip([("a/./b", b"1"), ("a/b", b"2")]))
        self.assertIn(("a/b", "RF107"), {(f.path, f.rule_id) for f in findings})

    def test_file_used_as_parent_directory(self):
        for members in ([("a", b"x"), ("a/b", b"y")], [("a/b/c", b"y"), ("a", b"x")]):
            _, findings = scan_inventory(self.zip(members))
            self.assertEqual({(f.path, f.rule_id) for f in findings}, {("a", "RF107")})

    def test_explicit_directories_with_children_stay_clean(self):
        records, findings = scan_inventory(self.zip([("d/", b""), ("d/e/", b""), ("d/e/f", b"x"), ("g", b"y")]))
        self.assertEqual(findings, [])
        self.assertEqual([r.path for r in records], ["d/e/f", "g"])

if __name__ == "__main__":
    unittest.main()
