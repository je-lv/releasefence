"""CLI and archive checks for publication mistakes and hostile inputs.

Secret shapes are concatenated in this module so the test source does not
itself contain a full token. Sample trees under fixtures/ hold the synthetic
values a human scan is expected to flag.
"""

import contextlib
import hashlib
import io
import json
import os
import stat
import socket
import sys
import tempfile
import time
import unittest
import warnings
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from releasefence.cli import main
from releasefence.inventory import CHUNK_SIZE

from helpers import bind_unix_socket

PEM = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
PUBLIC = "-----BEGIN " + "PUBLIC KEY-----"
GITHUB = "ghp_" + ("A" * 36)
OPENAI = "sk-proj-" + ("q" * 20)
GLASS = "gb_" + ("c" * 24)
SHORT_GITHUB = "ghp_" + "short"


def _invoke(*args):
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
    return code, out.getvalue(), err.getvalue()


def _rules(report, path=None):
    return sorted(f["rule_id"] for f in report["findings"] if path is None or f["path"] == path)


class CliCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.root = self.tmp / "release"
        self.root.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def put(self, rel, data=b"x"):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = data if isinstance(data, bytes) else data.encode()
        path.write_bytes(payload)
        return path

    def scan(self, path=None, policy=None):
        args = ["scan", str(path or self.root), "--format", "json"]
        if policy is not None:
            policy_path = self.tmp / "policy.json"
            policy_path.write_text(json.dumps(policy))
            args.extend(["--policy", str(policy_path)])
        code, out, err = _invoke(*args)
        self.assertEqual(err, "", err)
        report = json.loads(out) if out else {}
        return code, report, out

    def zip(self, members):
        archive = self.tmp / "in.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(archive, "w") as zf:
                for name, data in members:
                    zf.writestr(name, data)
        return archive


class FixtureTests(unittest.TestCase):
    def test_safe_fixture_is_clean_and_repeatable(self):
        code, out, err = _invoke("scan", str(ROOT / "fixtures" / "safe"), "--format", "json")
        self.assertEqual(err, "")
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertEqual(report["findings"], [])
        self.assertFalse(report["blocking"])
        self.assertEqual(
            [row["path"] for row in report["files"]],
            [".env.example", "LICENSE", "README.md", "certs/public.crt", "src/app.py"],
        )
        app = next(row for row in report["files"] if row["path"] == "src/app.py")
        body = (ROOT / "fixtures" / "safe" / "src" / "app.py").read_bytes()
        self.assertEqual(app["size"], len(body))
        self.assertEqual(app["sha256"], hashlib.sha256(body).hexdigest())
        _, again, _ = _invoke("scan", str(ROOT / "fixtures" / "safe"), "--format", "json")
        self.assertEqual(out, again)

    def test_unsafe_fixture_blocks_without_echoing_secrets(self):
        secrets = (ROOT / "fixtures" / "unsafe" / ".env").read_text().splitlines()
        pem = (ROOT / "fixtures" / "unsafe" / "id_rsa").read_text()
        code, out, err = _invoke("scan", str(ROOT / "fixtures" / "unsafe"), "--format", "json")
        self.assertEqual(code, 1, err)
        report = json.loads(out)
        text_code, text, text_err = _invoke("scan", str(ROOT / "fixtures" / "unsafe"))
        self.assertEqual(text_code, 1)
        blob = out + err + text + text_err
        for line in secrets:
            value = line.split("=", 1)[1]
            self.assertNotIn(value, blob)
            self.assertNotIn(value[-8:], blob)
        self.assertNotIn(pem, blob)
        self.assertNotIn("PRIVATE KEY", blob)
        got = {(f["path"], f["rule_id"]) for f in report["findings"]}
        self.assertIn((".env", "RF301"), got)
        self.assertIn((".env", "RF202"), got)
        self.assertIn((".env", "RF203"), got)
        self.assertIn((".env", "RF204"), got)
        self.assertIn(("id_rsa", "RF201"), got)
        self.assertIn(("id_rsa", "RF302"), got)
        self.assertIn(("certs/server.pem", "RF307"), got)
        self.assertIn((".DS_Store", "RF304"), got)
        self.assertIn(("notes.txt~", "RF304"), got)
        # Source distributions replace symbolic links with copies, so the link
        # sample is only checked where it is still a link (a Git checkout).
        if (ROOT / "fixtures" / "unsafe" / "outside-link").is_symlink():
            self.assertIn(("outside-link", "RF101"), got)
            self.assertIn(("outside-link", "RF103"), got)
            self.assertNotIn("outside-link", [row["path"] for row in report["files"]])

    def test_bad_archive_fixture_is_blocking_and_not_extracted(self):
        archive = ROOT / "fixtures" / "bad-archive.zip"
        parent = archive.parent
        before = sorted(p.name for p in parent.iterdir())
        code, out, err = _invoke("scan", str(archive), "--format", "json")
        self.assertEqual(sorted(p.name for p in parent.iterdir()), before)
        self.assertEqual(code, 1, err)
        report = json.loads(out)
        got = {(f["path"], f["rule_id"]) for f in report["findings"]}
        self.assertIn(("dup.txt", "RF107"), got)
        self.assertIn(("tmp/abs.txt", "RF104"), got)
        self.assertIn(("../outside.txt", "RF105"), got)
        self.assertIn(("a/b.txt", "RF106"), got)
        self.assertIn("ok.txt", [row["path"] for row in report["files"]])

    def test_safe_manifest_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "safe.json"
            code, _, err = _invoke("manifest", str(ROOT / "fixtures" / "safe"), "--out", str(manifest))
            self.assertEqual((code, err), (0, ""))
            code, out, err = _invoke(
                "verify", str(ROOT / "fixtures" / "safe"), "--manifest", str(manifest), "--format", "json"
            )
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out)["changes"], [])
            stored = json.loads(manifest.read_text())
            self.assertEqual(set(stored), {"schema_version", "files"})


class PublicationTests(CliCase):
    def test_warning_only_allows_manifest_and_errors_do_not(self):
        self.put(".DS_Store", b"DS")
        code, report, _ = self.scan()
        self.assertEqual(code, 0)
        self.assertEqual(_rules(report), ["RF304"])
        self.assertFalse(report["blocking"])
        manifest = self.tmp / "m.json"
        self.assertEqual(_invoke("manifest", str(self.root), "--out", str(manifest))[0], 0)
        self.assertTrue(manifest.exists())

        self.put(".env", "TOKEN=1\n")
        code, _, _ = self.scan()
        self.assertEqual(code, 1)
        blocked = self.tmp / "blocked.json"
        self.assertEqual(_invoke("manifest", str(self.root), "--out", str(blocked))[0], 1)
        self.assertFalse(blocked.exists())

    def test_suppression_is_audited_and_does_not_hide_other_rules(self):
        self.put(".env", f"TOKEN={OPENAI}\n")
        code, report, raw = self.scan(policy={"ignore": [{"rule_id": "RF301", "path_glob": ".env"}]})
        self.assertEqual(code, 1)
        self.assertEqual(_rules(report, ".env"), ["RF204"])
        suppressed = [item for item in report["suppressions"] if item["rule_id"] == "RF301"]
        self.assertEqual(len(suppressed), 1)
        self.assertTrue(suppressed[0]["blocking"])
        self.assertEqual(suppressed[0]["suppression"], [{"rule_id": "RF301", "path_glob": ".env"}])
        self.assertNotIn(OPENAI, raw)

        (self.root / ".env").unlink()
        self.put("dir/notes.txt~", b"x")
        code, report, _ = self.scan(policy={"ignore": [{"rule_id": "RF304", "path_glob": "dir/*"}]})
        self.assertEqual(code, 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["suppressions"][0]["path"], "dir/notes.txt~")

    def test_forbidden_glob_and_negative_secret_shapes(self):
        self.put("readme.txt", "sk-learn\n" + SHORT_GITHUB + "\n" + PUBLIC + "\n-----END PUBLIC KEY-----\n")
        self.put("id_rsa.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake\n")
        self.put(".env.example", "TOKEN=replace-me\n")
        code, report, raw = self.scan(policy={"forbidden_globs": ["readme.txt"]})
        self.assertEqual(code, 1)
        self.assertEqual(_rules(report), ["RF400"])
        self.assertNotIn(SHORT_GITHUB, raw)
        self.assertNotIn("PRIVATE KEY", raw)

    def test_names_and_tokens_across_a_chunk_boundary(self):
        prefix = b"a" * (CHUNK_SIZE - 8) + b"\n\n"
        self.put("split.bin", prefix + PEM.encode() + b"\n")
        self.put(".ENV", "x=1\n")
        code, report, raw = self.scan()
        self.assertEqual(code, 1)
        self.assertEqual(_rules(report, "split.bin"), ["RF201"])
        split = next(finding for finding in report["findings"] if finding["path"] == "split.bin")
        self.assertIn("line ", split["message"])
        self.assertEqual(_rules(report, ".ENV"), ["RF301"])
        self.assertNotIn(PEM, raw)

    def test_control_character_name_stays_on_one_report_line(self):
        self.put("evil\nname.txt", b"ok")
        code, out, err = _invoke("scan", str(self.root))
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        self.assertIn("RF113", out)
        self.assertNotIn("evil\nname", out)
        for line in out.splitlines():
            self.assertNotIn("\n", line)

    def test_symlink_directory_is_not_walked(self):
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / ".env").write_text(f"TOKEN={OPENAI}\n")
        os.symlink(outside, self.root / "linked")
        code, report, raw = self.scan()
        self.assertEqual(code, 1)
        self.assertEqual(_rules(report, "linked"), ["RF101", "RF103"])
        self.assertNotIn("RF301", _rules(report))
        self.assertNotIn("RF204", _rules(report))
        self.assertNotIn(OPENAI, raw)

    def test_special_files_and_hard_link_warning(self):
        os.mkfifo(self.root / "pipe")
        code, report, _ = self.scan()
        self.assertEqual(code, 1)
        self.assertEqual(_rules(report, "pipe"), ["RF102"])
        self.assertNotIn("pipe", [row["path"] for row in report["files"]])

        os.remove(self.root / "pipe")
        self.put("a.txt", b"same")
        os.link(self.root / "a.txt", self.root / "b.txt")
        code, report, _ = self.scan()
        self.assertEqual(code, 0)
        self.assertEqual(set(_rules(report)), {"RF115"})
        self.assertEqual([f["path"] for f in report["findings"]], ["a.txt", "b.txt"])

    def test_socket_is_special(self):
        with socket.socket(socket.AF_UNIX) as sock:
            bind_unix_socket(sock, self.root, "sock", self)
            code, report, _ = self.scan()
        self.assertEqual(code, 1)
        self.assertEqual(_rules(report, "sock"), ["RF102"])

    def test_root_symlink_missing_path_and_plain_file_fail_closed(self):
        os.symlink(self.root, self.tmp / "alias")
        token_name = self.tmp / ("missing-" + GITHUB)
        code, out, err = _invoke("scan", str(self.tmp / "alias"))
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("symbolic link", err)
        code, out, err = _invoke("scan", str(token_name))
        self.assertEqual(code, 2)
        self.assertNotIn(GITHUB, err)
        self.assertNotIn(GITHUB, out)
        plain = self.tmp / "plain.txt"
        plain.write_text("not a zip")
        self.assertEqual(_invoke("scan", str(plain))[0], 2)
        self.assertEqual(_invoke()[0], 2)

    def test_total_budget_counts_bytes_actually_read(self):
        for name in "abcde":
            self.put(f"{name}.bin", b"Z" * 100)
        limits = {"max_file_bytes": 1000, "max_total_bytes": 150, "large_file_bytes": 100000}
        counted = []
        real_read = os.read

        def counting(fd, size):
            data = real_read(fd, size)
            counted.append(len(data))
            return data

        policy = self.tmp / "policy.json"
        policy.write_text(json.dumps(limits))
        import releasefence.inventory as inventory
        from unittest import mock
        with mock.patch.object(inventory.os, "read", counting):
            code, out, err = _invoke("scan", str(self.root), "--policy", str(policy), "--format", "json")
        self.assertEqual(code, 1, err)
        report = json.loads(out)
        total = sum(counted)
        self.assertGreater(total, 100)
        self.assertLess(total, 300)
        self.assertLessEqual(total, limits["max_total_bytes"] + 1)
        self.assertIn("RF111", _rules(report, "b.bin"))
        by_path = {row["path"]: row for row in report["files"]}
        self.assertIsNotNone(by_path["a.bin"]["sha256"])
        self.assertIsNone(by_path["c.bin"]["sha256"])

    def test_verify_reports_added_and_removed_files(self):
        self.put("a.txt", b"one")
        manifest = self.tmp / "m.json"
        self.assertEqual(_invoke("manifest", str(self.root), "--out", str(manifest))[0], 0)
        self.put("b.txt", b"new")
        (self.root / "a.txt").unlink()
        code, out, _ = _invoke("verify", str(self.root), "--manifest", str(manifest), "--format", "json")
        self.assertEqual(code, 1)
        changes = {item["path"]: item["change"] for item in json.loads(out)["changes"]}
        self.assertEqual(changes, {"a.txt": "removed", "b.txt": "added"})


class ZipTests(CliCase):
    def test_hostile_members_types_and_no_extraction(self):
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        fifo = zipfile.ZipInfo("fifo")
        fifo.create_system = 3
        fifo.external_attr = (stat.S_IFIFO | 0o644) << 16
        slash_link = zipfile.ZipInfo("hidden/")
        slash_link.create_system = 3
        slash_link.external_attr = (stat.S_IFLNK | 0o777) << 16
        before = set(os.listdir(self.tmp))
        archive = self.zip([
            ("ok.txt", b"ok"),
            ("dup.txt", b"1"),
            ("dup.txt", b"2"),
            ("/tmp/abs.txt", b"x"),
            ("C:/win/abs.txt", b"x"),
            ("../../up.txt", b"x"),
            ("a\\b.txt", b"x"),
            (link, b"../outside"),
            (fifo, b""),
            (slash_link, b"/tmp"),
        ])
        code, out, err = _invoke("scan", str(archive), "--format", "json")
        self.assertEqual(set(os.listdir(self.tmp)), before | {"in.zip"})
        self.assertEqual(code, 1, err)
        report = json.loads(out)
        got = {(f["path"], f["rule_id"]) for f in report["findings"]}
        for item in (
            ("dup.txt", "RF107"),
            ("tmp/abs.txt", "RF104"),
            ("win/abs.txt", "RF104"),
            ("../../up.txt", "RF105"),
            ("a/b.txt", "RF106"),
            ("link", "RF101"),
            ("fifo", "RF102"),
            ("hidden", "RF101"),
        ):
            self.assertIn(item, got)
        paths = [row["path"] for row in report["files"]]
        self.assertNotIn("link", paths)
        self.assertNotIn("fifo", paths)
        self.assertNotIn("hidden", paths)

    def test_encrypted_member_is_not_decrypted_or_echoed(self):
        archive = self.zip([("secret.txt", PEM.encode() + b"\n" + OPENAI.encode())])
        data = bytearray(archive.read_bytes())
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            index = data.find(signature)
            data[index + offset] |= 0x01
        archive.write_bytes(bytes(data))
        code, out, err = _invoke("scan", str(archive), "--format", "json")
        self.assertEqual(code, 1, err)
        report = json.loads(out)
        self.assertEqual(_rules(report), ["RF108"])
        self.assertIsNone(report["files"][0]["sha256"])
        self.assertNotIn(OPENAI, out)
        self.assertNotIn("PRIVATE KEY", out)

    def test_nested_zip_is_not_opened_and_deflate_stays_bounded(self):
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w") as inner:
            inner.writestr("nested-secret.txt", OPENAI)
        self_archive = self.tmp / "outer.zip"
        info = zipfile.ZipInfo("bomb.bin")
        info.compress_type = zipfile.ZIP_DEFLATED
        started = time.monotonic()
        with zipfile.ZipFile(self_archive, "w") as outer:
            outer.writestr("inner.zip", inner_buf.getvalue())
            outer.writestr(info, b"\0" * 200000)
        policy = self.tmp / "policy.json"
        policy.write_text(json.dumps({
            "max_file_bytes": 2000,
            "max_total_bytes": 3000,
            "large_file_bytes": 1000000,
        }))
        before = set(os.listdir(self.tmp))
        code, out, err = _invoke("scan", str(self_archive), "--policy", str(policy), "--format", "json")
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(set(os.listdir(self.tmp)), before)
        self.assertEqual(code, 1, err)
        report = json.loads(out)
        self.assertNotIn("nested-secret.txt", [row["path"] for row in report["files"]])
        self.assertTrue({"RF110", "RF111"} & set(_rules(report)))
        self.assertNotIn(OPENAI, out)

    def test_zip_verify_sees_content_change(self):
        archive = self.zip([("a.txt", b"one"), ("b.txt", b"two")])
        manifest = self.tmp / "m.json"
        self.assertEqual(_invoke("manifest", str(archive), "--out", str(manifest))[0], 0)
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("a.txt", b"one")
            zf.writestr("b.txt", b"changed")
        code, out, err = _invoke("verify", str(archive), "--manifest", str(manifest), "--format", "json")
        self.assertEqual(code, 1, err)
        self.assertEqual(json.loads(out)["changes"], [{"change": "changed", "path": "b.txt"}])


if __name__ == "__main__":
    unittest.main()
