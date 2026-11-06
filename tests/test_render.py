import io
import unittest

from releasefence.render import render_text, use_color


def finding(path, rule_id, severity="error", message="m"):
    return dict(path=path, rule_id=rule_id, severity=severity, message=message,
                blocking=severity == "error")


def report(findings=(), files=1, changes=None, suppressions=()):
    r = dict(schema_version=1, files=[{"path": f"f{i}", "size": 0, "sha256": "0" * 64} for i in range(files)],
             findings=list(findings), suppressions=list(suppressions),
             blocking=any(f["blocking"] for f in findings))
    if changes is not None:
        r["changes"] = changes
        r["blocking"] = r["blocking"] or bool(changes)
    return r


class FakeTty(io.StringIO):
    def isatty(self):
        return True


class RenderTests(unittest.TestCase):
    def test_clean_scan(self):
        text = render_text(report(files=5), "scan", "dist")
        self.assertEqual(text, "releasefence  scanned dist  5 files\n\nOK  no findings\n")

    def test_files_with_errors_come_first_and_verdict_is_last(self):
        text = render_text(report([finding("a.txt~", "RF304", "warning"),
                                   finding("z/.env", "RF301"),
                                   finding("z/.env", "RF204", message="OpenAI API key, line 1")]),
                           "scan", "dist")
        lines = text.splitlines()
        self.assertEqual(lines[2], "[x] z/.env   [2 findings]")
        self.assertEqual(lines[3], "      error    RF204  OpenAI API key, line 1")
        self.assertIn("[!] a.txt~   [1 finding]", lines)
        self.assertLess(lines.index("[x] z/.env   [2 findings]"), lines.index("[!] a.txt~   [1 finding]"))
        self.assertEqual(lines[-1], "BLOCKED  2 errors  1 warning")

    def test_finding_counts_line_up(self):
        text = render_text(report([finding(".env", "RF301"), finding("src/config", "RF101"),
                                   finding("x" * 60, "RF304", "warning")]), "scan", "x")
        heads = [l for l in text.splitlines() if l.startswith(("[x]", "[!]"))]
        self.assertEqual(heads[0], "[x] .env         [1 finding]")
        self.assertEqual(heads[1], "[x] src/config   [1 finding]")
        self.assertEqual(heads[2], "[!] " + "x" * 60 + "   [1 finding]")

    def test_verbose_explains_each_rule_instead_of_hints(self):
        r = report([finding(".env", "RF204", message="OpenAI API key, line 1")], files=2)
        r["files"][0]["path"] = ".env"
        text = render_text(r, "scan", "x", verbose=True)
        self.assertIn("                      An OpenAI API key.", text)
        self.assertIn("                      fix: Remove the key and revoke it.", text)
        self.assertNotIn("Secret values are never printed", text)
        self.assertNotIn("`", text)
        self.assertIn("[-] f1", text)
        self.assertIn("sha256 000000000000", text)
        self.assertNotIn("[-] .env", text)

    def test_verbose_lists_suppressed_findings_with_their_policy_entry(self):
        hidden = dict(finding("a.env", "RF301"), blocking=True,
                      suppression=[{"rule_id": "RF301", "path_glob": "*.env"}])
        r = report(suppressions=[hidden])
        self.assertNotIn("[s]", render_text(r, "scan", "x"))
        self.assertIn("(see -v)", render_text(r, "scan", "x"))
        text = render_text(r, "scan", "x", verbose=True)
        self.assertIn("[s] a.env   [1 suppressed]", text)
        self.assertIn("suppressed by policy: RF301 *.env", text)
        self.assertTrue(text.endswith("OK  no findings  1 suppressed by policy\n"))

    def test_verbose_flag_reaches_the_cli(self):
        import contextlib, io, tempfile
        from pathlib import Path
        from releasefence.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".env").write_text("x=1\n")
            for flag in ("-v", "--verbose"):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(main(["scan", tmp, flag]), 1)
                self.assertIn("fix: Publish a template", out.getvalue())

    def test_hints_are_printed_once(self):
        text = render_text(report([finding(".env", "RF203"), finding(".env", "RF204")]), "scan", "x")
        self.assertEqual(text.count("Secret values are never printed"), 1)

    def test_warnings_only_is_ok(self):
        text = render_text(report([finding(".DS_Store", "RF304", "warning")]), "scan", "x")
        self.assertTrue(text.endswith("OK  1 warning\n"))

    def test_verify_lists_changes(self):
        text = render_text(report(changes=[{"path": "a", "change": "added"},
                                           {"path": "b", "change": "removed"}]), "verify", "x")
        self.assertIn("      added    a\n", text)
        self.assertIn("      removed  b\n", text)
        self.assertTrue(text.endswith("BLOCKED  2 changes\n"))
        clean = render_text(report(changes=[]), "verify", "x")
        self.assertTrue(clean.endswith("OK  matches the manifest\n"))

    def test_manifest_outcome_is_stated(self):
        self.assertTrue(render_text(report(files=2), "manifest", "x", manifest_written="m.json")
                        .endswith("wrote m.json  2 files\n"))
        refused = render_text(report([finding("id_rsa", "RF302")]), "manifest", "x", manifest_written=False)
        self.assertTrue(refused.endswith("manifest not written: fix the errors above first\n"))

    def test_suppressions_are_counted(self):
        text = render_text(report(suppressions=[finding("a", "RF304", "warning")]), "scan", "x")
        self.assertIn("1 suppressed by policy (see -v)", text)

    def test_control_characters_never_reach_the_terminal(self):
        evil = "a\x1b[31mb‮.txt"
        text = render_text(report([finding(evil, "RF113", message="x\x07")]), "scan", "t\x1b]0;x\x07")
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertNotIn("‮", text)
        self.assertIn("\\u001b", text)

    def test_color_only_on_request_or_terminal(self):
        plain = io.StringIO()
        self.assertFalse(use_color(plain, {}))
        self.assertTrue(use_color(FakeTty(), {}))
        self.assertFalse(use_color(FakeTty(), {"NO_COLOR": "1"}))
        self.assertFalse(use_color(FakeTty(), {"TERM": "dumb"}))
        self.assertTrue(use_color(plain, {"FORCE_COLOR": "1"}))
        self.assertFalse(use_color(plain, {"FORCE_COLOR": "0"}))
        self.assertFalse(use_color(FakeTty(), {"NO_COLOR": "1", "FORCE_COLOR": "1"}))

    def test_colored_output_has_same_text(self):
        r = report([finding(".env", "RF301"), finding("x~", "RF304", "warning")])
        colored = render_text(r, "scan", "dist", color=True)
        import re
        self.assertEqual(re.sub(r"\x1b\[[0-9;]*m", "", colored).replace(" BLOCKED ", "BLOCKED"),
                         render_text(r, "scan", "dist"))

    def test_output_is_deterministic(self):
        r = report([finding("b", "RF304", "warning"), finding("a", "RF301")])
        self.assertEqual(render_text(r, "scan", "x"), render_text(r, "scan", "x"))


if __name__ == "__main__":
    unittest.main()
