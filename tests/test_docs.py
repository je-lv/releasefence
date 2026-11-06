import subprocess
import sys
import unittest
from pathlib import Path

from releasefence.model import RULE_DOCS, RULES

ROOT = Path(__file__).resolve().parent.parent


class DocsTests(unittest.TestCase):
    def test_every_rule_is_documented(self):
        self.assertEqual(set(RULE_DOCS), set(RULES) | {"RF400"})

    def test_rules_doc_is_current(self):
        generated = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen_rules_doc.py")],
                                   capture_output=True, text=True, check=True).stdout
        self.assertEqual(generated, (ROOT / "docs" / "RULES.md").read_text(encoding="utf-8"),
                         "run: python scripts/gen_rules_doc.py > docs/RULES.md")

    def test_readme_links_resolve(self):
        import re
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        for target in re.findall(r"\]\(([^)#]+)\)", text) + re.findall(r'src="([^"]+)"', text):
            if not target.startswith(("http://", "https://")):
                self.assertTrue((ROOT / target).exists(), target)
