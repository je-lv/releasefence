import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from releasefence.cli import main
from releasefence.policy import load_policy

class CliPolicyTests(unittest.TestCase):
    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_manifest_lifecycle_and_no_clobber(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'input'; root.mkdir()
            (root/'a.txt').write_text('hello')
            manifest = Path(tmp)/'manifest.json'
            self.assertEqual(self.invoke('manifest', str(root), '--out', str(manifest))[0], 0)
            original = manifest.read_bytes()
            self.assertEqual(self.invoke('manifest', str(root), '--out', str(manifest))[0], 2)
            self.assertEqual(manifest.read_bytes(), original)
            self.assertEqual(self.invoke('verify', str(root), '--manifest', str(manifest))[0], 0)
            (root/'a.txt').write_text('changed')
            (root/'b.txt').write_text('added')
            code, text, _ = self.invoke('verify', str(root), '--manifest', str(manifest), '--format', 'json')
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(text)['changes'], [{'change':'changed','path':'a.txt'}, {'change':'added','path':'b.txt'}])
            (root/'a.txt').unlink()
            self.assertIn('removed', self.invoke('verify', str(root), '--manifest', str(manifest))[1])

    def test_strict_policy_and_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'input'; root.mkdir(); (root/'a.txt').write_text('safe')
            policy = Path(tmp)/'policy.json'
            for content in ['{"max_file_bytes": true}', '{"other":1}', '{"ignore":[{}]}', '{"ignore":[{"rule_id":"typo","path_glob":"*"}]}', '{"max_file_bytes":1,"max_file_bytes":2}', '{"max_file_bytes":NaN}']:
                policy.write_text(content)
                with self.assertRaises(ValueError): load_policy(policy)
            policy.write_text(json.dumps({'forbidden_globs':['*.txt'], 'ignore':[{'rule_id':'RF400','path_glob':'a.txt'}]}))
            code, text, _ = self.invoke('scan', str(root), '--policy', str(policy), '--format', 'json')
            self.assertEqual(code, 0)
            report = json.loads(text)
            self.assertEqual(report['suppressions'][0]['rule_id'], 'RF400')
            self.assertFalse(report['findings'])
            self.assertEqual(text, self.invoke('scan', str(root), '--policy', str(policy), '--format', 'json')[1])

    def test_invalid_inputs_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'input'; root.mkdir()
            self.assertEqual(self.invoke('scan', str(root/'missing'))[0], 2)
            self.assertEqual(self.invoke('manifest', str(root), '--out', str(root/'m.json'))[0], 2)
            manifest = Path(tmp)/'m.json'; manifest.write_text('{"schema_version":1,"files":[{"path":"../x","size":0,"sha256":"'+'0'*64+'"}]}')
            self.assertEqual(self.invoke('verify', str(root), '--manifest', str(manifest))[0], 2)

    def test_suppressed_limits_cannot_create_incomplete_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'input'; root.mkdir(); (root/'a.txt').write_text('larger than limit')
            policy = Path(tmp)/'policy.json'
            policy.write_text(json.dumps({'max_file_bytes':1, 'ignore':[{'rule_id':'RF110','path_glob':'*'}]}))
            out = Path(tmp)/'m.json'
            self.assertEqual(self.invoke('manifest', str(root), '--out', str(out), '--policy', str(policy))[0], 2)
            self.assertFalse(out.exists())
