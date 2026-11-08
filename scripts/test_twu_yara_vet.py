import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import twu_yara_vet as v  # noqa: E402


class Static(unittest.TestCase):
    def test_ok(self):
        names, why = v.static_check('import "pe"\nrule A { condition: true }\nprivate rule B { condition: true }')
        self.assertEqual((names, why), (["A", "B"], None))

    def test_disabled_module(self):
        self.assertIn("disabled module", v.static_check('import "cuckoo"\nrule A { condition: true }')[1])

    def test_import_in_comment_ignored(self):
        self.assertIsNone(v.static_check('// import "cuckoo"\nrule A { condition: true }')[1])

    def test_global_and_include_rejected(self):
        self.assertIn("global", v.static_check("global rule G { condition: true }")[1])
        self.assertIn("include", v.static_check('include "x.yar"\nrule A { condition: true }')[1])


class Real(unittest.TestCase):
    def test_repo_rules_verify(self):
        self.assertEqual(v.verify(compile_index=False), [])

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as td:
            shutil.copytree(str(v.RULES), td + "/r")
            man = json.loads(Path(td, "r", "MANIFEST.json").read_text())
            target = Path(td, "r", man["files"][0]["path"])
            target.write_text(target.read_text() + "\n// tampered\n")
            self.assertTrue(any("sha256 mismatch" in p for p in v.verify(Path(td) / "r", compile_index=False)))

    def test_exclusions_file_lists_reason(self):
        ex = json.loads((v.RULES / "EXCLUSIONS.json").read_text())
        for e in ex["excluded"]:
            self.assertTrue(e["rule"] and e["why"])

    def test_licenses_recorded(self):
        man = json.loads((v.RULES / "MANIFEST.json").read_text())
        for s in man["sources"]:
            self.assertTrue(s["license"] and len(s["commit"]) == 40 and s["url"].startswith("https://github.com/"))
        self.assertTrue(all(len(f["sha256"]) == 64 for f in man["files"]))


if __name__ == "__main__":
    unittest.main()
