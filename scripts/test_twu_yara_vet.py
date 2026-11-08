#!/usr/bin/env python3
## ==============================================================================
## UNIT TESTS: YARA RULE VETTING & AOT COMPILATION ENGINE
## ==============================================================================
## Author: Ethan REDACTED <ethan@REDACTED>
## Organization: TWU LLC
## Copyright: (c) 2026 Ethan REDACTED, TWU LLC
## License: MIT License 2026
##
## Educational Purpose:
## This test suite validates the Ahead-of-Time (AOT) static analysis and security
## vetting mechanisms implemented in `twu_yara_vet.py`.
##
## Key Test Areas:
## 1. Static AST Lexing: Verification of comment stripping, import extraction,
##    and rejection of dangerous external modules (e.g. 'cuckoo').
## 2. Structural Scope Enforcement: Validation that 'global' rules and 'include'
##    directives are strictly rejected to maintain hermetic rule evaluation.
## 3. Cryptographic Tamper Detection: Proves that unauthorized mutations to
##    vetted rule files trigger immediate SHA-256 hash mismatch failures.
## 4. Exclusion & Fixture Schema: Asserts that every suppressed false-positive
##    rule documents an explicit human-readable justification.
## 5. Upstream Provenance Tracking: Ensures all vendor feeds document full 40-character
##    commit hashes, upstream URLs, and valid licenses in MANIFEST.json.
## ==============================================================================

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

## Ensure scripts directory is on Python module search path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import twu_yara_vet as v  # noqa: E402


## -----------------------------------------------------------------------------
## TEST SUITE 1: STATIC LEXICAL & AST CONSTRAINT CHECKS
## -----------------------------------------------------------------------------
class Static(unittest.TestCase):
    """Unit tests for in-memory static AST rule inspection."""

    def test_ok(self):
        """Verify that benign rules using approved modules (pe) pass static analysis."""
        ## Rule declaring approved module 'pe' and standard boolean condition
        rule_text = 'import "pe"\nrule A { condition: true }\nprivate rule B { condition: true }'
        names, why = v.static_check(rule_text)
        ## Both public rule A and private rule B should be extracted with zero errors
        self.assertEqual((names, why), (["A", "B"], None))

    def test_disabled_module(self):
        """Verify that rules importing non-allowlisted modules (e.g. cuckoo) are rejected."""
        ## Module 'cuckoo' can trigger dynamic sandbox calls and is disallowed
        rule_text = 'import "cuckoo"\nrule A { condition: true }'
        names, why = v.static_check(rule_text)
        self.assertEqual(names, [])
        self.assertIn("disabled module", why)

    def test_import_in_comment_ignored(self):
        """Verify that imports located inside comments do not trigger false rejections."""
        ## The import 'cuckoo' is commented out with // and must be ignored by regex
        rule_text = '// import "cuckoo"\nrule A { condition: true }'
        names, why = v.static_check(rule_text)
        self.assertEqual(names, ["A"])
        self.assertIsNone(why)

    def test_global_and_include_rejected(self):
        """Verify that global rules and relative include statements are strictly rejected."""
        ## Global rules modify global evaluation state and break isolation
        names_g, why_g = v.static_check("global rule G { condition: true }")
        self.assertIn("global", why_g)

        ## Relative includes introduce path traversal and non-hermetic packaging risks
        names_inc, why_inc = v.static_check('include "x.yar"\nrule A { condition: true }')
        self.assertIn("include", why_inc)


## -----------------------------------------------------------------------------
## TEST SUITE 2: REPOSITORY RULESET INTEGRITY & TAMPER DETECTION
## -----------------------------------------------------------------------------
class Real(unittest.TestCase):
    """Unit tests against actual repository files, manifests, and tamper simulations."""

    def test_repo_rules_verify(self):
        """Verify that all vetted rules committed to the repository match MANIFEST.json."""
        ## In CI / unit tests, verify file presence and SHA-256 digests without requiring yarac
        self.assertEqual(v.verify(compile_index=False), [])

    def test_tamper_detected(self):
        """Simulate malicious file modification and verify immediate SHA-256 detection."""
        with tempfile.TemporaryDirectory() as td:
            ## Copy legitimate vetted rules into temporary directory sandbox
            shutil.copytree(str(v.RULES), td + "/r")
            man = json.loads(Path(td, "r", "MANIFEST.json").read_text())

            ## Tamper with the first rule file by appending arbitrary comment
            target = Path(td, "r", man["files"][0]["path"])
            target.write_text(target.read_text() + "\n// tampered\n")

            ## Verify that verify() flags the sha256 mismatch
            probs = v.verify(Path(td) / "r", compile_index=False)
            self.assertTrue(any("sha256 mismatch" in p for p in probs))

    def test_exclusions_file_lists_reason(self):
        """Verify that every entry in EXCLUSIONS.json includes an explicit justification."""
        ex = json.loads((v.RULES / "EXCLUSIONS.json").read_text())
        for e in ex["excluded"]:
            ## Every suppressed rule must document the rule identifier and rationale
            self.assertTrue(e.get("rule"), "Rule identifier missing in EXCLUSIONS.json")
            self.assertTrue(e.get("why"), "Exclusion reason missing for rule: %s" % e.get("rule"))

    def test_licenses_recorded(self):
        """Verify that MANIFEST.json tracks complete cryptographic and legal provenance."""
        man = json.loads((v.RULES / "MANIFEST.json").read_text())
        ## Verify all sources contain valid upstream license, full commit hash, and HTTPS URL
        for s in man["sources"]:
            self.assertTrue(s["license"])
            self.assertEqual(len(s["commit"]), 40, "Commit hash must be full 40-character SHA-1")
            self.assertTrue(s["url"].startswith("https://github.com/"))
        ## Verify all files contain valid 64-character hexadecimal SHA-256 digests
        self.assertTrue(all(len(f["sha256"]) == 64 for f in man["files"]))


if __name__ == "__main__":
    unittest.main()
