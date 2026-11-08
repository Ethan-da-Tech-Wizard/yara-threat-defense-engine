#!/usr/bin/env python3
## ==============================================================================
## UNIT TESTS: DUAL-ENGINE THREAT DEFENSE SCANNER (YARA + CLAMAV)
## ==============================================================================
## Author: Ethan REDACTED <ethan@REDACTED>
## Organization: TWU LLC
## Copyright: (c) 2026 Ethan REDACTED, TWU LLC
## License: MIT License 2026
##
## Educational Purpose:
## This test suite exhaustively verifies the threat classification logic, fail-closed
## error handling, anonymous symlink staging, and forensic receipts implemented in
## `twu_scan.py`.
##
## Key Test Areas:
## 1. Threat Classification Hierarchy: Proves exact verdict synthesis:
##    - CLEAN (Exit 0): Both engines pass with zero matches.
##    - SUSPICIOUS (Exit 1): YARA heuristic pattern match.
##    - INFECTED (Exit 1): ClamAV confirmed signature match.
##    - COULD-NOT-SCAN (Exit 2): Engine missing, timeout, oversized file, or permission denied.
## 2. Anonymous Symlink Staging: Ensures filenames with shell escapes, spaces, quotes,
##    or newlines are safely processed as anonymous aliases (f0000000, f0000001).
## 3. Defense-in-Depth & Non-Execution: Asserts scanned executable scripts are never
##    invoked or evaluated dynamically.
## 4. Pinned Test Fixtures: Confirms that intentional test fixtures (path + sha256)
##    suppress YARA warnings while never suppressing confirmed ClamAV virus signatures.
## 5. Write-Once Audit Receipts: Verifies that forensic JSON receipts are atomically
##    persisted using hard-link uniqueness (`link()`).
## ==============================================================================

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

## Ensure scripts directory is on Python search path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import twu_scan as ts  # noqa: E402

## Industry-standard EICAR antivirus test string (harmless standard pattern)
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

## Mock executable simulating native ClamAV CLI behavior in hermetic test environments
FAKE_CLAM = """#!%s
import sys
a = sys.argv[1:]
if "--version" in a:
    print("ClamAV 9.9.9/27000/Fri Nov  6 23:24:18 2026"); sys.exit(0)
lst = a[a.index("-f") + 1]
rc = 0
for p in open(lst).read().splitlines():
    try:
        d = open(p, "rb").read()
    except OSError:
        sys.stderr.write("ERROR: cannot open " + p + "\\n"); rc = 2; continue
    if b"EICAR" in d:
        print(p + ": Win.Test.EICAR_HDB-1 FOUND"); rc = 1 if rc == 0 else rc
sys.exit(rc)
""" % sys.executable

## Mock executable simulating native YARA CLI behavior in hermetic test environments
FAKE_YARA = """#!%s
import os, sys
a = sys.argv[1:]
if "--version" in a:
    print("4.5.9"); sys.exit(0)
t = a[-1]
for r, _, fs in os.walk(t):
    for f in fs:
        p = os.path.join(r, f)
        d = open(p, "rb").read()
        if b"EICAR" in d: print("TWU_EICAR_Test_String " + p)
        if b"MARKER_EXCLUDED" in d: print("Excluded_Rule " + p)
        if b"MARKER_SLEEP" in d:
            import time; time.sleep(30)
""" % sys.executable


def mk_tool(d, name, body):
    """Helper to provision a mock executable binary in a temporary bin directory.

    Parameters:
        d (Path | str): Temporary bin directory.
        name (str): Tool binary name (e.g. 'yara', 'clamscan').
        body (str): Python script content to write and chmod +x.

    Returns:
        str: Absolute path to the created executable.
    """
    p = Path(d) / name
    p.write_text(body)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return str(p)


## -----------------------------------------------------------------------------
## TEST FIXTURE BASE CLASS
## -----------------------------------------------------------------------------
class Base(unittest.TestCase):
    """Isolated test harness providing clean temporary directories and mock tools."""

    def setUp(self):
        """Provision isolated temporary workspace with mock rules and tools."""
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, True)
        self.root = Path(self.td) / "root"
        (self.root / "data" / "yara_rules").mkdir(parents=True)
        (self.root / "data" / "yara_rules" / "index.yar").write_text("// empty\n")
        (self.root / "data" / "yara_rules" / "EXCLUSIONS.json").write_text(
            json.dumps({"excluded": [{"rule": "Excluded_Rule"}]})
        )
        (self.root / "data" / "yara_rules" / "MANIFEST.json").write_text(
            json.dumps({"files": [], "rule_count": 5, "built_epoch": int(time.time())})
        )
        self.bin = Path(self.td) / "bin"
        self.bin.mkdir()
        self.tools = {
            "yara": mk_tool(self.bin, "yara", FAKE_YARA),
            "clamscan": mk_tool(self.bin, "clamscan", FAKE_CLAM),
        }
        self.data = Path(self.td) / "data"
        self.data.mkdir()

    def f(self, name, text):
        """Create sample test file in temporary data directory."""
        p = self.data / name
        p.write_text(text)
        return str(p)

    def scan(self, *paths, **kw):
        """Invoke scanner with default mock tools and repository root."""
        kw.setdefault("tools", self.tools)
        kw.setdefault("root", self.root)
        return ts.scan(list(paths), **kw)


## -----------------------------------------------------------------------------
## TEST SUITE 1: THREAT VERDICTS & DECISION HIERARCHY
## -----------------------------------------------------------------------------
class Verdicts(Base):
    """Unit tests verifying fail-closed verdict synthesis and classification rank."""

    def test_clean(self):
        """Verify that benign files yield CLEAN verdict and exit code 0."""
        r = self.scan(self.f("a.txt", "hello"))
        self.assertEqual(r["verdict"], "CLEAN")
        self.assertEqual(ts.exit_code(r["verdict"]), 0)

    def test_eicar_both_engines_infected(self):
        """Verify that files matching both engines yield INFECTED (highest rank)."""
        r = self.scan(self.f("e.com", EICAR))
        self.assertEqual(r["verdict"], "INFECTED")
        self.assertNotEqual(ts.exit_code(r["verdict"]), 0)
        engines = {x["engine"] for x in r["files"][0]["findings"]}
        self.assertEqual(engines, {"clamav", "yara"})

    def test_yara_only_is_suspicious(self):
        """Verify that heuristic matches without virus signatures yield SUSPICIOUS."""
        ## Configure mock ClamAV to report clean
        self.tools["clamscan"] = mk_tool(self.bin, "clam2", FAKE_CLAM.replace('b"EICAR" in d', 'False'))
        r = self.scan(self.f("e.com", EICAR))
        self.assertEqual(r["verdict"], "SUSPICIOUS")
        self.assertEqual(ts.exit_code("SUSPICIOUS"), 1)

    def test_excluded_rule_ignored(self):
        """Verify that rules listed in EXCLUSIONS.json are suppressed during synthesis."""
        r = self.scan(self.f("x.txt", "MARKER_EXCLUDED"))
        self.assertEqual(r["verdict"], "CLEAN")

    def test_missing_engine_is_could_not_scan_not_clean(self):
        """Verify fail-closed principle: missing engine NEVER yields CLEAN."""
        self.tools["clamscan"] = None
        r = self.scan(self.f("a.txt", "hello"))
        self.assertEqual(r["verdict"], "COULD-NOT-SCAN")
        self.assertTrue(any("clamscan" in x for x in r["reasons"]))

    def test_missing_engine_still_reports_detection(self):
        """Verify that if one engine is missing, detections from the other are still reported."""
        self.tools["clamscan"] = None
        r = self.scan(self.f("e.com", EICAR))
        self.assertEqual(r["verdict"], "SUSPICIOUS")

    def test_oversize_could_not_scan(self):
        """Verify that files exceeding the byte cap yield COULD-NOT-SCAN."""
        r = self.scan(self.f("big.bin", "x" * 100), max_bytes=10)
        self.assertEqual(r["verdict"], "COULD-NOT-SCAN")
        self.assertTrue(any("larger than" in x for x in r["reasons"]))

    def test_missing_path(self):
        """Verify that scanning a nonexistent path yields COULD-NOT-SCAN."""
        r = self.scan(str(self.data / "nope"))
        self.assertEqual(r["verdict"], "COULD-NOT-SCAN")

    def test_timeout(self):
        """Verify that engine timeout yields COULD-NOT-SCAN rather than hanging."""
        r = self.scan(self.f("s.txt", "MARKER_SLEEP"), timeout=1)
        self.assertEqual(r["verdict"], "COULD-NOT-SCAN")
        self.assertTrue(any("time" in x for x in r["reasons"]))

    def test_directory_recursed_worst_wins(self):
        """Verify that scanning a folder evaluates all files and reports the worst verdict."""
        sub = self.data / "d" / "e"
        sub.mkdir(parents=True)
        (sub / "bad").write_text(EICAR)
        (self.data / "d" / "ok").write_text("fine")
        r = self.scan(str(self.data / "d"))
        self.assertEqual(r["verdict"], "INFECTED")
        self.assertEqual(len(r["files"]), 2)

    def test_symlink_not_followed(self):
        """Verify that symlinks are not followed to prevent TOCTOU and traversal attacks."""
        real = self.f("real.txt", EICAR)
        link = self.data / "link"
        os.symlink(real, str(link))
        r = self.scan(str(link))
        self.assertEqual(r["verdict"], "COULD-NOT-SCAN")
        self.assertTrue(any("symlink" in x for x in r["reasons"]))

    def test_never_executes_scanned_file(self):
        """Verify that scanned executable scripts are never executed by the scanner."""
        marker = Path(self.td) / "ran"
        p = self.f("script.sh", "#!/bin/sh\ntouch %s\n" % marker)
        os.chmod(p, 0o755)
        self.scan(p)
        self.assertFalse(marker.exists())

    def test_weird_filename(self):
        """Verify that spaces, quotes, and dollar signs are handled safely via symlink aliases."""
        r = self.scan(self.f("sp ace 'q' $x.txt", "hello"))
        self.assertEqual(r["verdict"], "CLEAN")

    def test_filename_with_newline_handled(self):
        """Verify that filenames with embedded newlines do not break parser logic."""
        r = self.scan(self.f("a\nb.txt", EICAR))
        self.assertIn(r["verdict"], ("INFECTED", "SUSPICIOUS", "COULD-NOT-SCAN"))
        self.assertNotEqual(r["verdict"], "CLEAN")

    def test_exit_code_contract(self):
        """Verify standard POSIX exit status code mapping."""
        self.assertEqual([ts.exit_code(v) for v in ("CLEAN", "SUSPICIOUS", "INFECTED", "COULD-NOT-SCAN")], [0, 1, 1, 2])

    def test_cli_prints_verdict_line_per_file(self):
        """Verify CLI terminal output formatting per file."""
        r = self.scan(self.f("a.txt", "hello"), self.f("e.com", EICAR))
        text = ts.render_scan(r)
        self.assertIn("CLEAN: " + str(self.data / "a.txt"), text)
        self.assertIn("INFECTED: " + str(self.data / "e.com"), text)

    def test_no_paths(self):
        """Verify that invoking scan without target paths yields COULD-NOT-SCAN."""
        r = self.scan()
        self.assertEqual(r["verdict"], "COULD-NOT-SCAN")


## -----------------------------------------------------------------------------
## TEST SUITE 2: ATOMIC FORENSIC RECEIPTS
## -----------------------------------------------------------------------------
class Receipts(Base):
    """Unit tests verifying atomic write-once forensic scan audit logs."""

    def test_receipt_written_atomically(self):
        """Verify that receipts are written atomically with SHA-256 and verified schema."""
        r = self.scan(self.f("a.txt", "hello"))
        d = self.root / "data" / "health" / "scans"
        files = list(d.glob("*.json"))
        self.assertEqual(len(files), 1)
        self.assertEqual(list(d.glob("*.tmp")), [])
        doc = json.loads(files[0].read_text())
        self.assertEqual(doc["verdict"], "CLEAN")
        self.assertEqual(len(doc["files"][0]["sha256"]), 64)
        self.assertEqual(r["receipt"], str(files[0]))

    def test_receipts_do_not_overwrite(self):
        """Verify that subsequent scans generate new unique receipt files (never overwriting)."""
        a = self.f("a.txt", "hello")
        self.scan(a)
        self.scan(a)
        self.assertEqual(len(list((self.root / "data" / "health" / "scans").glob("*.json"))), 2)


## -----------------------------------------------------------------------------
## TEST SUITE 3: STATUS DIAGNOSTICS & SIGNATURE UPDATES
## -----------------------------------------------------------------------------
class StatusAndUpdates(Base):
    """Unit tests for status inspection, signature age checking, and update proposals."""

    def _db(self, days_old):
        """Helper to create a fake ClamAV CVD file with specific age."""
        db = Path(self.td) / "db"
        db.mkdir(exist_ok=True)
        p = db / "daily.cvd"
        p.write_text("x")
        t = time.time() - days_old * 86400
        os.utime(str(p), (t, t))
        return db

    def test_status_fresh(self):
        """Verify status reports fresh when ClamAV database is recently modified."""
        s = ts.status(root=self.root, tools=self.tools, db_dir=self._db(1))
        self.assertTrue(s["signatures"]["fresh"])
        self.assertEqual(s["tools"]["clamscan"]["version"], "9.9.9")

    def test_stale_db_creates_proposal_not_fetch(self):
        """Verify that stale signature databases generate proposals without unapproved network requests."""
        called = []
        ts.scan([self.f("a.txt", "hi")], tools=self.tools, root=self.root, db_dir=self._db(9),
                decider=lambda a: called.append(a) or "PROPOSE")
        self.assertIn("update_clamav_signatures", called)
        prop = json.loads(next((self.root / "data" / "health").glob("scan_updates.*.json")).read_text())
        self.assertEqual(prop["items"][0]["action"], "update_clamav_signatures")
        self.assertEqual(prop["items"][0]["class"], "PROPOSE")

    def test_fresh_db_no_proposal(self):
        """Verify that fresh signature databases generate no update proposals."""
        ts.scan([self.f("a.txt", "hi")], tools=self.tools, root=self.root, db_dir=self._db(1),
                decider=lambda a: "PROPOSE")
        props = list((self.root / "data" / "health").glob("scan_updates.*.json"))
        if props:
            self.assertEqual(json.loads(props[0].read_text())["items"], [])

    def test_update_requires_approve(self):
        """Verify that `update_signatures` requires explicit `--approve` flag."""
        out = ts.update_signatures(root=self.root, approve=False, tools=self.tools, runner=lambda *a, **k: self.fail("fetched"))
        self.assertEqual(out["status"], "proposal")

    def test_update_refused_when_policy_never(self):
        """Verify that autonomous policy refusal (NEVER) aborts update."""
        out = ts.update_signatures(root=self.root, approve=True, tools=self.tools, decider=lambda a: "NEVER",
                                   runner=lambda *a, **k: self.fail("fetched"))
        self.assertEqual(out["status"], "refused")

    def test_update_runs_freshclam_when_approved(self):
        """Verify that approved update executes freshclam binary."""
        seen = []
        out = ts.update_signatures(root=self.root, approve=True, tools={"freshclam": "/x/freshclam"},
                                   decider=lambda a: "PROPOSE", runner=lambda argv, t: seen.append(argv) or (0, "ok"))
        self.assertEqual(out["status"], "updated")
        self.assertEqual(seen[0][0], "/x/freshclam")

    def test_active_requires_rules_and_fresh_db(self):
        """Verify that scanner reports NOT ACTIVE when database is stale."""
        s = ts.status(root=self.root, tools=self.tools, db_dir=self._db(30))
        self.assertFalse(s["active"])


## -----------------------------------------------------------------------------
## TEST SUITE 4: PINNED SECURITY TEST FIXTURES
## -----------------------------------------------------------------------------
class PinnedFixtures(Base):
    """Educational Concept: Pinned Test Fixtures.
    A test file that holds attack text on purpose may be allowed by path + sha256;
    any mutation invalidates the hash and rescans it as suspicious.
    """

    def setUp(self):
        super().setUp()
        self.tools["clamscan"] = mk_tool(self.bin, "clam2", FAKE_CLAM.replace('b"EICAR" in d', 'False'))
        (self.root / "scripts").mkdir()
        self.fx = self.root / "scripts" / "test_fix.py"
        self.fx.write_text("# " + EICAR + "\n")
        self.pin(self.fx)

    def pin(self, path, rel="scripts/test_fix.py"):
        """Pin a fixture in EXCLUSIONS.json with its exact SHA-256 hash."""
        import hashlib
        h = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        ex = self.root / "data" / "yara_rules" / "EXCLUSIONS.json"
        d = json.loads(ex.read_text())
        d["fixtures"] = [{"path": rel, "sha256": h, "why": "test fixture"}]
        ex.write_text(json.dumps(d))

    def test_pinned_fixture_is_clean_and_says_why(self):
        """Verify that a pinned fixture with matching hash is classified as CLEAN."""
        r = self.scan(str(self.fx))
        self.assertEqual(r["verdict"], "CLEAN")
        self.assertTrue(any("pinned test fixture" in x for x in r["reasons"]), r["reasons"])
        self.assertTrue(r["files"][0].get("fixture_pinned"))

    def test_changed_fixture_is_rescanned(self):
        """Verify that mutating a pinned fixture revokes exemption and triggers SUSPICIOUS."""
        self.fx.write_text("# " + EICAR + "\n# edited\n")
        self.assertEqual(self.scan(str(self.fx))["verdict"], "SUSPICIOUS")

    def test_same_bytes_at_other_path_not_allowed(self):
        """Verify that exemption requires path match (same bytes elsewhere are flagged)."""
        other = self.root / "scripts" / "other.py"
        other.write_bytes(self.fx.read_bytes())
        self.assertEqual(self.scan(str(other))["verdict"], "SUSPICIOUS")

    def test_outside_repo_never_allowed(self):
        """Verify that fixtures outside repository boundaries are never exempt."""
        out = self.data / "scripts"
        out.mkdir()
        (out / "test_fix.py").write_bytes(self.fx.read_bytes())
        self.assertEqual(self.scan(str(out / "test_fix.py"))["verdict"], "SUSPICIOUS")

    def test_clamav_hit_on_pinned_fixture_still_infected(self):
        """Verify that confirmed ClamAV virus signatures are NEVER suppressed by fixtures."""
        self.tools["clamscan"] = mk_tool(self.bin, "clam3", FAKE_CLAM)
        self.assertEqual(self.scan(str(self.fx))["verdict"], "INFECTED")

    def test_malformed_fixtures_ignored(self):
        """Verify that corrupted fixture schemas fail closed and flag suspicious files."""
        ex = self.root / "data" / "yara_rules" / "EXCLUSIONS.json"
        d = json.loads(ex.read_text())
        d["fixtures"] = ["junk", {"path": 5}, {"path": "scripts/test_fix.py"}]
        ex.write_text(json.dumps(d))
        self.assertEqual(self.scan(str(self.fx))["verdict"], "SUSPICIOUS")


## -----------------------------------------------------------------------------
## TEST SUITE 5: LIVE REPOSITORY RULES & ENGINE INTEGRATION
## -----------------------------------------------------------------------------
class RealRules(unittest.TestCase):
    """Executes live scans using real system binaries and repository YARA rules when available."""

    def setUp(self):
        """Verify availability of native yara, clamscan, and signature database."""
        self.tools = ts.find_tools()
        if not self.tools.get("yara") or not self.tools.get("clamscan"):
            self.skipTest("yara or clamscan not installed")
        if not ts.signature_info(ts.default_db_dir())["present"]:
            self.skipTest("ClamAV signatures not installed / present on this host")
        ## Verify ClamAV database is valid and readable without errors
        db_dir = ts.default_db_dir()
        chk = subprocess.run([self.tools["clamscan"], "--database=" + str(db_dir), "/dev/null"], capture_output=True)
        if chk.returncode not in (0, 1):
            self.skipTest("ClamAV database not fully initialized (%s)" % chk.stderr.decode().strip()[:80])
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, True)

    def test_manifest_verifies(self):
        """Verify cryptographic integrity of repository ruleset against MANIFEST.json."""
        import twu_yara_vet as v
        self.assertEqual(v.verify(), [])

    def test_real_eicar_caught_by_both(self):
        """Verify that live YARA and ClamAV engines both detect the EICAR string."""
        p = Path(self.td) / "eicar.txt"
        p.write_text(EICAR)
        r = ts.scan([str(p)], tools=self.tools, root=Path(self.td) / "r", rules_dir=ts.REPO / "data" / "yara_rules",
                    timeout=300, write_receipt=False)
        engines = {x["engine"] for x in r["files"][0]["findings"]}
        self.assertEqual(r["verdict"], "INFECTED")
        self.assertEqual(engines, {"clamav", "yara"})

    def test_real_clean_file(self):
        """Verify that live engines report CLEAN on standard benign text file."""
        p = Path(self.td) / "clean.txt"
        p.write_text("just a harmless note\n")
        r = ts.scan([str(p)], tools=self.tools, root=Path(self.td) / "r", rules_dir=ts.REPO / "data" / "yara_rules",
                    timeout=300, write_receipt=False)
        self.assertEqual(r["verdict"], "CLEAN", r["reasons"])


if __name__ == "__main__":
    unittest.main()
