import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import twu_scan as ts  # noqa: E402

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
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
    p = Path(d) / name
    p.write_text(body)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return str(p)


class Base(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, True)
        self.root = Path(self.td) / "root"
        (self.root / "data" / "yara_rules").mkdir(parents=True)
        (self.root / "data" / "yara_rules" / "index.yar").write_text("// empty\n")
        (self.root / "data" / "yara_rules" / "EXCLUSIONS.json").write_text(json.dumps({"excluded": [{"rule": "Excluded_Rule"}]}))
        (self.root / "data" / "yara_rules" / "MANIFEST.json").write_text(
            json.dumps({"files": [], "rule_count": 5, "built_epoch": int(time.time())}))
        self.bin = Path(self.td) / "bin"
        self.bin.mkdir()
        self.tools = {"yara": mk_tool(self.bin, "yara", FAKE_YARA), "clamscan": mk_tool(self.bin, "clamscan", FAKE_CLAM)}
        self.data = Path(self.td) / "data"
        self.data.mkdir()

    def f(self, name, text):
        p = self.data / name
        p.write_text(text)
        return str(p)

    def scan(self, *paths, **kw):
        kw.setdefault("tools", self.tools)
        kw.setdefault("root", self.root)
        return ts.scan(list(paths), **kw)


class Verdicts(Base):
    def test_clean(self):
        r = self.scan(self.f("a.txt", "hello"))
        self.assertEqual(r["verdict"], "CLEAN")
        self.assertEqual(ts.exit_code(r["verdict"]), 0)

    def test_eicar_both_engines_infected(self):
        r = self.scan(self.f("e.com", EICAR))
        self.assertEqual(r["verdict"], "INFECTED")
        self.assertNotEqual(ts.exit_code(r["verdict"]), 0)
        engines = {x["engine"] for x in r["files"][0]["findings"]}
        self.assertEqual(engines, {"clamav", "yara"})

    def test_yara_only_is_suspicious(self):
        self.tools["clamscan"] = mk_tool(self.bin, "clam2", FAKE_CLAM.replace('b"EICAR" in d', 'False'))
        r = self.scan(self.f("e.com", EICAR))
        self.assertEqual(r["verdict"], "SUSPICIOUS")
        self.assertEqual(ts.exit_code("SUSPICIOUS"), 1)

    def test_excluded_rule_ignored(self):
        r = self.scan(self.f("x.txt", "MARKER_EXCLUDED"))
        self.assertEqual(r["verdict"], "CLEAN")

    def test_missing_engine_is_could_not_scan_not_clean(self):
        self.tools["clamscan"] = None
        r = self.scan(self.f("a.txt", "hello"))
        self.assertEqual(r["verdict"], "COULD-NOT-SCAN")
        self.assertTrue(any("clamscan" in x for x in r["reasons"]))

    def test_missing_engine_still_reports_detection(self):
        self.tools["clamscan"] = None
        r = self.scan(self.f("e.com", EICAR))
        self.assertEqual(r["verdict"], "SUSPICIOUS")

    def test_oversize_could_not_scan(self):
        r = self.scan(self.f("big.bin", "x" * 100), max_bytes=10)
        self.assertEqual(r["verdict"], "COULD-NOT-SCAN")
        self.assertTrue(any("larger than" in x for x in r["reasons"]))

    def test_missing_path(self):
        r = self.scan(str(self.data / "nope"))
        self.assertEqual(r["verdict"], "COULD-NOT-SCAN")

    def test_timeout(self):
        r = self.scan(self.f("s.txt", "MARKER_SLEEP"), timeout=1)
        self.assertEqual(r["verdict"], "COULD-NOT-SCAN")
        self.assertTrue(any("time" in x for x in r["reasons"]))

    def test_directory_recursed_worst_wins(self):
        sub = self.data / "d" / "e"
        sub.mkdir(parents=True)
        (sub / "bad").write_text(EICAR)
        (self.data / "d" / "ok").write_text("fine")
        r = self.scan(str(self.data / "d"))
        self.assertEqual(r["verdict"], "INFECTED")
        self.assertEqual(len(r["files"]), 2)

    def test_symlink_not_followed(self):
        real = self.f("real.txt", EICAR)
        link = self.data / "link"
        os.symlink(real, str(link))
        r = self.scan(str(link))
        self.assertEqual(r["verdict"], "COULD-NOT-SCAN")
        self.assertTrue(any("symlink" in x for x in r["reasons"]))

    def test_never_executes_scanned_file(self):
        marker = Path(self.td) / "ran"
        p = self.f("script.sh", "#!/bin/sh\ntouch %s\n" % marker)
        os.chmod(p, 0o755)
        self.scan(p)
        self.assertFalse(marker.exists())

    def test_weird_filename(self):
        r = self.scan(self.f("sp ace 'q' $x.txt", "hello"))
        self.assertEqual(r["verdict"], "CLEAN")

    def test_filename_with_newline_handled(self):
        r = self.scan(self.f("a\nb.txt", EICAR))
        self.assertIn(r["verdict"], ("INFECTED", "SUSPICIOUS", "COULD-NOT-SCAN"))
        self.assertNotEqual(r["verdict"], "CLEAN")

    def test_exit_code_contract(self):
        self.assertEqual([ts.exit_code(v) for v in ("CLEAN", "SUSPICIOUS", "INFECTED", "COULD-NOT-SCAN")], [0, 1, 1, 2])

    def test_cli_prints_verdict_line_per_file(self):
        r = self.scan(self.f("a.txt", "hello"), self.f("e.com", EICAR))
        text = ts.render_scan(r)
        self.assertIn("CLEAN: " + str(self.data / "a.txt"), text)
        self.assertIn("INFECTED: " + str(self.data / "e.com"), text)

    def test_no_paths(self):
        r = self.scan()
        self.assertEqual(r["verdict"], "COULD-NOT-SCAN")


class Receipts(Base):
    def test_receipt_written_atomically(self):
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
        a = self.f("a.txt", "hello")
        self.scan(a)
        self.scan(a)
        self.assertEqual(len(list((self.root / "data" / "health" / "scans").glob("*.json"))), 2)


class StatusAndUpdates(Base):
    def _db(self, days_old):
        db = Path(self.td) / "db"
        db.mkdir(exist_ok=True)
        p = db / "daily.cvd"
        p.write_text("x")
        t = time.time() - days_old * 86400
        os.utime(str(p), (t, t))
        return db

    def test_status_fresh(self):
        s = ts.status(root=self.root, tools=self.tools, db_dir=self._db(1))
        self.assertTrue(s["signatures"]["fresh"])
        self.assertEqual(s["tools"]["clamscan"]["version"], "9.9.9")

    def test_stale_db_creates_proposal_not_fetch(self):
        called = []
        ts.scan([self.f("a.txt", "hi")], tools=self.tools, root=self.root, db_dir=self._db(9),
                decider=lambda a: called.append(a) or "PROPOSE")
        self.assertIn("update_clamav_signatures", called)
        prop = json.loads(next((self.root / "data" / "health").glob("scan_updates.*.json")).read_text())
        self.assertEqual(prop["items"][0]["action"], "update_clamav_signatures")
        self.assertEqual(prop["items"][0]["class"], "PROPOSE")

    def test_fresh_db_no_proposal(self):
        ts.scan([self.f("a.txt", "hi")], tools=self.tools, root=self.root, db_dir=self._db(1),
                decider=lambda a: "PROPOSE")
        props = list((self.root / "data" / "health").glob("scan_updates.*.json"))
        if props:
            self.assertEqual(json.loads(props[0].read_text())["items"], [])

    def test_update_requires_approve(self):
        out = ts.update_signatures(root=self.root, approve=False, tools=self.tools, runner=lambda *a, **k: self.fail("fetched"))
        self.assertEqual(out["status"], "proposal")

    def test_update_refused_when_policy_never(self):
        out = ts.update_signatures(root=self.root, approve=True, tools=self.tools, decider=lambda a: "NEVER",
                                   runner=lambda *a, **k: self.fail("fetched"))
        self.assertEqual(out["status"], "refused")

    def test_update_runs_freshclam_when_approved(self):
        seen = []
        out = ts.update_signatures(root=self.root, approve=True, tools={"freshclam": "/x/freshclam"},
                                   decider=lambda a: "PROPOSE", runner=lambda argv, t: seen.append(argv) or (0, "ok"))
        self.assertEqual(out["status"], "updated")
        self.assertEqual(seen[0][0], "/x/freshclam")

    def test_active_requires_rules_and_fresh_db(self):
        s = ts.status(root=self.root, tools=self.tools, db_dir=self._db(30))
        self.assertFalse(s["active"])


class PinnedFixtures(Base):
    """A test file that holds attack text on purpose may be allowed by path + sha256; any change rescans it."""
    def setUp(self):
        super().setUp()
        self.tools["clamscan"] = mk_tool(self.bin, "clam2", FAKE_CLAM.replace('b"EICAR" in d', 'False'))
        (self.root / "scripts").mkdir()
        self.fx = self.root / "scripts" / "test_fix.py"
        self.fx.write_text("# " + EICAR + "\n")
        self.pin(self.fx)

    def pin(self, path, rel="scripts/test_fix.py"):
        import hashlib
        h = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        ex = self.root / "data" / "yara_rules" / "EXCLUSIONS.json"
        d = json.loads(ex.read_text())
        d["fixtures"] = [{"path": rel, "sha256": h, "why": "test fixture"}]
        ex.write_text(json.dumps(d))

    def test_pinned_fixture_is_clean_and_says_why(self):
        r = self.scan(str(self.fx))
        self.assertEqual(r["verdict"], "CLEAN")
        self.assertTrue(any("pinned test fixture" in x for x in r["reasons"]), r["reasons"])
        self.assertTrue(r["files"][0].get("fixture_pinned"))

    def test_changed_fixture_is_rescanned(self):
        self.fx.write_text("# " + EICAR + "\n# edited\n")
        self.assertEqual(self.scan(str(self.fx))["verdict"], "SUSPICIOUS")

    def test_same_bytes_at_other_path_not_allowed(self):
        other = self.root / "scripts" / "other.py"
        other.write_bytes(self.fx.read_bytes())
        self.assertEqual(self.scan(str(other))["verdict"], "SUSPICIOUS")

    def test_outside_repo_never_allowed(self):
        out = self.data / "scripts"
        out.mkdir()
        (out / "test_fix.py").write_bytes(self.fx.read_bytes())
        self.assertEqual(self.scan(str(out / "test_fix.py"))["verdict"], "SUSPICIOUS")

    def test_clamav_hit_on_pinned_fixture_still_infected(self):
        self.tools["clamscan"] = mk_tool(self.bin, "clam3", FAKE_CLAM)
        self.assertEqual(self.scan(str(self.fx))["verdict"], "INFECTED")

    def test_malformed_fixtures_ignored(self):
        ex = self.root / "data" / "yara_rules" / "EXCLUSIONS.json"
        d = json.loads(ex.read_text())
        d["fixtures"] = ["junk", {"path": 5}, {"path": "scripts/test_fix.py"}]
        ex.write_text(json.dumps(d))
        self.assertEqual(self.scan(str(self.fx))["verdict"], "SUSPICIOUS")


class RealRules(unittest.TestCase):
    """Uses the repo's vetted rules and the real engines when this box has them."""
    def setUp(self):
        self.tools = ts.find_tools()
        if not self.tools.get("yara") or not self.tools.get("clamscan"):
            self.skipTest("yara or clamscan not installed")
        if not ts.signature_info(ts.default_db_dir())["present"]:
            self.skipTest("ClamAV signatures not installed / present on this host")
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, True)

    def test_manifest_verifies(self):
        import twu_yara_vet as v
        self.assertEqual(v.verify(), [])

    def test_real_eicar_caught_by_both(self):
        p = Path(self.td) / "eicar.txt"
        p.write_text(EICAR)
        r = ts.scan([str(p)], tools=self.tools, root=Path(self.td) / "r", rules_dir=ts.REPO / "data" / "yara_rules",
                    timeout=300, write_receipt=False)
        engines = {x["engine"] for x in r["files"][0]["findings"]}
        self.assertEqual(r["verdict"], "INFECTED")
        self.assertEqual(engines, {"clamav", "yara"})

    def test_real_clean_file(self):
        p = Path(self.td) / "clean.txt"
        p.write_text("just a harmless note\n")
        r = ts.scan([str(p)], tools=self.tools, root=Path(self.td) / "r", rules_dir=ts.REPO / "data" / "yara_rules",
                    timeout=300, write_receipt=False)
        self.assertEqual(r["verdict"], "CLEAN", r["reasons"])


if __name__ == "__main__":
    unittest.main()
