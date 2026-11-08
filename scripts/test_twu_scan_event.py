#!/usr/bin/env python3
## ==============================================================================
## UNIT TESTS: EVENT-DRIVEN FILE SCANNER & FORENSIC ALERT STAGING
## ==============================================================================
## Author: Ethan REDACTED <ethan@REDACTED>
## Organization: TWU LLC
## Copyright: (c) 2026 Ethan REDACTED, TWU LLC
## License: MIT License 2026
##
## Educational Purpose:
## This test suite validates the event-driven filesystem watcher mechanisms,
## single-sleep debounce stabilization, deduplication state caching, memory-safe
## GGUF model header inspection, and USB removable media depth containment
## implemented in `twu_scan_event.py`.
##
## Key Test Areas:
## 1. Internal Path Filtering: Proves scanner self-trigger loops are prevented by
##    filtering out receipts, manifests, and VCS metadata before any disk I/O.
## 2. Write Stability Debouncing: Asserts files undergoing active writes are
##    safely deferred to the subsequent event pass rather than corrupted.
## 3. Scalable Debounce Architecture: Verifies that candidate files share a SINGLE
##    debounce wait interval instead of stalling the system with per-file sleeps.
## 4. Non-Destructive Forensic Alerts: Confirms that flagged files are preserved
##    intact in place while structured alert records are staged atomically.
## 5. Memory-Safe Model Headers: Proves large AI checkpoints (GGUF) are inspected
##    via an isolated 16 MiB header window, avoiding out-of-memory kernel kills.
## 6. Removable Media (USB) Containment: Verifies depth bounding (depth=3) and
##    automatic detection of Windows autorun.inf threat vectors.
## ==============================================================================

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

## Ensure scripts directory is on Python search path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import twu_scan_event as ev  # noqa: E402


def fake_scan(verdicts):
    """Generate a mock scanner callable returning predetermined verdicts.

    Parameters:
        verdicts (dict[str, str]): Mapping of basename to verdict ('CLEAN', 'SUSPICIOUS', 'INFECTED').

    Returns:
        callable: Mock scanner function compatible with `twu_scan.scan()` signature.
    """
    def f(paths, **kw):
        files = [
            {
                "path": p,
                "verdict": verdicts.get(os.path.basename(p), "CLEAN"),
                "sha256": "ab" * 32,
                "findings": (
                    [{"engine": "yara", "name": "Rule_X"}]
                    if verdicts.get(os.path.basename(p)) in ("SUSPICIOUS", "INFECTED")
                    else []
                ),
                "errors": [],
            }
            for p in paths
        ]
        worst = max((x["verdict"] for x in files), key=lambda v: ev.twu_scan.VERDICT_RANK[v], default="CLEAN")
        return {"verdict": worst, "files": files, "receipt": "r.json", "reasons": [], "notes": []}
    return f


## -----------------------------------------------------------------------------
## TEST SUITE: EVENT PROCESSING, DEBOUNCING, AND CONTAINMENT
## -----------------------------------------------------------------------------
class TestScanEvent(unittest.TestCase):
    """Exhaustive test suite for event-driven scanning and containment."""

    def setUp(self):
        """Create clean temporary repository structure for isolated testing."""
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name) / "repo"
        (self.root / "data" / "health").mkdir(parents=True)
        self.d = Path(self.td.name) / "in"
        self.d.mkdir()

    def tearDown(self):
        """Clean up temporary sandbox files."""
        self.td.cleanup()

    def mk(self, name, data=b"hello"):
        """Create sample regular file in candidate directory."""
        p = self.d / name
        p.write_bytes(data)
        return str(p)

    def run_new(self, paths, verdicts=None, **kw):
        """Invoke `scan_new()` with mock scanner and zero wait by default."""
        return ev.scan_new(
            paths,
            root=self.root,
            scanner=fake_scan(verdicts or {}),
            wait=0,
            sleeper=lambda s: None,
            **kw
        )

    def test_skip_own_files(self):
        """Verify internal control files, receipts, and Syncthing metadata are skipped."""
        r = self.root
        for rel in (
            ".git/x",
            "data/health/scans/a.json",
            "data/health/scan_alerts.h.json",
            "data/yara_rules/a.yar",
            "a/.stversions/x",
            "a/.syncthing.f.tmp",
            "a/~syncthing~f.tmp",
            ".DS_Store",
        ):
            self.assertTrue(ev.skip_reason(str(r / rel), r), rel)
        ## Standard external file should not be skipped
        self.assertIsNone(ev.skip_reason(str(self.d / "ok.txt"), r))

    def test_clean_no_alert(self):
        """Verify that files evaluated as CLEAN do not generate alert records."""
        res = self.run_new([self.mk("a.txt")])
        self.assertEqual(res["verdict"], "CLEAN")
        self.assertFalse((self.root / "data/health" / ("scan_alerts.%s.json" % ev.HOST)).exists())

    def test_suspicious_writes_alert_moves_nothing(self):
        """Verify non-destructive staging: flagged file remains untouched on disk."""
        p = self.mk("bad.bin")
        res = self.run_new([p], {"bad.bin": "INFECTED"})
        self.assertEqual(res["verdict"], "INFECTED")
        ## File MUST remain in place for forensic investigation
        self.assertTrue(os.path.exists(p))
        doc = json.loads((self.root / "data/health" / ("scan_alerts.%s.json" % ev.HOST)).read_text())
        self.assertEqual(doc["alerts"][0]["path"], p)
        self.assertIn("Do not open", doc["alerts"][0]["sentence"])

    def test_alerts_newest_first_and_capped(self):
        """Verify that alerts are sorted newest-first and capped at MAX_ALERTS limit."""
        for i in range(ev.MAX_ALERTS + 5):
            p = self.mk("b%d.bin" % i, b"x%d" % i)
            self.run_new([p], {"b%d.bin" % i: "SUSPICIOUS"})
        doc = json.loads((self.root / "data/health" / ("scan_alerts.%s.json" % ev.HOST)).read_text())
        self.assertEqual(len(doc["alerts"]), ev.MAX_ALERTS)
        self.assertTrue(doc["alerts"][0]["path"].endswith("b%d.bin" % (ev.MAX_ALERTS + 4)))

    def test_debounce_same_file_not_rescanned(self):
        """Verify deduplication cache prevents redundant rescanning of unchanged files."""
        p = self.mk("a.txt")
        self.assertEqual(len(self.run_new([p])["scanned"]), 1)
        r2 = self.run_new([p])
        self.assertEqual(len(r2["scanned"]), 0)
        self.assertEqual(r2["skipped"][0]["why"], "unchanged since last scan")

    def test_unstable_file_skipped(self):
        """Verify that a file actively being written during debounce delay is deferred."""
        p = self.mk("a.txt")
        ## Mutate file content during simulated debounce delay
        res = ev.scan_new(
            [p],
            root=self.root,
            scanner=fake_scan({}),
            wait=2,
            sleeper=lambda s: Path(p).write_bytes(b"more than before"),
        )
        self.assertEqual(res["scanned"], [])
        self.assertIn("still being written", res["skipped"][0]["why"])

    def test_size_cap_is_not_clean(self):
        """Verify that oversized files yield COULD-NOT-SCAN under fail-closed policy."""
        p = self.mk("big.bin", b"x" * 20)
        real = lambda paths, **kw: ev.twu_scan.scan(paths, write_receipt=False, **kw)
        res = ev.scan_new([p], root=self.root, scanner=real, wait=0, sleeper=lambda s: None, max_bytes=10)
        self.assertEqual(res["verdict"], "COULD-NOT-SCAN")

    def test_expand_dirs_recent_only(self):
        """Verify directory expansion filters files outside modification window."""
        new = self.mk("new.txt")
        old = self.mk("old.txt")
        os.utime(old, (1, 1))
        got = [os.path.basename(p) for p in ev.expand_dirs([str(self.d)])]
        self.assertEqual(got, ["new.txt"])

    def test_stability_wait_is_one_sleep_for_all_files(self):
        """Verify scalable debouncing: executes exactly ONE sleep for the entire candidate batch."""
        ps = [self.mk("f%d.txt" % i) for i in range(30)]
        calls = []
        ev.scan_new(ps, root=self.root, scanner=fake_scan({}), wait=2, sleeper=lambda s: calls.append(s))
        self.assertEqual(len(calls), 1)  ## Single batch delay prevents O(N) wait scaling

    def test_expand_dirs_skips_noise_dirs_and_old_pass(self):
        """Verify expansion skips internal noise directories and respect since_ts threshold."""
        for sub in ("data/health", "receipts", "rules", "archive", ".git", "keep"):
            (self.d / sub).mkdir(parents=True, exist_ok=True)
            (self.d / sub / "x.txt").write_text("hi")
        got = sorted(os.path.relpath(p, str(self.d)) for p in ev.expand_dirs([str(self.d)]))
        self.assertEqual(got, ["keep/x.txt"])
        a = self.mk("a.txt")
        os.utime(a, (1000, 1000))
        got = [os.path.basename(p) for p in ev.expand_dirs([str(self.d / "keep")], since_ts=1e12)]
        self.assertEqual(got, [])

    def test_last_pass_roundtrip_and_survives_state_prune(self):
        """Verify last pass timestamp is preserved across state cache pruning."""
        ev.save_last_pass(self.root, 1234.5)
        self.assertEqual(ev.load_last_pass(self.root), 1234.5)
        self.run_new([self.mk("z.txt")])
        self.assertEqual(ev.load_last_pass(self.root), 1234.5)

    def test_main_logs_start_and_done(self):
        """Verify CLI main entrypoint outputs operational start/done telemetry."""
        self.mk("m.txt")
        buf = io.StringIO()
        real, ev.twu_scan.scan = ev.twu_scan.scan, fake_scan({})
        self.addCleanup(setattr, ev.twu_scan, "scan", real)
        with contextlib.redirect_stdout(buf):
            ev.main(["scan-new", "--dir", str(self.d), "--root", str(self.root), "--no-wait"])
        out = buf.getvalue()
        self.assertIn("start", out)
        self.assertIn("done", out)
        self.assertIn("files=", out)
        self.assertGreater(ev.load_last_pass(self.root), 0)

    def test_gguf_header_pass(self):
        """Verify memory-safe GGUF inspection: evaluates initial header without reading tensors."""
        p = self.mk("m.gguf", b"GGUF" + b"\0" * 100)
        out = ev.gguf_header_scan(p, scanner=fake_scan({}), nbytes=50)
        self.assertEqual(out["verdict"], "CLEAN")
        self.assertTrue(out["partial"])
        self.assertEqual(out["bytes_scanned"], 50)
        bad = ev.gguf_header_scan(self.mk("n.gguf", b"GGUF"), scanner=fake_scan({"header.n.gguf": "SUSPICIOUS"}))
        self.assertEqual(bad["verdict"], "SUSPICIOUS")

    def test_usb_depth_cap_and_autorun(self):
        """Verify USB containment: enforces directory depth limit and detects autorun.inf."""
        v = self.d / "VOL"
        (v / "a/b/c/d").mkdir(parents=True)
        (v / "top.txt").write_text("1")
        (v / "a/b/c/d/deep.txt").write_text("2")
        (v / "autorun.inf").write_text("[autorun]")
        res = ev.usb_scan([str(v)], root=self.root, scanner=fake_scan({}), depth=2)
        names = [os.path.basename(x["path"]) for x in res["files"]]
        self.assertIn("top.txt", names)
        self.assertNotIn("deep.txt", names)
        self.assertTrue(res["too_deep"])
        self.assertIn("autorun.inf", " ".join(res["warnings"]))
        self.assertNotEqual(res["verdict"], "CLEAN")  ## Unscanned depth prevents CLEAN verdict

    def test_usb_default_volumes_skips_symlink_root(self):
        """Verify removable media discovery ignores symlinked root filesystem volumes."""
        vols = self.d / "Volumes"
        (vols / "USB").mkdir(parents=True)
        os.symlink("/", vols / "Macintosh HD")
        self.assertEqual([os.path.basename(x) for x in ev.list_volumes(str(vols))], ["USB"])


if __name__ == "__main__":
    unittest.main()
