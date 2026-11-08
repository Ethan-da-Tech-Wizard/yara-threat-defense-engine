import json, os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import twu_scan_event as ev


def fake_scan(verdicts):
    def f(paths, **kw):
        files = [{"path": p, "verdict": verdicts.get(os.path.basename(p), "CLEAN"), "sha256": "ab" * 32,
                  "findings": [{"engine": "yara", "name": "Rule_X"}] if verdicts.get(os.path.basename(p)) in ("SUSPICIOUS", "INFECTED") else [],
                  "errors": []} for p in paths]
        worst = max((x["verdict"] for x in files), key=lambda v: ev.twu_scan.VERDICT_RANK[v], default="CLEAN")
        return {"verdict": worst, "files": files, "receipt": "r.json", "reasons": [], "notes": []}
    return f


class T(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name) / "repo"
        (self.root / "data" / "health").mkdir(parents=True)
        self.d = Path(self.td.name) / "in"
        self.d.mkdir()

    def tearDown(self):
        self.td.cleanup()

    def mk(self, name, data=b"hello"):
        p = self.d / name
        p.write_bytes(data)
        return str(p)

    def run_new(self, paths, verdicts=None, **kw):
        return ev.scan_new(paths, root=self.root, scanner=fake_scan(verdicts or {}), wait=0, sleeper=lambda s: None, **kw)

    def test_skip_own_files(self):
        r = self.root
        for rel in (".git/x", "data/health/scans/a.json", "data/health/scan_alerts.h.json", "data/yara_rules/a.yar", "a/.stversions/x", "a/.syncthing.f.tmp", "a/~syncthing~f.tmp", ".DS_Store"):
            self.assertTrue(ev.skip_reason(str(r / rel), r), rel)
        self.assertIsNone(ev.skip_reason(str(self.d / "ok.txt"), r))

    def test_clean_no_alert(self):
        res = self.run_new([self.mk("a.txt")])
        self.assertEqual(res["verdict"], "CLEAN")
        self.assertFalse((self.root / "data/health" / ("scan_alerts.%s.json" % ev.HOST)).exists())

    def test_suspicious_writes_alert_moves_nothing(self):
        p = self.mk("bad.bin")
        res = self.run_new([p], {"bad.bin": "INFECTED"})
        self.assertEqual(res["verdict"], "INFECTED")
        self.assertTrue(os.path.exists(p))
        doc = json.loads((self.root / "data/health" / ("scan_alerts.%s.json" % ev.HOST)).read_text())
        self.assertEqual(doc["alerts"][0]["path"], p)
        self.assertIn("Do not open", doc["alerts"][0]["sentence"])

    def test_alerts_newest_first_and_capped(self):
        for i in range(ev.MAX_ALERTS + 5):
            p = self.mk("b%d.bin" % i, b"x%d" % i)
            self.run_new([p], {"b%d.bin" % i: "SUSPICIOUS"})
        doc = json.loads((self.root / "data/health" / ("scan_alerts.%s.json" % ev.HOST)).read_text())
        self.assertEqual(len(doc["alerts"]), ev.MAX_ALERTS)
        self.assertTrue(doc["alerts"][0]["path"].endswith("b%d.bin" % (ev.MAX_ALERTS + 4)))

    def test_debounce_same_file_not_rescanned(self):
        p = self.mk("a.txt")
        self.assertEqual(len(self.run_new([p])["scanned"]), 1)
        r2 = self.run_new([p])
        self.assertEqual(len(r2["scanned"]), 0)
        self.assertEqual(r2["skipped"][0]["why"], "unchanged since last scan")

    def test_unstable_file_skipped(self):
        p = self.mk("a.txt")
        sizes = iter([1, 2, 3, 4])
        res = ev.scan_new([p], root=self.root, scanner=fake_scan({}), wait=2, sleeper=lambda s: Path(p).write_bytes(b"more than before"))
        self.assertEqual(res["scanned"], [])
        self.assertIn("still being written", res["skipped"][0]["why"])

    def test_size_cap_is_not_clean(self):
        p = self.mk("big.bin", b"x" * 20)
        real = lambda paths, **kw: ev.twu_scan.scan(paths, write_receipt=False, **kw)
        res = ev.scan_new([p], root=self.root, scanner=real, wait=0, sleeper=lambda s: None, max_bytes=10)
        self.assertEqual(res["verdict"], "COULD-NOT-SCAN")

    def test_expand_dirs_recent_only(self):
        new = self.mk("new.txt")
        old = self.mk("old.txt")
        os.utime(old, (1, 1))
        got = [os.path.basename(p) for p in ev.expand_dirs([str(self.d)])]
        self.assertEqual(got, ["new.txt"])

    def test_stability_wait_is_one_sleep_for_all_files(self):
        ps = [self.mk("f%d.txt" % i) for i in range(30)]
        calls = []
        ev.scan_new(ps, root=self.root, scanner=fake_scan({}), wait=2, sleeper=lambda s: calls.append(s))
        self.assertEqual(len(calls), 1)  # was one 2 s sleep PER file: 2000 files = over an hour under launchd

    def test_expand_dirs_skips_noise_dirs_and_old_pass(self):
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
        ev.save_last_pass(self.root, 1234.5)
        self.assertEqual(ev.load_last_pass(self.root), 1234.5)
        self.run_new([self.mk("z.txt")])
        self.assertEqual(ev.load_last_pass(self.root), 1234.5)

    def test_main_logs_start_and_done(self):
        import io, contextlib
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
        p = self.mk("m.gguf", b"GGUF" + b"\0" * 100)
        out = ev.gguf_header_scan(p, scanner=fake_scan({}), nbytes=50)
        self.assertEqual(out["verdict"], "CLEAN")
        self.assertTrue(out["partial"])
        self.assertEqual(out["bytes_scanned"], 50)
        bad = ev.gguf_header_scan(self.mk("n.gguf", b"GGUF"), scanner=fake_scan({"header.n.gguf": "SUSPICIOUS"}))
        self.assertEqual(bad["verdict"], "SUSPICIOUS")

    def test_usb_depth_cap_and_autorun(self):
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
        self.assertNotEqual(res["verdict"], "CLEAN")  # unscanned depth means not fully cleared

    def test_usb_default_volumes_skips_symlink_root(self):
        vols = self.d / "Volumes"
        (vols / "USB").mkdir(parents=True)
        os.symlink("/", vols / "Macintosh HD")
        self.assertEqual([os.path.basename(x) for x in ev.list_volumes(str(vols))], ["USB"])


if __name__ == "__main__":
    unittest.main()
