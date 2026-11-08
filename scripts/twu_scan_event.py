#!/usr/bin/env python3
## ==============================================================================
## TWU THREAT DEFENSE ENGINE: EVENT-DRIVEN SCANNER & ALERT STAGING
## ==============================================================================
## Author: Ethan REDACTED <ethan@REDACTED>
## Organization: TWU LLC
## Copyright: (c) 2026 Ethan REDACTED, TWU LLC
## License: MIT License 2026
##
## EDUCATIONAL ARCHITECTURE: EVENT-DRIVEN THREAT DETECTION & QUARANTINE STAGING
## ------------------------------------------------------------------------------
## Traditional antivirus architectures frequently rely on continuous filesystem
## polling or heavyweight kernel filesystem filter drivers. In constrained,
## high-security, or containerized environments, these approaches present major
## drawbacks: high idle CPU usage, battery drain, memory leaks, and kernel panics.
##
## This module demonstrates an event-driven, zero-daemon scanning architecture:
##
## 1. Passive Event Hook Integration:
##    - Integrates natively with operating system notification facilities:
##      systemd `.path` units on Linux, `launchd` `WatchPaths` on macOS, or
##      file synchronization hooks (such as Syncthing folder change events).
##    - Near-zero idle CPU: The process executes only when filesystem events fire,
##      scans new/modified files, persists state, and immediately terminates.
##
## 2. I/O Race Prevention & Write Stability (Debouncing):
##    - Files arriving via network sync or browser downloads are often written
##      incrementally across several seconds. Scanning a file mid-write yields
##      corrupted hashes, false COULD-NOT-SCAN errors, or false negatives.
##    - Mechanism: We capture a high-resolution stat signature `(st_size, st_mtime_ns)`.
##      After a single shared wait interval (default 2.0s), we re-verify the snapshot.
##      If the file is still changing, it is gracefully deferred to the next event pass.
##
## 3. State Deduplication & Scalable Inode Tracking:
##    - Retains a persistent cache mapping `file_path -> [st_size, st_mtime_ns]`.
##    - Repeated events on existing files bypass rescanning in microseconds,
##      preventing redundant compute load while preserving instant responsiveness.
##
## 4. Non-Destructive Quarantine Staging:
##    - Automated scripts should NEVER silently delete or alter flagged files.
##      Premature deletion destroys forensic evidence required for incident
##      response, reverse engineering, and threat attribution.
##    - Staging Pattern: The file remains untouched in place; permissions can be
##      restricted, and structured forensic alerts (`scan_alerts.<host>.json`)
##      are dispatched atomically for human security review.
##
## 5. Safe Model Header Scanning (GGUF Tensors):
##    - Machine learning weights (GGUF, Safetensors) are frequently 10 GB - 70 GB.
##      Full memory-mapping or hashing of these files risks immediate Out-Of-Memory
##      (OOM) crashes and system freezes.
##    - `gguf_header_scan` inspects only the first 16 MiB of the file header,
##      where metadata, embedded scripts, and malicious loader structures reside,
##      providing fast heuristic screening without exhausting host RAM.
##
## 6. Removable Media (USB) Containment:
##    - Removable drives present physical attack vectors (e.g. BadUSB, AutoRun worms).
##    - Employs strict directory depth limits (depth=3) and file count caps (max 5000)
##      to prevent zip bombs, directory traversal loops, or denial-of-service.
## ==============================================================================

"""twu_scan_event: Event-Driven File Security Scanner and Forensic Alert Staging."""

## -----------------------------------------------------------------------------
## SECTION 1: IMPORTS & GLOBAL CONFIGURATION CONSTANTS
## -----------------------------------------------------------------------------
import argparse
import json
import os
import platform
import stat
import sys
import tempfile
import time
from pathlib import Path

## Base directory setup: Anchors to repository root
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
import twu_scan  # noqa: E402

## Node identification for multi-device cluster tracking
HOST = platform.node().split(".")[0] or "host"

## Operational guardrails and thresholds
MAX_ALERTS = 50                      ## Maximum alert history retained in rolling alert log
MAX_STATE = 5000                     ## Maximum file paths tracked in deduplication cache
DEFAULT_MAX_BYTES = 500 * 1024 * 1024  ## 500 MiB upper limit for event-triggered files
STABLE_SECONDS = 2.0                 ## Debounce interval to ensure file writes completed
GGUF_HEADER_BYTES = 16 * 1024 * 1024  ## 16 MiB window for scanning ML model headers
USB_DEPTH = 3                        ## Maximum directory depth scanned on external media
USB_MAX_FILES = 5000                 ## Maximum file count threshold for USB drives

## Directory segments and filenames excluded from event processing
SKIP_PARTS = (".git", ".stversions", ".stfolder", ".hg", ".svn")
SKIP_NAMES = (".DS_Store", ".stignore", ".stfolder")
RANK = twu_scan.VERDICT_RANK


def _stamp(t=None):
    """Format local timestamp for standard operational logging.

    Parameters:
        t (float | None): Epoch timestamp.

    Returns:
        str: YYYY-MM-DD HH:MM:SS formatted string.
    """
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t or time.time()))


def _worse(a, b):
    """Compare two threat verdicts and return the one with higher severity rank.

    Parameters:
        a (str): First verdict string.
        b (str): Second verdict string.

    Returns:
        str: Higher-ranking verdict.
    """
    return a if RANK[a] >= RANK[b] else b


## -----------------------------------------------------------------------------
## SECTION 2: INTERNAL FILE & VCS FILTERING
## -----------------------------------------------------------------------------
def skip_reason(path, root=REPO):
    """Filter out internal control files, VCS metadata, and temporary artifacts.

    Educational Pattern: Preventing Scanner Self-Trigger Loops.
    If an event scanner flags its own scan receipts, log files, or YARA rule files,
    it could trigger an infinite loop of filesystem events. This function filters
    out all known internal artifacts before any disk I/O occurs.

    Parameters:
        path (str): Candidate file path.
        root (Path | str): Workspace root.

    Returns:
        str | None: String reason if file should be skipped, else None.
    """
    p = os.path.abspath(path)
    parts = Path(p).parts
    base = os.path.basename(p)

    ## 1. Skip VCS internal metadata and version control history
    if any(x in SKIP_PARTS for x in parts):
        return "inside .git / Syncthing versions"

    ## 2. Skip temporary partial downloads or OS clutter
    if (
        base in SKIP_NAMES
        or base.startswith(".syncthing.")
        or base.startswith("~syncthing~")
        or base.endswith(".part")
        or base.endswith(".crdownload")
    ):
        return "temporary or bookkeeping file"

    ## 3. Skip scanner's own receipts and rule directories
    r = os.path.abspath(str(root))
    for rel in ("data/health/scans", "data/yara_rules"):
        d = os.path.join(r, rel)
        if p == d or p.startswith(d + os.sep):
            return "our own receipts or rules"

    ## 4. Skip scanner health monitoring records
    if p.startswith(os.path.join(r, "data", "health") + os.sep) and base.startswith("scan_"):
        return "our own receipts or rules"

    return None


## -----------------------------------------------------------------------------
## SECTION 3: STAT SIGNATURE & DEBOUNCE STABILIZATION
## -----------------------------------------------------------------------------
def _sig(path):
    """Generate high-resolution stat signature: (size_in_bytes, mtime_in_nanoseconds).

    Parameters:
        path (str): Target file path.

    Returns:
        tuple[int, int]: (file_size_bytes, mtime_nanoseconds)
    """
    st = os.lstat(path)
    return st.st_size, int(st.st_mtime_ns)


def _stable(path, wait, sleeper):
    """Determine if a single file has completed writing by checking stat drift.

    Parameters:
        path (str): File path to verify.
        wait (float): Delay interval in seconds.
        sleeper (callable): Sleep function hook.

    Returns:
        bool: True if stat signature remained identical across the wait window.
    """
    try:
        a = _sig(path)
        if wait:
            sleeper(wait)
        return a == _sig(path)
    except OSError:
        return False


def _state_path(root):
    """Return path to host-specific deduplication cache file.

    Parameters:
        root (Path | str): Workspace root.

    Returns:
        Path: Path to scan_event_state.<host>.json
    """
    return Path(root) / "data" / "health" / ("scan_event_state.%s.json" % HOST)


def _load(path, default):
    """Safely load JSON file with automatic fallback on missing or corrupt files.

    Parameters:
        path (Path | str): Target JSON file.
        default (any): Value to return on read/parse error.

    Returns:
        Parsed JSON object or default value.
    """
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


## -----------------------------------------------------------------------------
## SECTION 4: INCIDENT FORMATTING & ALERT DISPATCH
## -----------------------------------------------------------------------------
def sentence(path, verdict, findings):
    """Format human-readable alert notification guidance for security operators.

    Reinforces non-destructive incident response: Never delete blindly.

    Parameters:
        path (str): Flagged file path.
        verdict (str): 'SUSPICIOUS' or 'INFECTED'.
        findings (list[dict]): Findings list from engine execution.

    Returns:
        str: Human-readable guidance message.
    """
    names = ", ".join(sorted({f.get("name", "?") for f in findings})[:4]) or "a scanner match"
    kind = "matched a virus signature" if verdict == "INFECTED" else "matched a suspicious-file rule"
    return (
        "%s: %s %s (%s). Do not open or run it. Nothing was moved or deleted; tell Ethan and see "
        "docs/SECURITY_TOOLS_RUNBOOK.md (A file got flagged)." % (verdict, path, kind, names)
    )


def write_alerts(root, new_alerts, now=None):
    """Atomically append new security incidents to rolling alert history log.

    Maintains the most recent `MAX_ALERTS` alerts sorted newest-first.

    Parameters:
        root (Path | str): Workspace root.
        new_alerts (list[dict]): Newly generated alert records.
        now (float | None): Epoch timestamp.

    Returns:
        str | None: Path to written alert file or None if no alerts.
    """
    if not new_alerts:
        return None
    p = Path(root) / "data" / "health" / ("scan_alerts.%s.json" % HOST)
    doc = _load(p, {})
    old = doc.get("alerts", []) if isinstance(doc, dict) else []
    alerts = (list(reversed(new_alerts)) + old)[:MAX_ALERTS]
    out = {
        "schema": "twu.scan_alerts.v1",
        "host": HOST,
        "updated": now or time.time(),
        "note": "Newest first. Nothing was moved; a person decides.",
        "alerts": alerts,
    }
    twu_scan.write_atomic(p, out)
    return str(p)


EXPAND_SKIP_DIRS = SKIP_PARTS + ("receipts", "rules", "archive", "scans", "yara_rules", "__pycache__", "node_modules")
EXPAND_SKIP_REL = ("data/health",)
LAST_PASS_KEY = "__last_pass__"


def load_last_pass(root):
    """Retrieve timestamp of last successful directory expansion pass.

    Parameters:
        root (Path | str): Repository root.

    Returns:
        float: Epoch timestamp of prior pass or 0.0.
    """
    v = _load(_state_path(root), {}).get(LAST_PASS_KEY)
    return float(v) if isinstance(v, (int, float)) else 0.0


def save_last_pass(root, ts):
    """Record timestamp of current directory expansion pass.

    Parameters:
        root (Path | str): Repository root.
        ts (float): Epoch timestamp to record.
    """
    p = _state_path(root)
    st = _load(p, {})
    st[LAST_PASS_KEY] = ts
    try:
        twu_scan.write_atomic(p, st)
    except OSError:
        pass


## -----------------------------------------------------------------------------
## SECTION 5: BOUNDED DIRECTORY EXPANSION FOR EVENT HOOKS
## -----------------------------------------------------------------------------
def expand_dirs(dirs, since_days=1.0, depth=4, max_files=2000, now=None, since_ts=0.0, root=None):
    """Expand directory trees into changed file candidates for batch event hooks.

    Educational Note: Generic filesystem event hooks (e.g. systemd `.path` or
    launchd `WatchPaths`) notify that *something* in a directory changed, but
    do not provide the specific list of modified file paths.
    This function performs a bounded depth-limited traversal, collecting files
    modified since the last successful pass timestamp.

    Parameters:
        dirs (list[str]): Directories to traverse.
        since_days (float): Maximum lookback window in days.
        depth (int): Maximum directory depth.
        max_files (int): Hard cap on collected files.
        now (float | None): Current epoch timestamp.
        since_ts (float): Minimum timestamp threshold from prior pass.
        root (Path | str | None): Repository root for skipping relative paths.

    Returns:
        list[str]: Candidate file paths matching modification criteria.
    """
    cutoff = max((now or time.time()) - since_days * 86400, since_ts)
    skip_rel = [os.path.abspath(os.path.join(str(root), r)) for r in EXPAND_SKIP_REL] if root else []
    out = []
    for d in dirs:
        base = os.path.abspath(d).rstrip(os.sep).count(os.sep)
        for r, ds, fs in os.walk(d, followlinks=False):
            if r.rstrip(os.sep).count(os.sep) - base >= depth:
                ds[:] = []
            ds[:] = [
                x for x in ds
                if x not in EXPAND_SKIP_DIRS
                and not any(os.path.join(os.path.abspath(r), x) == k for k in skip_rel)
                and not (os.path.abspath(r).endswith("/data") and x == "health")
            ]
            for f in fs:
                fp = os.path.join(r, f)
                try:
                    if not os.path.islink(fp) and os.lstat(fp).st_mtime >= cutoff and len(out) < max_files:
                        out.append(fp)
                except OSError:
                    pass
    return out


## -----------------------------------------------------------------------------
## SECTION 6: CORE EVENT PROCESSING PIPELINE
## -----------------------------------------------------------------------------
def scan_new(paths, root=REPO, scanner=None, max_bytes=DEFAULT_MAX_BYTES, wait=STABLE_SECONDS,
             sleeper=time.sleep, timeout=twu_scan.DEFAULT_TIMEOUT, **scan_kw):
    """Core event processing pipeline: filter, debounce, deduplicate, and scan.

    Educational Algorithm:
    1. Filter & Deduplicate Inputs: Eliminate duplicates and system control files.
    2. Shared Debounce Interval: Instead of waiting 2 seconds *per file* (which
       would take an hour for 2,000 files), collect pre-wait stat signatures
       for all candidate files, perform a SINGLE sleep(2.0), and compare.
    3. In-Flight Write Detection: If (size, mtime_ns) changed during the wait,
       the file is still being written; skip it and let the next event rescan.
    4. State Cache Comparison: If (size, mtime_ns) matches our persistent cache,
       the file hasn't changed since its last clean scan; skip it.
    5. Dual-Engine Execution: Run `twu_scan.scan()` on all confirmed candidates.
    6. Forensic Alerting & State Update: For any SUSPICIOUS or INFECTED file,
       generate an immutable alert record. Update deduplication cache for
       all successfully evaluated files.

    Parameters:
        paths (list[str]): Triggered file paths.
        root (Path | str): Workspace root.
        scanner (callable | None): Scanner function (defaults to twu_scan.scan).
        max_bytes (int): Upper bound on file size.
        wait (float): Debounce interval in seconds.
        sleeper (callable): Sleep implementation (for testing).
        timeout (int): Per-scan subprocess timeout.

    Returns:
        dict: {verdict, scanned, skipped, receipt, alerts_file}
    """
    scanner = scanner or twu_scan.scan
    root = Path(root)
    state_p = _state_path(root)
    state = _load(state_p, {})
    skipped, todo = [], []
    seen = set()
    pending = {}  ## Map of path -> (size, mtime_ns) before shared wait

    for raw in paths:
        p = os.path.abspath(raw)
        if p in seen:
            continue
        seen.add(p)
        why = skip_reason(p, root)
        if not why:
            try:
                st = os.lstat(p)
                if stat.S_ISDIR(st.st_mode):
                    why = "directory (the event hook passes files; a changed directory is rescanned by its files)"
                elif not stat.S_ISREG(st.st_mode):
                    why = "not a regular file"
                elif st.st_size > max_bytes:
                    todo.append(p)  ## Let twu_scan report COULD-NOT-SCAN for oversized files
                    continue
                else:
                    pending[p] = _sig(p)
            except OSError:
                why = "vanished"
        if why:
            skipped.append({"path": p, "why": why})

    ## Execute single batch stabilization delay for all pending files
    if pending and wait:
        sleeper(wait)

    for p, before in pending.items():
        try:
            after = _sig(p)
        except OSError:
            skipped.append({"path": p, "why": "vanished"})
            continue
        if after != before:
            skipped.append({
                "path": p,
                "why": "still being written (size or time changed in %ss); the next event rescans it" % wait,
            })
        elif state.get(p) == list(after):
            skipped.append({"path": p, "why": "unchanged since last scan"})
        else:
            todo.append(p)

    verdict, files, receipt, alerts = "CLEAN", [], None, []
    if todo:
        doc = scanner(todo, root=root, max_bytes=max_bytes, timeout=timeout, **scan_kw)
        verdict, files, receipt = doc["verdict"], doc["files"], doc.get("receipt")
        now = time.time()
        for f in files:
            if f["verdict"] in ("SUSPICIOUS", "INFECTED"):
                alerts.append({
                    "ts": now,
                    "path": f["path"],
                    "verdict": f["verdict"],
                    "sha256": f.get("sha256"),
                    "findings": f.get("findings", []),
                    "receipt": receipt,
                    "sentence": sentence(f["path"], f["verdict"], f.get("findings", [])),
                })
            ## Successfully scanned files are added to state; COULD-NOT-SCAN remains eligible for retry
            if f["verdict"] != "COULD-NOT-SCAN":
                try:
                    state[f["path"]] = list(_sig(f["path"]))
                except OSError:
                    pass

        ## Evict oldest state cache entries if size exceeds MAX_STATE limit
        if len(state) > MAX_STATE:
            for k in [k for k in state if k != LAST_PASS_KEY][:len(state) - MAX_STATE]:
                del state[k]
        try:
            twu_scan.write_atomic(state_p, state)
        except OSError:
            pass

    alert_file = write_alerts(root, alerts)
    return {
        "verdict": verdict,
        "scanned": files,
        "skipped": skipped,
        "receipt": receipt,
        "alerts_file": alert_file,
    }


## -----------------------------------------------------------------------------
## SECTION 7: LARGE ASSET SECURITY: GGUF MODEL HEADER PASS
## -----------------------------------------------------------------------------
def gguf_header_scan(path, scanner=None, nbytes=GGUF_HEADER_BYTES, root=REPO):
    """Scan the initial binary header of large GGUF AI model weights.

    Educational Concept: Memory-Safe Large File Inspection.
    LLM checkpoint files can be 10 GB to 70 GB. Attempting to scan the entire
    binary with regex or signature engines causes severe memory thrashing.
    However, attack vectors (such as embedded shell scripts, pickle bombs,
    or malicious metadata payloads) are located in the metadata header at
    the beginning of the file. By extracting and scanning only the first 16 MiB,
    we achieve fast heuristic security screening while maintaining a strict
    RAM ceiling.

    Parameters:
        path (str): Path to large model checkpoint.
        scanner (callable | None): Scanner function.
        nbytes (int): Number of header bytes to extract and scan.
        root (Path | str): Workspace root.

    Returns:
        dict: {path, verdict, bytes_scanned, file_bytes, partial, findings, note}
    """
    scanner = scanner or twu_scan.scan
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(nbytes)
    with tempfile.TemporaryDirectory(prefix="twugguf.") as td:
        tmp = os.path.join(td, "header." + os.path.basename(path))
        with open(tmp, "wb") as g:
            g.write(head)
        doc = scanner([tmp], root=root, write_receipt=False) if scanner is twu_scan.scan else scanner([tmp])
    v = doc["verdict"]
    return {
        "path": str(path),
        "verdict": v,
        "bytes_scanned": len(head),
        "file_bytes": size,
        "partial": size > len(head),
        "findings": [x for f in doc["files"] for x in f.get("findings", [])],
        "note": "header-only pass (first %d MiB); weights are not scanned" % (nbytes // (1 << 20)),
    }


## -----------------------------------------------------------------------------
## SECTION 8: REMOVABLE MEDIA (USB) CONTAINMENT
## -----------------------------------------------------------------------------
def list_volumes(base=None):
    """Discover mounted removable media partitions across Linux and macOS.

    Parameters:
        base (str | None): Base mount directory override.

    Returns:
        list[str]: Discovered removable media partition mount paths.
    """
    bases = [base] if base else ["/Volumes", "/media", "/run/media"]
    out = []
    for b in bases:
        if not os.path.isdir(b):
            continue
        for n in sorted(os.listdir(b)):
            p = os.path.join(b, n)
            if os.path.islink(p):
                continue  ## e.g. /Volumes/Macintosh HD is a symlink to root
            if os.path.isdir(p) and (base or b != "/run/media"):
                out.append(p)
            elif os.path.isdir(p):  ## Linux multi-user mount: /run/media/<user>/<label>
                out += [
                    os.path.join(p, m)
                    for m in sorted(os.listdir(p))
                    if os.path.isdir(os.path.join(p, m)) and not os.path.islink(os.path.join(p, m))
                ]
    return out


def usb_scan(volumes=None, root=REPO, scanner=None, depth=USB_DEPTH, max_files=USB_MAX_FILES, max_bytes=DEFAULT_MAX_BYTES):
    """Execute depth-capped, file-count-capped scan of removable storage devices.

    Enforces strict operational boundaries to prevent Denial of Service:
    - Max recursion depth: depth=3
    - Max files scanned: max_files=5000
    - Autorun detection: Explicitly flags Windows autorun files.

    Parameters:
        volumes (list[str] | None): Specific volume mount paths.
        root (Path | str): Workspace root.
        scanner (callable | None): Scanner function.
        depth (int): Max directory depth.
        max_files (int): Max total files.
        max_bytes (int): Upper bound on file size.

    Returns:
        dict: {volumes, verdict, files, warnings, too_deep, over_cap, receipt, alerts_file}
    """
    scanner = scanner or twu_scan.scan
    vols = list(volumes) if volumes else list_volumes()
    files, warnings, too_deep, over_cap = [], [], [], []

    for v in vols:
        base_depth = v.rstrip(os.sep).count(os.sep)
        for r, ds, fs in os.walk(v, followlinks=False):
            d = r.rstrip(os.sep).count(os.sep) - base_depth
            ds[:] = [x for x in sorted(ds) if not os.path.islink(os.path.join(r, x))]
            if d >= depth:
                if ds:
                    too_deep.extend(os.path.join(r, x) for x in ds)
                ds[:] = []
            for f in sorted(fs):
                fp = os.path.join(r, f)
                if f.lower() == "autorun.inf":
                    warnings.append("autorun.inf on %s (Windows auto-run file; never open it)" % v)
                if os.path.islink(fp):
                    continue
                if len(files) >= max_files:
                    over_cap.append(fp)
                else:
                    files.append(fp)

    verdict, results, receipt = "CLEAN", [], None
    if files:
        doc = scanner(files, root=root, max_bytes=max_bytes)
        verdict, results, receipt = doc["verdict"], doc["files"], doc.get("receipt")
    elif not vols:
        verdict = "CLEAN"

    if too_deep or over_cap:
        verdict = _worse(verdict, "COULD-NOT-SCAN")

    alerts = [
        {
            "ts": time.time(),
            "path": f["path"],
            "verdict": f["verdict"],
            "sha256": f.get("sha256"),
            "findings": f.get("findings", []),
            "receipt": receipt,
            "sentence": sentence(f["path"], f["verdict"], f.get("findings", [])),
        }
        for f in results
        if f["verdict"] in ("SUSPICIOUS", "INFECTED")
    ]
    alert_file = write_alerts(root, alerts)
    return {
        "volumes": vols,
        "verdict": verdict,
        "files": results,
        "warnings": warnings,
        "too_deep": too_deep,
        "over_cap": over_cap,
        "receipt": receipt,
        "alerts_file": alert_file,
    }


def _render(res, label):
    """Format event scan or USB scan results for CLI output.

    Parameters:
        res (dict): Result dictionary from scan_new or usb_scan.
        label (str): Subcommand label.

    Returns:
        str: Human-readable terminal string.
    """
    lines = ["VERDICT: %s" % res["verdict"]]
    for f in res.get("scanned", res.get("files", [])):
        lines.append("%s: %s" % (f["verdict"], f["path"]))
    for s in res.get("skipped", []):
        lines.append("skipped: %s (%s)" % (s["path"], s["why"]))
    for w in res.get("warnings", []):
        lines.append("WARNING: " + w)
    if res.get("too_deep"):
        lines.append("NOT scanned (deeper than %d levels): %d folder(s), e.g. %s" % (
            USB_DEPTH, len(res["too_deep"]), res["too_deep"][0]
        ))
    if res.get("over_cap"):
        lines.append("NOT scanned (over %d-file cap): %d file(s)" % (USB_MAX_FILES, len(res["over_cap"])))
    if res.get("alerts_file"):
        lines.append("alert written: " + res["alerts_file"])
    return "\n".join(lines)


## -----------------------------------------------------------------------------
## SECTION 9: CLI ENTRYPOINT & DISPATCHER
## -----------------------------------------------------------------------------
def main(argv=None):
    """CLI entrypoint for event-driven scans and USB removable device scans.

    Parameters:
        argv (list[str] | None): Argument list override.

    Returns:
        int: POSIX exit status code.
    """
    ap = argparse.ArgumentParser(prog="twu_scan_event.py", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    ## Subcommand: scan-new
    a = sub.add_parser("scan-new", help="Process new or modified files triggered by event hooks")
    a.add_argument("paths", nargs="*", help="File paths that triggered the event")
    a.add_argument("--dir", action="append", default=[], help="Directory to expand changed files from")
    a.add_argument("--since-days", type=float, default=1.0, help="Lookback window in days")
    a.add_argument("--max-mb", type=int, default=DEFAULT_MAX_BYTES >> 20, help="Per-file size cap in MiB")
    a.add_argument("--json", action="store_true", help="Output JSON result")
    a.add_argument("--root", default=str(REPO), help="Workspace root directory")
    a.add_argument("--no-wait", action="store_true", help="Bypass debounce delay (testing)")

    ## Subcommand: usb
    u = sub.add_parser("usb", help="Inspect and scan attached external USB volumes")
    u.add_argument("volumes", nargs="*", help="Explicit mount paths to scan")
    u.add_argument("--depth", type=int, default=USB_DEPTH, help="Maximum directory depth")
    u.add_argument("--json", action="store_true", help="Output JSON result")

    ns = ap.parse_args(argv)
    t0 = time.time()

    if ns.cmd == "scan-new":
        root = Path(ns.root)
        print("%s scan-new start dirs=%s since_last_pass=%s" % (
            _stamp(t0),
            ",".join(ns.dir) or "-",
            "yes" if load_last_pass(root) else "no (first run, last %g day)" % ns.since_days,
        ), flush=True)

        paths = list(ns.paths) + expand_dirs(ns.dir, ns.since_days, since_ts=load_last_pass(root), root=root)
        if not paths:
            save_last_pass(root, t0)
            print("%s scan-new done files=0 verdict=CLEAN (nothing new)" % _stamp(), flush=True)
            return 0

        res = scan_new(paths, root=root, max_bytes=ns.max_mb << 20, wait=0 if ns.no_wait else STABLE_SECONDS)
        if res["verdict"] != "COULD-NOT-SCAN":
            save_last_pass(root, t0)

        n = {}
        for f in res["scanned"]:
            n[f["verdict"]] = n.get(f["verdict"], 0) + 1

        print("%s scan-new done candidates=%d files=%d skipped=%d verdict=%s %s%s" % (
            _stamp(), len(paths), len(res["scanned"]), len(res["skipped"]), res["verdict"],
            " ".join("%s=%d" % kv for kv in sorted(n.items())),
            " alerts=" + res["alerts_file"] if res.get("alerts_file") else "",
        ), flush=True)
    else:
        res = usb_scan(ns.volumes, depth=ns.depth)

    print(json.dumps(res, indent=1) if ns.json else _render(res, ns.cmd))
    return twu_scan.exit_code(res["verdict"])


if __name__ == "__main__":
    sys.exit(main())
