#!/usr/bin/env python3
## ==============================================================================
## TWU THREAT DEFENSE ENGINE: DUAL-ENGINE MALWARE SCANNER (YARA + CLAMAV)
## ==============================================================================
## Author: Ethan REDACTED <ethan@REDACTED>
## Organization: TWU LLC
## Copyright: (c) 2026 Ethan REDACTED, TWU LLC
## License: MIT License 2026
##
## EDUCATIONAL ARCHITECTURE: DUAL-ENGINE THREAT DETECTION PATTERN
## ------------------------------------------------------------------------------
## Modern threat detection requires complementary scanning paradigms. Relying on
## a single engine leaves dangerous blind spots:
##
## 1. ClamAV (Signature-Based Detection):
##    - Strengths: Rapid matching of known malware families, exact file hashes,
##      trojans, worms, and established virus signatures.
##    - Limitations: Ineffective against novel zero-day payloads, polymorphic scripts,
##      or living-off-the-land techniques that don't match existing signature databases.
##    - Classification: A match here indicates confirmed malware -> INFECTED.
##
## 2. YARA (Heuristic & Pattern-Based Detection):
##    - Strengths: Identifying behavioral patterns, webshell syntax, reverse shell strings,
##      cryptominer artifacts, obfuscated eval routines, and structural anomalies.
##    - Limitations: Higher risk of false positives on legitimate developer tools,
##      system utilities, or test fixtures.
##    - Classification: A match here flags behavioral suspicion -> SUSPICIOUS.
##
## 3. Strict Fail-Closed Decision Hierarchy:
##    - CLEAN: Both engines executed successfully with zero signature or rule matches.
##    - SUSPICIOUS: YARA matched heuristic patterns.
##    - INFECTED: ClamAV matched a confirmed virus/malware signature.
##    - COULD-NOT-SCAN: An engine failed, timed out, was uninstalled, had permission
##      denied, or a file was oversized / non-regular. Crucially, UNCERTAINTY IS
##      NEVER REPORTED AS CLEAN.
##
## 4. Execution Isolation & Anti-Tamper Design:
##    - Scanned files are NEVER executed, imported, or dynamically evaluated.
##    - Target paths are staged as anonymous symlinks (`f0000000`, `f0000001`)
##      inside a private 0700 temporary directory. This prevents command injection,
##      filename manipulation, or shell escape attacks against native engine CLIs.
##    - Cryptographic receipts (SHA-256) are generated atomically for forensic audit.
##
## Commands:
##   scan PATH... [--max-mb N] [--timeout S] [--json]
##         Execute dual-engine scan. Exit 0 = CLEAN, 1 = SUSPICIOUS/INFECTED, 2 = COULD-NOT-SCAN.
##   status [--json]
##         Display health, engine versions, signature database age, and rule counts.
##   update-signatures [--approve]
##         Propose or apply ClamAV signature database refresh via freshclam.
##   update-rules
##         Display instructions for refreshing vetted YARA rules from pinned commits.
## ==============================================================================

"""twu_scan: Dual-Engine Threat Defense Scanner (YARA Heuristics + ClamAV Signatures)."""

## -----------------------------------------------------------------------------
## SECTION 1: IMPORTS & RUNTIME ENVIRONMENT INITIALIZATION
## -----------------------------------------------------------------------------
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

## Base directory setup: Anchors to repository root
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))

## System hostname identification for multi-node audit provenance
HOST = platform.node().split(".")[0] or "host"

## -----------------------------------------------------------------------------
## SECTION 2: THREAT CLASSIFICATION HIERARCHY & OPERATIONAL THRESHOLDS
## -----------------------------------------------------------------------------
## Severity ranking: Higher numerical value indicates higher threat priority.
## Used in synthesis to compute overall scan verdict across multiple targets.
VERDICT_RANK = {
    "CLEAN": 0,           ## Safe: Both engines ran, zero detections
    "COULD-NOT-SCAN": 1,  ## Inconclusive: Errors, timeouts, or permission limits
    "SUSPICIOUS": 2,      ## Anomaly: YARA heuristic or behavioral pattern match
    "INFECTED": 3,        ## Confirmed Threat: ClamAV virus signature match
}

## Standard POSIX exit status codes for CLI automation and CI/CD pipelines
EXIT = {
    "CLEAN": 0,           ## Pipeline succeeds: All scanned files verified clean
    "SUSPICIOUS": 1,      ## Pipeline fails: Security warning, heuristic anomaly
    "INFECTED": 1,        ## Pipeline fails: Critical threat detected
    "COULD-NOT-SCAN": 2,  ## Pipeline fails: Scan failure, timeout, or misconfiguration
}

## Operational guardrails and thresholds
DEFAULT_MAX_BYTES = 200 * 1024 * 1024  ## 200 MiB per-file cap to prevent memory exhaustion
DEFAULT_TIMEOUT = 300                  ## 5-minute watchdog timer per scan invocation
SIG_MAX_AGE_DAYS = 7                   ## Max acceptable age for ClamAV signature database
RULES_MAX_AGE_DAYS = 90                ## Max recommended age for vetted YARA rules
TOOL_NAMES = ("yara", "clamscan", "freshclam")


def exit_code(verdict):
    """Translate scan verdict string into standard POSIX exit status code.

    Parameters:
        verdict (str): 'CLEAN', 'SUSPICIOUS', 'INFECTED', or 'COULD-NOT-SCAN'.

    Returns:
        int: 0 for CLEAN, 1 for SUSPICIOUS/INFECTED, 2 for COULD-NOT-SCAN.
    """
    return EXIT.get(verdict, 3)


## -----------------------------------------------------------------------------
## SECTION 3: EXTERNAL BINARY DISCOVERY & UTILITY FUNCTIONS
## -----------------------------------------------------------------------------
def _which(cmd):
    """Locate tool executable with graceful fallback to ~/.local/bin.

    Educational Note: In locked-down systems, custom or sandboxed security
    tools often reside in user-isolated directories rather than /usr/bin.

    Parameters:
        cmd (str): Executable name to discover.

    Returns:
        str | None: Absolute path to executable if runnable, else None.
    """
    try:
        import twu_toolparity
        return twu_toolparity.which_with_local(cmd)
    except Exception:
        p = shutil.which(cmd)
        if p:
            return p
        c = Path.home() / ".local" / "bin" / cmd
        return str(c) if c.is_file() and os.access(str(c), os.X_OK) else None


def find_tools():
    """Discover paths for required external security binaries.

    Returns:
        dict[str, str | None]: Map of tool name to discovered binary path.
    """
    return {n: _which(n) for n in TOOL_NAMES}


def default_db_dir():
    """Locate platform-specific default ClamAV signature database path.

    Educational Note: macOS ClamAV installations (Homebrew) or user-space
    setups store databases in ~/.local/share/clamav, whereas Linux distribution
    packages default to system-wide /var/lib/clamav.

    Returns:
        Path: Target directory where CVD/CLD signature databases reside.
    """
    user = Path.home() / ".local" / "share" / "clamav"
    if sys.platform == "darwin" or user.is_dir():
        return user
    return Path("/var/lib/clamav")


def _run(argv, timeout, cwd=None):
    """Execute external subprocess with strict timeout and output capture.

    Parameters:
        argv (list[str]): Command-line arguments.
        timeout (int): Timeout in seconds before subprocess aborts.
        cwd (str | None): Working directory for the process.

    Returns:
        tuple[int, str, str]: (returncode, stdout_text, stderr_text)
    """
    r = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout, cwd=cwd)
    return r.returncode, (r.stdout or ""), (r.stderr or "")


def _default_runner(argv, timeout):
    """Standard execution runner returning combined output.

    Parameters:
        argv (list[str]): Command arguments.
        timeout (int): Execution timeout.

    Returns:
        tuple[int, str]: (returncode, combined_stdout_and_stderr)
    """
    rc, out, err = _run(argv, timeout)
    return rc, out + err


def sha256(path):
    """Calculate streaming cryptographic SHA-256 checksum.

    Parameters:
        path (Path | str): File path to hash.

    Returns:
        str: 64-character hexadecimal SHA-256 digest.
    """
    h = hashlib.sha256()
    with open(str(path), "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


## -----------------------------------------------------------------------------
## SECTION 4: ATOMIC RECEIPTS & WRITE-ONCE FORENSIC PRESERVATION
## -----------------------------------------------------------------------------
def write_atomic(path, doc, unique=False):
    """Write JSON document atomically to prevent race conditions or corrupt reads.

    Parameters:
        path (Path | str): Target file path.
        doc (dict): JSON-serializable dictionary.
        unique (bool): If True, uses link() to guarantee an existing receipt is never overwritten.

    Returns:
        Path: Actual path where the file was written.

    Educational Pattern: Atomic Renaming & Hard-Link Write-Once Audit.
    Writing to a sibling temporary file and using os.replace() guarantees that
    readers never see partially written files. When unique=True, using os.link()
    ensures write-once immutability for forensic records: if the target filename
    already exists, an incrementing index is appended until an unused slot is found.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.write("\n")
        if not unique:
            os.replace(tmp, str(path))
            return path
        n = 0
        while True:
            final = path if n == 0 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
            try:
                os.link(tmp, str(final))  ## Fails atomically if file exists
                return final
            except FileExistsError:
                n += 1
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


## -----------------------------------------------------------------------------
## SECTION 5: ENGINE HEALTH & STATUS INSPECTION
## -----------------------------------------------------------------------------
def tool_version(path, timeout=15):
    """Extract semantic version string from tool binary via `--version` flag.

    Parameters:
        path (str | None): Tool binary path.
        timeout (int): Timeout in seconds.

    Returns:
        str | None: Extracted version number or None.
    """
    if not path:
        return None
    try:
        rc, out, err = _run([path, "--version"], timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = out + err
    m = re.search(r"ClamAV\s+(\d+(?:\.\d+)*)", text) or re.search(r"(\d+\.\d+(?:\.\d+)*)", text)
    return m.group(1) if m else None


def signature_info(db_dir, now=None):
    """Inspect ClamAV signature database age and freshness.

    Parameters:
        db_dir (Path | str | None): Path to ClamAV signature database directory.
        now (float | None): Current epoch timestamp for age calculation.

    Returns:
        dict: {dir, present, age_days, fresh}
    """
    now = now if now is not None else time.time()
    db = Path(db_dir) if db_dir else None
    newest = None
    if db and db.is_dir():
        for f in db.iterdir():
            ## ClamAV database files have extensions .cvd (official), .cld (local), .cud (uncompressed)
            if f.suffix in (".cvd", ".cld", ".cud") and f.is_file():
                newest = max(newest or 0, f.stat().st_mtime)
    if newest is None:
        return {"dir": str(db) if db else None, "present": False, "age_days": None, "fresh": False}
    age = (now - newest) / 86400.0
    return {"dir": str(db), "present": True, "age_days": round(age, 2), "fresh": age <= SIG_MAX_AGE_DAYS}


def rules_info(rules_dir, now=None, check_files=True):
    """Inspect YARA ruleset metadata, compiler readiness, and SHA-256 integrity.

    Parameters:
        rules_dir (Path | str): Path to directory holding vetted YARA rules.
        now (float | None): Current epoch timestamp override.
        check_files (bool): Whether to invoke `twu_yara_vet.verify()` hash check.

    Returns:
        dict: Metadata dictionary including rule_count, age_days, problems, and ok flag.
    """
    now = now if now is not None else time.time()
    rd = Path(rules_dir)
    info = {"dir": str(rd), "rule_count": 0, "files": 0, "built": None, "age_days": None, "problems": [], "ok": False}
    try:
        man = json.loads((rd / "MANIFEST.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        info["problems"].append("MANIFEST.json unreadable: %s" % e)
        return info
    info["rule_count"] = int(man.get("rule_count", 0))
    info["files"] = len(man.get("files", []))
    info["built"] = man.get("built")
    if man.get("built_epoch"):
        info["age_days"] = round((now - man["built_epoch"]) / 86400.0, 2)
    if check_files:
        try:
            import twu_yara_vet
            info["problems"] = twu_yara_vet.verify(rd, compile_index=False)
        except Exception as e:
            info["problems"].append("integrity check failed: %s" % e)
    if not (rd / "index.yar").is_file():
        info["problems"].append("index.yar missing")
    info["ok"] = not info["problems"] and info["rule_count"] > 0
    return info


## -----------------------------------------------------------------------------
## SECTION 6: EXCLUSIONS & PINNED TEST FIXTURES
## -----------------------------------------------------------------------------
def load_exclusions(rules_dir):
    """Load list of false-positive rule names explicitly suppressed in EXCLUSIONS.json.

    Parameters:
        rules_dir (Path | str): Directory containing EXCLUSIONS.json.

    Returns:
        set[str]: Set of rule identifiers to suppress during scanning.
    """
    try:
        d = json.loads((Path(rules_dir) / "EXCLUSIONS.json").read_text(encoding="utf-8"))
        return set(e["rule"] for e in d.get("excluded", []))
    except (OSError, ValueError, KeyError, TypeError):
        return set()


def load_fixtures(rules_dir):
    """Load map of {repo-relative path: sha256} for intentional test attack fixtures.

    Parameters:
        rules_dir (Path | str): Directory containing EXCLUSIONS.json.

    Returns:
        dict[str, str]: Mapping of repository-relative path to lowercase SHA-256 digest.
    """
    try:
        d = json.loads((Path(rules_dir) / "EXCLUSIONS.json").read_text(encoding="utf-8"))
        out = {}
        for e in d.get("fixtures", []):
            if isinstance(e, dict) and isinstance(e.get("path"), str) and isinstance(e.get("sha256"), str) and e["sha256"]:
                out[e["path"]] = e["sha256"].lower()
        return out
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


def _pinned_fixture(path, sha, root, fixtures):
    """Verify if a flagged file is an explicitly pinned test fixture with matching hash.

    Educational Concept: Safe Security Test Suites.
    Testing antivirus engines requires files with malicious patterns (e.g. EICAR or
    webshell snippets). To prevent scanners from breaking developer builds while
    preventing real malware from bypassing detection, fixtures are pinned BOTH by
    relative path AND exact cryptographic SHA-256 digest. If an attacker modifies
    a fixture file, its SHA-256 changes and the exemption is revoked.

    Parameters:
        path (str): Real filesystem path of candidate file.
        sha (str | None): Computed SHA-256 hash of candidate file.
        root (Path | str): Workspace root.
        fixtures (dict[str, str]): Pinned fixtures map {path: sha256}.

    Returns:
        bool: True only if path is inside repository and matches pinned SHA-256.
    """
    try:
        rel = os.path.relpath(os.path.realpath(path), os.path.realpath(root))
    except ValueError:
        return False
    if rel.startswith("..") or os.path.isabs(rel):
        return False
    return bool(sha) and fixtures.get(rel.replace(os.sep, "/")) == sha


def status(root=REPO, tools=None, db_dir=None, rules_dir=None, now=None):
    """Compile comprehensive system health and engine readiness report.

    Parameters:
        root (Path | str): Repository root directory.
        tools (dict | None): Tool binary dictionary.
        db_dir (Path | str | None): ClamAV database directory.
        rules_dir (Path | str | None): Vetted YARA rules directory.
        now (float | None): Epoch timestamp override.

    Returns:
        dict: Complete scanner readiness diagnostic structure.
    """
    root = Path(root)
    tools = tools if tools is not None else find_tools()
    rules_dir = Path(rules_dir) if rules_dir else root / "data" / "yara_rules"
    now = now if now is not None else time.time()
    tinfo = {n: {"path": tools.get(n), "version": tool_version(tools.get(n))} for n in TOOL_NAMES}
    sig = signature_info(db_dir if db_dir is not None else default_db_dir(), now)
    rules = rules_info(rules_dir, now)
    problems = []
    for n in ("yara", "clamscan"):
        if not tinfo[n]["path"]:
            problems.append("%s is not installed" % n)
    if not rules["ok"]:
        problems.append("YARA rules not usable: %s" % ("; ".join(rules["problems"]) or "no rules"))
    if not sig["present"]:
        problems.append("no ClamAV signature database found")
    elif not sig["fresh"]:
        problems.append("ClamAV signatures are %.0f days old (limit %d)" % (sig["age_days"], SIG_MAX_AGE_DAYS))
    return {
        "host": HOST,
        "tools": tinfo,
        "rules": rules,
        "signatures": sig,
        "active": not problems,
        "problems": problems,
        "ts": now,
    }


## -----------------------------------------------------------------------------
## SECTION 7: SIGNATURE & RULE UPDATE PROPOSALS
## -----------------------------------------------------------------------------
def _decide(action, root, decider=None):
    """Policy decision hook: determines if an update should be automated or proposed.

    Parameters:
        action (str): Identifier of the maintenance action.
        root (Path | str): Repository root.
        decider (callable | None): Policy decider override.

    Returns:
        str: Policy outcome ('PROPOSE', 'NEVER', 'ALLOW').
    """
    try:
        if decider:
            return decider(action)
        import twu_autonomy
        return twu_autonomy.decide(action, Path(root), HOST)
    except Exception:
        return "PROPOSE"


def update_items(st, root, decider=None):
    """Audit engine status and construct actionable maintenance proposals.

    Parameters:
        st (dict): System status structure from status().
        root (Path | str): Repository root.
        decider (callable | None): Policy decider hook.

    Returns:
        list[dict]: List of update proposals.
    """
    items = []
    sig, rules = st["signatures"], st["rules"]
    if st["tools"]["clamscan"]["path"] and (not sig["present"] or not sig["fresh"]):
        why = "ClamAV signatures are %s" % (
            "missing" if not sig["present"] else "%.0f days old (limit %d)" % (sig["age_days"], SIG_MAX_AGE_DAYS)
        )
        items.append({
            "id": "clamav-signatures",
            "action": "update_clamav_signatures",
            "why": why,
            "class": _decide("update_clamav_signatures", root, decider),
            "approve": "python3 scripts/twu_scan.py update-signatures --approve",
        })
    if rules["age_days"] is not None and rules["age_days"] > RULES_MAX_AGE_DAYS:
        items.append({
            "id": "yara-rules",
            "action": "update_yara_rules",
            "why": "vetted YARA rules are %.0f days old (limit %d)" % (rules["age_days"], RULES_MAX_AGE_DAYS),
            "class": _decide("update_yara_rules", root, decider),
            "approve": "see data/yara_rules/README.md (pinned-commit refresh)",
        })
    return items


def write_updates(root, items, now=None):
    """Persist structured update proposals to health directory.

    Parameters:
        root (Path | str): Workspace root.
        items (list[dict]): Update proposal items.
        now (float | None): Current epoch timestamp.
    """
    doc = {
        "host": HOST,
        "ts": now if now is not None else time.time(),
        "items": items,
        "note": "PROPOSE-class: nothing is fetched until Ethan approves.",
    }
    try:
        write_atomic(Path(root) / "data" / "health" / ("scan_updates.%s.json" % HOST), doc)
    except OSError:
        pass


def update_signatures(root=REPO, approve=False, tools=None, decider=None, runner=None, timeout=900):
    """Execute freshclam update when explicitly authorized by operator.

    Parameters:
        root (Path | str): Repository root.
        approve (bool): Operator confirmation flag.
        tools (dict | None): Tool binaries map.
        decider (callable | None): Policy decision hook.
        runner (callable | None): Subprocess execution runner hook.
        timeout (int): Download timeout in seconds.

    Returns:
        dict: Status result dictionary.
    """
    tools = tools if tools is not None else find_tools()
    cmd = "python3 scripts/twu_scan.py update-signatures --approve"
    cls = _decide("update_clamav_signatures", root, decider)
    if cls == "NEVER":
        return {"status": "refused", "detail": "policy says NEVER"}
    if not approve:
        return {"status": "proposal", "detail": "Update available. Approve with: " + cmd}
    fc = tools.get("freshclam")
    if not fc:
        return {"status": "missing", "detail": "freshclam is not installed"}
    runner = runner or _default_runner
    try:
        rc, out = runner([fc], timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"status": "failed", "detail": str(e)}
    if rc == 0:
        return {"status": "updated", "detail": (out or "").strip()[-300:]}
    hint = "" if sys.platform == "darwin" else " On Linux the system database needs: sudo freshclam"
    return {"status": "failed", "detail": ((out or "").strip()[-300:] + hint)}


## -----------------------------------------------------------------------------
## SECTION 8: TARGET FILE COLLECTION & FILTERING
## -----------------------------------------------------------------------------
def _collect(paths, max_bytes):
    """Filter, stat, and collect candidate regular files for scanning.

    Educational Safety Checks:
    1. Symlink Rejection: Symlinks at the top level are flagged and not followed.
       Nested symlinks are skipped during directory traversal. This mitigates
       symlink race attacks (TOCTOU) and path traversal outside target roots.
    2. File Type Constraints: Sockets, FIFOs, device nodes, and pipes are skipped.
    3. Memory / DoS Guardrails: Files exceeding `max_bytes` are rejected with
       a skip message, preventing scanners from running out of memory on large files.

    Parameters:
        paths (list[str]): List of files or directories to inspect.
        max_bytes (int): Upper bound on file size.

    Returns:
        list[dict]: Collected file candidate records.
    """
    entries = []

    def add(p, top):
        try:
            st = os.lstat(p)
        except OSError as e:
            entries.append({"path": p, "skip": "cannot stat: %s" % e.strerror})
            return
        if stat.S_ISLNK(st.st_mode):
            if top:
                entries.append({"path": p, "skip": "is a symlink (not followed; scan the real file)"})
            return
        if not stat.S_ISREG(st.st_mode):
            if top:
                entries.append({"path": p, "skip": "not a regular file"})
            return
        if st.st_size > max_bytes:
            entries.append({
                "path": p,
                "skip": "file is larger than the %d MB cap (%d bytes)" % (max_bytes // (1 << 20), st.st_size),
            })
            return
        entries.append({"path": p, "skip": None, "size": st.st_size})

    for raw in paths:
        p = os.path.abspath(raw)
        if os.path.isdir(p) and not os.path.islink(p):
            for r, ds, fs in os.walk(p, followlinks=False):
                for f in sorted(fs):
                    add(os.path.join(r, f), False)
        else:
            add(p, True)
    return entries


ALIAS_RE = re.compile(r"\bf\d{7}\b")


def _file_errors(text, engine):
    """Parse engine error logs to map failure diagnostics back to specific file aliases.

    Parameters:
        text (str): Subprocess stdout/stderr log output.
        engine (str): Name of reporting engine ('ClamAV' or 'YARA').

    Returns:
        dict[str, str]: Map of alias identifier to human-readable error description.
    """
    out = {}
    for line in text.splitlines():
        if not re.search(r"error|denied|can't|cannot|could not|unable|no such", line, re.I):
            continue
        m = ALIAS_RE.search(line)
        if m:
            out[m.group(0)] = "%s could not read this file: %s" % (
                engine,
                re.sub(r"^.*?" + m.group(0) + r"\S*:?\s*", "", line).replace(" ERROR", "").strip()[:100] or "read error",
            )
    return out


## -----------------------------------------------------------------------------
## SECTION 9: ENGINE DISPATCHERS (CLAMAV & YARA)
## -----------------------------------------------------------------------------
def _engine_clam(clam, aliases, lst, timeout):
    """Invoke ClamAV engine on staged file list.

    Parameters:
        clam (str): Path to clamscan executable.
        aliases (dict): Map of alias string to file candidate structure.
        lst (str): Path to staged text file containing list of target paths.
        timeout (int): Execution timeout in seconds.

    Returns:
        tuple[dict, str | None, dict]: (findings, engine_error, file_errors)
        - findings: {alias: [signature_name, ...]}
        - engine_error: Global error message if engine failed or timed out
        - file_errors: {alias: error_message} for per-file read failures
    """
    argv = [clam, "--no-summary", "--follow-file-symlinks=2", "-f", lst]
    try:
        rc, out, err = _run(argv, timeout, cwd=os.path.dirname(lst))
    except subprocess.TimeoutExpired:
        return {}, "ClamAV ran out of time (%ds)" % timeout, {}
    except OSError as e:
        return {}, "ClamAV could not start: %s" % e, {}

    found = {}
    for line in out.splitlines():
        if line.endswith(" FOUND"):
            path, _, sig = line[:-6].rpartition(": ")
            found.setdefault(os.path.basename(path), []).append(sig)

    ferr = _file_errors(out + "\n" + err, "ClamAV")
    ## ClamAV returns 0 for clean, 1 for virus found. Any other exit code is an engine error.
    if rc not in (0, 1) and not ferr:
        return found, "ClamAV error (exit %d): %s" % (
            rc, ((err or out).strip().splitlines() or ["no detail"])[-1][:160]
        ), {}
    return found, None, ferr


def _engine_yara(yara, index, scandir, excl, timeout):
    """Invoke YARA engine against anonymous symlink directory.

    Parameters:
        yara (str): Path to yara executable.
        index (Path): Path to vetted index.yar.
        scandir (str): Path to directory holding anonymous symlinks.
        excl (set[str]): Excluded rule identifiers to ignore.
        timeout (int): Execution timeout in seconds.

    Returns:
        tuple[dict, str | None, dict]: (findings, engine_error, file_errors)
        - findings: {alias: [rule_name, ...]}
        - engine_error: Global error message if engine failed or timed out
        - file_errors: {alias: error_message}
    """
    argv = [yara, "-r", str(index), scandir]
    try:
        rc, out, err = _run(argv, timeout, cwd=scandir)
    except subprocess.TimeoutExpired:
        return {}, "YARA ran out of time (%ds)" % timeout, {}
    except OSError as e:
        return {}, "YARA could not start: %s" % e, {}

    found = {}
    for line in out.splitlines():
        rule, _, path = line.partition(" ")
        if rule and path and rule not in excl:
            found.setdefault(os.path.basename(path), []).append(rule)

    ferr = _file_errors(err, "YARA")
    ## YARA returns 0 on clean/success. Any non-zero exit without specific file error is an engine fault.
    if rc != 0 and not ferr:
        return found, "YARA error (exit %d): %s" % (
            rc, ((err or out).strip().splitlines() or ["no detail"])[-1][:160]
        ), {}
    return found, None, ferr


## -----------------------------------------------------------------------------
## SECTION 10: DUAL-ENGINE SCAN ORCHESTRATION & VERDICT SYNTHESIS
## -----------------------------------------------------------------------------
def scan(paths, root=REPO, tools=None, rules_dir=None, db_dir=None, max_bytes=DEFAULT_MAX_BYTES,
         timeout=DEFAULT_TIMEOUT, write_receipt=True, decider=None, now=None, engines=("yara", "clamav")):
    """Execute complete dual-engine scanning cycle across provided file paths.

    Parameters:
        paths: Iterable of file and/or directory paths to scan
        root: Workspace repository root
        tools: Tool dictionary from find_tools()
        rules_dir: Path to directory containing vetted YARA rules
        db_dir: Path to ClamAV signature database directory
        max_bytes: Per-file byte cap before reporting COULD-NOT-SCAN
        timeout: Subprocess timeout in seconds
        write_receipt: If True, writes immutable JSON receipt under data/health/scans/
        decider: Autonomous decision policy function
        now: Timestamp override for reproducible testing
        engines: Tuple of engine identifiers to run ('yara', 'clamav')

    Educational Flow:
    1. Pre-Flight Validation: Verify tool presence, signature age, and rule health.
    2. Candidate Collection: Walk paths, enforce file caps, reject symlinks.
    3. Anonymous Symlink Staging Sandbox: Create temporary directory (mode 0700) with
       numbered symlinks (`f0000000`, `f0000001`). This completely decouples
       engine command parsing from arbitrary user filenames, neutralizing command
       injection and path manipulation attacks.
    4. Parallel Engine Execution: Execute ClamAV and YARA against staged targets.
    5. Pinned Test Fixture Handling: Suppress YARA-only hits on verified fixtures
       that match both repository path AND cryptographic SHA-256 digest.
    6. Fail-Closed Verdict Synthesis:
       - ClamAV detection -> INFECTED
       - YARA detection -> SUSPICIOUS
       - Any engine/stat error -> COULD-NOT-SCAN
       - Zero errors, zero hits -> CLEAN
    7. Atomic Receipt Persistence: Calculate SHA-256 digest of input set and
       commit immutable JSON audit record to disk.
    """
    root = Path(root)
    now = now if now is not None else time.time()
    tools = tools if tools is not None else find_tools()
    rules_dir = Path(rules_dir) if rules_dir else root / "data" / "yara_rules"
    st = status(root, tools, db_dir, rules_dir, now)
    notes, reasons = [], []

    ## Step 1: Collect and validate candidate target files
    entries = _collect(list(paths), max_bytes)
    if not entries:
        reasons.append("nothing to scan: no paths given or nothing found")
    scannable = [e for e in entries if not e["skip"]]
    for e in entries:
        e["findings"], e["errors"] = [], []
        if e["skip"]:
            e["errors"].append(e["skip"])

    engine_err = {}
    if scannable:
        ## Step 2: Anonymous staging sandbox with mode 0700 permissions
        with tempfile.TemporaryDirectory(prefix="twuscan.") as td:
            os.chmod(td, 0o700)
            scandir = os.path.join(td, "files")
            os.mkdir(scandir)
            alias = {}
            for i, e in enumerate(scannable):
                a = "f%07d" % i
                os.symlink(e["path"], os.path.join(scandir, a))
                alias[a] = e
                e["sha256"] = None

            lst = os.path.join(td, "list.txt")
            with open(lst, "w") as f:
                f.write("".join(os.path.join(scandir, a) + "\n" for a in alias))

            ## Step 3a: ClamAV Execution (Virus Signatures)
            if "clamav" not in engines:
                pass
            elif not tools.get("clamscan"):
                engine_err["clamav"] = "clamscan is not installed"
            else:
                found, err, ferr = _engine_clam(tools["clamscan"], alias, lst, timeout)
                if err:
                    engine_err["clamav"] = err
                for a, m in ferr.items():
                    if a in alias:
                        alias[a]["errors"].append(m)
                for a, sigs in found.items():
                    if a in alias:
                        for s in sigs:
                            alias[a]["findings"].append({"engine": "clamav", "name": s})

            ## Step 3b: YARA Execution (Behavioral Heuristics)
            if "yara" not in engines:
                pass
            elif not tools.get("yara"):
                engine_err["yara"] = "yara is not installed"
            elif not st["rules"]["ok"]:
                engine_err["yara"] = "vetted YARA rules unusable: " + ("; ".join(st["rules"]["problems"]) or "no rules")
            else:
                found, err, ferr = _engine_yara(
                    tools["yara"], rules_dir / "index.yar", scandir, load_exclusions(rules_dir), timeout
                )
                if err:
                    engine_err["yara"] = err
                for a, m in ferr.items():
                    if a in alias:
                        alias[a]["errors"].append(m)
                for a, rl in found.items():
                    if a in alias:
                        for r in rl:
                            alias[a]["findings"].append({"engine": "yara", "name": r})

        ## Step 4: Record cryptographic file hashes
        for e in scannable:
            try:
                e["sha256"] = sha256(e["path"])
            except OSError:
                pass
        for e in scannable:
            for eng, msg in engine_err.items():
                e["errors"].append(msg)

    ## Step 5: Test fixture exemptions (YARA-only; ClamAV is NEVER ignored)
    fixtures = load_fixtures(rules_dir)
    for e in scannable if fixtures else []:
        if e["findings"] and all(f["engine"] == "yara" for f in e["findings"]) \
                and _pinned_fixture(e["path"], e.get("sha256"), root, fixtures):
            e["fixture_pinned"] = [f["name"] for f in e["findings"]]
            e["findings"] = []

    for msg in sorted(set(engine_err.values())):
        reasons.append(msg)

    ## Step 6: Fail-closed verdict synthesis
    files, worst = [], "CLEAN" if entries else "COULD-NOT-SCAN"
    for e in entries:
        if any(f["engine"] == "clamav" for f in e["findings"]):
            v = "INFECTED"
        elif e["findings"]:
            v = "SUSPICIOUS"
        elif e["errors"]:
            v = "COULD-NOT-SCAN"
        else:
            v = "CLEAN"

        if VERDICT_RANK[v] > VERDICT_RANK[worst]:
            worst = v

        if v == "INFECTED":
            reasons.append("%s -> ClamAV signature match: %s" % (
                e["path"], ", ".join(f["name"] for f in e["findings"] if f["engine"] == "clamav")
            ))
        if v in ("INFECTED", "SUSPICIOUS") and any(f["engine"] == "yara" for f in e["findings"]):
            reasons.append("%s -> YARA rule match: %s" % (
                e["path"], ", ".join(f["name"] for f in e["findings"] if f["engine"] == "yara")
            ))
        if e.get("fixture_pinned"):
            reasons.append("%s -> pinned test fixture (path+sha256 in EXCLUSIONS.json): YARA ignored %s" % (
                e["path"], ", ".join(e["fixture_pinned"])
            ))
        if e["skip"]:
            reasons.append("%s -> %s" % (e["path"], e["skip"]))
        elif v == "COULD-NOT-SCAN":
            own = [x for x in e["errors"] if x not in engine_err.values()]
            if own:
                reasons.append("%s -> %s" % (e["path"], "; ".join(own)))

        files.append({
            "path": e["path"],
            "verdict": v,
            "sha256": e.get("sha256"),
            "findings": e["findings"],
            "errors": [x for x in e["errors"]],
            **({"fixture_pinned": e["fixture_pinned"]} if e.get("fixture_pinned") else {}),
        })

    ## Fail-closed enforcement: if any engine failed, result can never be clean
    if worst == "CLEAN" and engine_err:
        worst = "COULD-NOT-SCAN"

    if not reasons and worst == "CLEAN":
        reasons.append("both engines ran; no signature or rule matched (this is not proof of safety)")

    ## Step 7: Update proposals and notifications
    items = update_items(st, root, decider)
    for it in items:
        notes.append("Note: %s. Update available, needs approval: %s" % (it["why"], it["approve"]))
    if write_receipt:
        write_updates(root, items, now)

    ## Step 8: Build forensic receipt document
    doc = {
        "schema": "twu.scan.v1",
        "ts": now,
        "host": HOST,
        "verdict": worst,
        "reasons": reasons,
        "notes": notes,
        "files": files,
        "engines": {
            "yara": st["tools"]["yara"]["version"],
            "clamscan": st["tools"]["clamscan"]["version"],
        },
        "rules": {
            "rule_count": st["rules"]["rule_count"],
            "built": st["rules"]["built"],
        },
        "signatures": {
            "age_days": st["signatures"]["age_days"],
        },
        "engines_run": list(engines),
        "caps": {
            "max_bytes": max_bytes,
            "timeout_s": timeout,
        },
    }

    ## Step 9: Atomically persist receipt
    if write_receipt:
        h = hashlib.sha256("\n".join(sorted(e["path"] for e in entries)).encode("utf-8", "replace")).hexdigest()[:8]
        name = "%s-%s.json" % (time.strftime("%Y%m%dT%H%M%S", time.gmtime(now)), h)
        try:
            doc["receipt"] = str(write_atomic(root / "data" / "health" / "scans" / name, doc, unique=True))
        except OSError as e:
            doc["notes"].append("receipt not written: %s" % e)

    return doc


## -----------------------------------------------------------------------------
## SECTION 11: CLI & TERMINAL RENDERING
## -----------------------------------------------------------------------------
def render_scan(doc):
    """Format structured scan result dictionary into human-readable terminal output.

    Parameters:
        doc (dict): Scan output document.

    Returns:
        str: Multi-line formatted terminal string.
    """
    lines = ["VERDICT: %s" % doc["verdict"]]
    for f in doc["files"]:
        lines.append("%s: %s" % (f["verdict"], f["path"]))
    for r in doc["reasons"][:12]:
        lines.append("  - " + r)
    if len(doc["reasons"]) > 12:
        lines.append("  - (+%d more in the receipt)" % (len(doc["reasons"]) - 12))
    lines.append("  scanned %d file(s) with YARA %s (%d rules) and ClamAV %s" % (
        len(doc["files"]),
        doc["engines"]["yara"] or "n/a",
        doc["rules"]["rule_count"],
        doc["engines"]["clamscan"] or "n/a",
    ))
    if doc.get("receipt"):
        lines.append("  receipt: " + doc["receipt"])
    return "\n".join(lines)


def render_status(s):
    """Format system diagnostic status dictionary into human-readable dashboard.

    Parameters:
        s (dict): Status output dictionary.

    Returns:
        str: Multi-line status dashboard text.
    """
    L = ["Security scanner status (%s): %s" % (s["host"], "ACTIVE" if s["active"] else "NOT ACTIVE")]
    for n in TOOL_NAMES:
        t = s["tools"][n]
        L.append("  %-9s %s" % (n, ("%s (%s)" % (t["version"] or "version unknown", t["path"])) if t["path"] else "MISSING"))
    r, g = s["rules"], s["signatures"]
    L.append("  YARA rules: %d rules in %d files, built %s (%s days old), integrity %s" % (
        r["rule_count"],
        r["files"],
        r["built"] or "?",
        "%.0f" % r["age_days"] if r["age_days"] is not None else "?",
        "OK" if not r["problems"] else "PROBLEM: " + "; ".join(r["problems"]),
    ))
    L.append("  ClamAV signatures: %s" % (
        "none found in %s" % g["dir"] if not g["present"] else
        "%.1f days old (%s)" % (g["age_days"], "fresh" if g["fresh"] else "OLD, limit %d" % SIG_MAX_AGE_DAYS)
    ))
    for p in s["problems"]:
        L.append("  ! " + p)
    return "\n".join(L)


def main(argv=None):
    """Main CLI entrypoint for manual and scripted execution.

    Parameters:
        argv (list[str] | None): Argument list override.

    Returns:
        int: POSIX exit status code.
    """
    ap = argparse.ArgumentParser(description="Cross-platform malware scan (YARA + ClamAV)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ## Subcommand: scan
    sc = sub.add_parser("scan", help="Scan specified files or directories")
    sc.add_argument("paths", nargs="+", help="Files or directories to scan")
    sc.add_argument("--max-mb", type=int, default=DEFAULT_MAX_BYTES // (1 << 20), help="Maximum file size in MiB")
    sc.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Scan timeout in seconds")
    sc.add_argument("--json", action="store_true", help="Output raw JSON document")

    ## Subcommand: status
    st = sub.add_parser("status", help="Show scanner health and signature status")
    st.add_argument("--json", action="store_true", help="Output status as JSON")

    ## Subcommand: update-signatures
    us = sub.add_parser("update-signatures", help="Refresh ClamAV signature database")
    us.add_argument("--approve", action="store_true", help="Execute download from official mirror")

    ## Subcommand: update-rules
    sub.add_parser("update-rules", help="Display instructions to refresh vetted YARA rules")

    a = ap.parse_args(argv)

    if a.cmd == "scan":
        doc = scan(a.paths, max_bytes=a.max_mb * (1 << 20), timeout=a.timeout)
        print(json.dumps(doc, indent=1) if a.json else render_scan(doc))
        for n in doc["notes"]:
            print(n, file=sys.stderr)
        return exit_code(doc["verdict"])

    if a.cmd == "status":
        s = status()
        print(json.dumps(s, indent=1) if a.json else render_status(s))
        for it in update_items(s, REPO):
            print("Note: %s. Update available, needs approval: %s" % (it["why"], it["approve"]), file=sys.stderr)
        return 0 if s["active"] else 1

    if a.cmd == "update-signatures":
        out = update_signatures(approve=a.approve)
        print("%s: %s" % (out["status"], out["detail"]))
        return 0 if out["status"] in ("proposal", "updated") else 1

    ## update-rules instructions
    print((REPO / "data" / "yara_rules" / "README.md").read_text(encoding="utf-8").split("## Refresh")[-1].strip()
          if (REPO / "data" / "yara_rules" / "README.md").is_file() else "See data/yara_rules/README.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
