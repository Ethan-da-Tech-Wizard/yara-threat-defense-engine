#!/usr/bin/env python3
"""twu_yara_vet: Compile-time YARA rule vetting and AST validation engine.

===============================================================================
EDUCATIONAL CONCEPT: SECURE YARA SIGNATURE VETTING PIPELINE
===============================================================================
YARA is an industry-standard pattern matching engine for malware researchers.
However, importing raw, unvetted YARA rules from community feeds into a
production environment presents substantial security and stability risks:

1. ReDoS & Runaway Complexity: Poorly constructed regular expressions can cause
   catastrophic backtracking, leading to denial-of-service (100% CPU lockup).
2. Malicious Modules: YARA supports external modules (such as 'cuckoo',
   which can trigger network calls or arbitrary system hooks).
3. Global Rule Side-Effects: A rule marked 'global' forces its condition onto
   EVERY other rule evaluated in the same compilation unit, silently altering
   the entire ruleset's evaluation logic.
4. Relative Include Traversal: 'include' directives can reference unexpected
   paths, create circular references, or break deterministic packaging.
5. Namespace Collisions: Duplicate rule identifiers trigger compile errors
   that abort the entire scanning run.

To solve this, `twu_yara_vet` enforces a strict Ahead-of-Time (AOT) static
verification pipeline:
  a) Lexical sanitization (stripping multi-line and single-line comments).
  b) AST / Regex Module Allowlisting (restricting imports strictly to
     safe binary parsing modules: pe, elf, math, hash, dotnet, macho).
  c) Structural constraints: rejection of 'global' rules and 'include' directives.
  d) Duplicate identifier detection across multiple feeds.
  e) Offline bytecode compilation via `yarac`.
  f) Cryptographic integrity manifest generation (SHA-256 for all vetted files).
  g) False-positive corpus testing (`fptest`) against known-benign binaries.

Usage:
  build  --src ID=DIR@COMMIT|LICENSE|URL ...   Vet rules from pinned checkouts
  fptest --corpus-file LIST                    Scan known-clean files for false positives
  verify                                       Validate MANIFEST sha256 & compile index
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Base directory anchors: Resolve absolute path to the repository root.
# Expects this script to reside in <REPO>/scripts/twu_yara_vet.py
ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "data" / "yara_rules"

# -----------------------------------------------------------------------------
# Security Allowlist: Modules Permitted in YARA Rules
# -----------------------------------------------------------------------------
# Only safe, deterministic parsing modules with no network or subprocess
# capabilities are permitted. Modules like 'cuckoo' are explicitly rejected.
ALLOWED_MODULES = {"pe", "elf", "math", "hash", "dotnet", "macho"}

# -----------------------------------------------------------------------------
# Lexical & AST Pattern Analyzers
# -----------------------------------------------------------------------------
# Regular expressions designed to inspect rule headers without full AST overhead.
# Matches: import "module_name"
IMPORT_RE = re.compile(r'^\s*import\s+"([^"]+)"', re.M)

# Matches: [private|global] rule <identifier>
# Captures modifier prefixes and rule identifier for namespace isolation.
RULE_RE = re.compile(r'^\s*((?:(?:private|global)\s+)*)rule\s+([A-Za-z_]\w*)', re.M)

# Matches: include "filename"
# Disallowed to enforce that each vetted rule file is self-contained.
INCLUDE_RE = re.compile(r'^\s*include\s+"', re.M)


def which_local(cmd):
    """Locate a binary on the system PATH or in ~/.local/bin fallback.

    Educational Note: In non-interactive automation or restricted container
    environments, user-installed CLI tools (like compiled YARA utilities)
    often reside in ~/.local/bin rather than standard system PATHs.
    """
    p = shutil.which(cmd)
    if p:
        return p
    c = Path.home() / ".local" / "bin" / cmd
    return str(c) if c.is_file() and os.access(str(c), os.X_OK) else None


def sha256(path):
    """Compute cryptographic SHA-256 digest in 1 MiB chunked streams.

    Streaming file contents ensures constant, deterministic memory usage
    even when hashing multi-gigabyte files or signature archives.
    """
    h = hashlib.sha256()
    with open(str(path), "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def strip_comments(text):
    """Strip C-style block comments (/* ... */) and line comments (// ...).

    Crucial for static AST inspection: Prevents commented-out imports or
    disabled rules from triggering false validation rejections.
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def static_check(text):
    """Perform static security analysis on raw YARA rule text.

    Returns:
        tuple: (rule_names: list[str], reason: str | None)
        If reason is not None, the rule violates security policy and is rejected.

    Educational Checks:
    1. Module Allowlisting: Verifies that any 'import' directive references
       only pre-approved, safe binary parsing libraries.
    2. Modularity & Hermeticity: Verifies that no 'include' directives exist;
       every rule file must be self-contained.
    3. Global Flag Rejection: Rules marked 'global' would alter the evaluation
       context of every other rule in the engine, breaking isolation.
    4. Valid Rule Syntax: Ensures at least one valid rule definition is present.
    """
    bare = strip_comments(text)

    # 1. Check for unauthorized modules
    for m in IMPORT_RE.findall(bare):
        if m not in ALLOWED_MODULES:
            return [], "uses disabled module '%s'" % m

    # 2. Check for disallowed include statements
    if INCLUDE_RE.search(bare):
        return [], "uses include (must be self-contained)"

    # 3. Extract rule names and check for hazardous 'global' modifiers
    names = []
    for mods, name in RULE_RE.findall(bare):
        if "global" in mods:
            return [], "declares global rule %s" % name
        names.append(name)

    # 4. Enforce presence of at least one rule
    if not names:
        return [], "no rules found"

    return names, None


def compile_check(yarac, path):
    """Run `yarac` ahead-of-time (AOT) compiler to test rule compilation.

    Returns:
        str | None: None if compilation succeeds; error message if it fails.

    Educational Note: Compiling rules into a temporary file descriptor tests
    the native YARA parser against syntax errors, undeclared variables,
    type errors in conditions, and unsupported engine features.
    """
    with tempfile.TemporaryDirectory() as td:
        try:
            r = subprocess.run(
                [yarac, str(path), os.path.join(td, "out.yarc")],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            return "yarac did not run: %s" % e

        if r.returncode != 0:
            # Capture the exact error diagnostic from stderr/stdout
            msg = ((r.stderr or r.stdout).strip().splitlines() or ["compile error"])[-1]
            if "undefined identifier" in msg or "external" in msg:
                return "needs external variable or undefined identifier: " + msg[-160:]
            return "does not compile: " + msg[-160:]
    return None


def combined_ok(yarac, index):
    """Validate that the aggregated master index (`index.yar`) compiles cleanly."""
    return compile_check(yarac, index)


def write_index(rules_dir, files):
    """Generate the root `index.yar` referencing all accepted vetted rule files.

    Generates a deterministic, sorted sequence of include directives.
    """
    lines = ["// generated by scripts/twu_yara_vet.py; do not edit. One include per vetted file.\n"]
    for rel in sorted(files):
        lines.append('include "%s"\n' % rel)
    (rules_dir / "index.yar").write_text("".join(lines), encoding="utf-8")


def write_atomic(path, doc):
    """Atomic write pattern: writes JSON payload to temporary file and renames.

    Prevents partial reads, race conditions, or file corruption if a process
    is interrupted midway through writing.
    """
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, str(path))


def parse_src(spec):
    """Parse vendor source specification string: ID=DIR@COMMIT|LICENSE|URL."""
    idpart, rest = spec.split("=", 1)
    d, commit, lic, url = rest.replace("@", "|", 1).split("|", 3)
    return idpart, Path(d), commit, lic, url


def build(srcs, rules_dir=RULES, yarac=None, include_dirs=None, now=None):
    """Compile-time vetting pipeline: ingest upstream rules, vet, copy, and manifest.

    Parameters:
        srcs: list of (id, source_dir, commit, license, url)
        rules_dir: target output directory for vetted rules
        yarac: path to yarac binary
        include_dirs: dict of {source_id: [subdirs]}
        now: optional timestamp override

    Educational Flow:
    1. Clean existing vendor targets to prevent stale rule pollution.
    2. Iterate through all .yar/.yara files in source directory.
    3. Run `static_check()` to enforce AST safety (no bad modules, no globals).
    4. Check for duplicate rule identifier collisions across feeds.
    5. Run `compile_check()` via `yarac` to ensure syntactic correctness.
    6. Copy accepted files to `vendor/<id>/<path>`.
    7. Generate `index.yar` linking all accepted files.
    8. Compile `index.yar` as a unified bundle to detect inter-rule collisions.
    9. Produce cryptographic `MANIFEST.json` with per-file SHA-256 hashes.
    """
    yarac = yarac or which_local("yarac")
    if not yarac:
        raise SystemExit("yarac not found")

    rules_dir = Path(rules_dir)
    taken, accepted, rejected, sources = {}, [], [], []
    vendor = rules_dir / "vendor"
    if vendor.exists():
        shutil.rmtree(str(vendor))

    for sid, d, commit, lic, url in srcs:
        entry = {"id": sid, "url": url, "commit": commit, "license": lic, "files": 0, "rejected": 0}
        for sub in (include_dirs or {}).get(sid) or ["."]:
            base = d / sub
            for p in sorted(base.rglob("*")):
                if p.suffix not in (".yar", ".yara") or not p.is_file() or "deprecated" in p.parts:
                    continue
                rel_src = str(p.relative_to(d))
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                # Step 1: Static AST validation
                names, why = static_check(text)

                # Step 2: Global namespace uniqueness check
                if not why:
                    dup = [n for n in names if n in taken]
                    if dup:
                        why = "duplicate rule name %s already in %s" % (dup[0], taken[dup[0]])

                # Step 3: AOT compilation check
                if not why:
                    why = compile_check(yarac, p)

                # Handle rejection or acceptance
                if why:
                    rejected.append({"source": sid, "file": rel_src, "reason": why})
                    entry["rejected"] += 1
                    continue

                dest_rel = "vendor/%s/%s" % (sid, rel_src)
                dest = rules_dir / dest_rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(str(p), str(dest))

                for n in names:
                    taken[n] = dest_rel
                accepted.append({
                    "path": dest_rel,
                    "sha256": sha256(dest),
                    "source": sid,
                    "source_path": rel_src,
                    "rules": len(names),
                })
                entry["files"] += 1

        # Preserve vendor LICENSE file for legal provenance and compliance
        lic_src = d / "LICENSE"
        if lic_src.is_file():
            (rules_dir / "vendor" / sid).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(lic_src), str(rules_dir / "vendor" / sid / "LICENSE"))
            entry["license_file_sha256"] = sha256(rules_dir / "vendor" / sid / "LICENSE")
        sources.append(entry)

    # Write unified master index
    write_index(rules_dir, [a["path"] for a in accepted])
    why = combined_ok(yarac, rules_dir / "index.yar")

    # Generate cryptographic provenance manifest
    doc = {
        "version": 1,
        "built": time.strftime("%Y-%m-%d", time.gmtime(now or time.time())),
        "built_epoch": int(now or time.time()),
        "note": "Pinned, vetted YARA rules. Refresh = re-run build from a new pinned commit; see README.md.",
        "sources": sources,
        "files": accepted,
        "rejected": rejected,
        "rule_count": sum(a["rules"] for a in accepted),
        "combined_compile": why or "ok",
    }
    write_atomic(rules_dir / "MANIFEST.json", doc)
    return doc


def verify(rules_dir=RULES, yarac=None, compile_index=True):
    """Verify rule integrity against `MANIFEST.json` and compile `index.yar`.

    Returns:
        list[str]: list of problems encountered (empty list indicates 100% OK).

    Educational Concept: Defense-in-Depth against tampering.
    Even if an adversary modifies a vendor rule on disk, the SHA-256 hash
    check against MANIFEST.json immediately fails before any scan runs.
    """
    rules_dir = Path(rules_dir)
    probs = []
    try:
        man = json.loads((rules_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return ["MANIFEST.json unreadable: %s" % e]

    # Check existence and SHA-256 hash of each vetted rule file
    for f in man.get("files", []):
        p = rules_dir / f["path"]
        if not p.is_file():
            probs.append("missing " + f["path"])
        elif sha256(p) != f["sha256"]:
            probs.append("sha256 mismatch " + f["path"])

    # Verify index.yar includes every single manifest file exactly once
    idx = rules_dir / "index.yar"
    want = set('include "%s"' % f["path"] for f in man.get("files", []))
    have = set(
        l.strip()
        for l in (idx.read_text(encoding="utf-8").splitlines() if idx.is_file() else [])
        if l.startswith("include")
    )
    if want != have:
        probs.append("index.yar does not match MANIFEST")

    # Compile entire ruleset bundle to ensure aggregate health
    yarac = yarac or which_local("yarac")
    if compile_index and yarac and not probs:
        why = compile_check(yarac, idx)
        if why:
            probs.append("index.yar " + why)

    return probs


def fptest(corpus, rules_dir=RULES, yara=None, exclusions=(), timeout=1800):
    """False-Positive Regression Testing against a corpus of known-clean files.

    Parameters:
        corpus: list of benign file paths (e.g. system binaries, python stdlib)
        rules_dir: directory containing index.yar
        yara: path to yara executable
        exclusions: set of rule names explicitly excluded in EXCLUSIONS.json
        timeout: execution timeout in seconds

    Returns:
        dict: {rule_name: [matching_clean_paths]}

    Educational Pattern: Batching with Symlink Aliases.
    To avoid compiling 5,000+ rules repeatedly for each corpus file, all corpus
    files are symlinked into a single temporary directory (`f0000001`, `f0000002`).
    YARA is then invoked once with recursive directory scanning.
    This reduces scanning time from hours to seconds while running zero untrusted code.
    """
    yara = yara or which_local("yara")
    hits = {}
    with tempfile.TemporaryDirectory() as td:
        names = {}
        for i, p in enumerate(corpus):
            n = "f%07d" % i
            try:
                os.symlink(p, os.path.join(td, n))
            except OSError:
                continue
            names[n] = p

        r = subprocess.run(
            [yara, "-r", str(Path(rules_dir) / "index.yar"), td],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        for line in r.stdout.splitlines():
            parts = line.split(" ", 1)
            if len(parts) != 2:
                continue
            rule, path = parts
            if rule in exclusions:
                continue
            hits.setdefault(rule, []).append(names.get(os.path.basename(path), path))
    return hits


def main(argv=None):
    """CLI entrypoint for building, testing, and verifying YARA rules."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="Vet and compile rules from source checkouts")
    b.add_argument("--src", action="append", required=True, help="ID=DIR@COMMIT|LICENSE|URL")
    b.add_argument("--only", action="append", default=[], help="ID=subdir (repeatable) to limit a source")

    f = sub.add_parser("fptest", help="Run false-positive sweep against clean file corpus")
    f.add_argument("--corpus-file", required=True, help="Text file with one clean path per line")

    sub.add_parser("verify", help="Verify rule manifest integrity and compile index")

    a = ap.parse_args(argv)

    if a.cmd == "build":
        inc = {}
        for o in a.only:
            k, v = o.split("=", 1)
            inc.setdefault(k, []).append(v)
        doc = build([parse_src(s) for s in a.src], include_dirs=inc)
        print("accepted %d files, %d rules; rejected %d; combined compile: %s" % (
            len(doc["files"]), doc["rule_count"], len(doc["rejected"]), doc["combined_compile"]))
        return 0

    if a.cmd == "verify":
        probs = verify()
        print("OK" if not probs else "\n".join(probs))
        return 1 if probs else 0

    # fptest command handling
    corpus = [l.rstrip("\n") for l in open(a.corpus_file, encoding="utf-8") if l.strip()]
    ex = set()
    try:
        ex = set(e["rule"] for e in json.loads((RULES / "EXCLUSIONS.json").read_text())["excluded"])
    except (OSError, ValueError, KeyError):
        pass
    hits = fptest(corpus, exclusions=ex)
    print(json.dumps(hits, indent=1))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
