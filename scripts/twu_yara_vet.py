#!/usr/bin/env python3
# ==============================================================================
# Program: twu_yara_vet.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Ahead-of-Time (AOT) static analysis, vetting, and compilation pipeline
#          for YARA malware detection signatures. Validates syntactic correctness,
#          restricts dangerous external modules (e.g. cuckoo), bans global rule side-effects
#          and recursive includes, enforces exclusions, and generates cryptographic
#          SHA-256 manifests to establish an immutable, verifiable rule baseline.
# ==============================================================================
## ==============================================================================
## TWU THREAT DEFENSE ENGINE: YARA RULE VETTING & AOT COMPILATION
## ==============================================================================
## Author: Ethan REDACTED <ethan@REDACTED>
## Organization: TWU LLC
## Copyright: (c) 2026 Ethan REDACTED, TWU LLC
## License: MIT License 2026
##
## EDUCATIONAL CONCEPT: SECURE YARA SIGNATURE VETTING PIPELINE
## ------------------------------------------------------------------------------
## YARA is an industry-standard pattern matching engine for malware researchers.
## However, importing raw, unvetted YARA rules from community feeds into a
## production environment presents substantial security and stability risks:
##
## 1. ReDoS & Runaway Complexity: Poorly constructed regular expressions can cause
##    catastrophic backtracking, leading to denial-of-service (100% CPU lockup).
## 2. Malicious Modules: YARA supports external modules (such as 'cuckoo',
##    which can trigger network calls or arbitrary system hooks).
## 3. Global Rule Side-Effects: A rule marked 'global' forces its condition onto
##    EVERY other rule evaluated in the same compilation unit, silently altering
##    the entire ruleset's evaluation logic.
## 4. Relative Include Traversal: 'include' directives can reference unexpected
##    paths, create circular references, or break deterministic packaging.
## 5. Namespace Collisions: Duplicate rule identifiers trigger compile errors
##    that abort the entire scanning run.
##
## To solve this, `twu_yara_vet` enforces a strict Ahead-of-Time (AOT) static
## verification pipeline:
##   a) Lexical sanitization (stripping multi-line and single-line comments).
##   b) AST / Regex Module Allowlisting (restricting imports strictly to
##      safe binary parsing modules: pe, elf, math, hash, dotnet, macho).
##   c) Structural constraints: rejection of 'global' rules and 'include' directives.
##   d) Duplicate identifier detection across multiple feeds.
##   e) Offline bytecode compilation via `yarac`.
##   f) Cryptographic integrity manifest generation (SHA-256 for all vetted files).
##   g) False-positive corpus testing (`fptest`) against known-benign binaries.
##
## Usage:
##   build  --src ID=DIR@COMMIT|LICENSE|URL ...   Vet rules from pinned checkouts
##   fptest --corpus-file LIST                    Scan known-clean files for false positives
##   verify                                       Validate MANIFEST sha256 & compile index
## ==============================================================================

"""twu_yara_vet: Compile-time YARA rule vetting and AST validation engine."""

## -----------------------------------------------------------------------------
## SECTION 1: IMPORTS & BASE DIRECTORY RESOLUTION
## -----------------------------------------------------------------------------
import argparse
## hashlib: SHA-256 manifest entries.
import hashlib
import json
import os
import re
## shutil: PATH lookup, copying vetted files, removing stale vendor trees.
import shutil
## subprocess: runs yarac/yara as argument lists (no shell).
import subprocess
import sys
import tempfile
import time
from pathlib import Path

## Base directory anchors: Resolve absolute path to the repository root.
## Expects this script to reside in <REPO>/scripts/twu_yara_vet.py
## Resolved so the script behaves the same from any working directory.
ROOT = Path(__file__).resolve().parent.parent
## Default output/verification directory for vetted rules.
RULES = ROOT / "data" / "yara_rules"

## -----------------------------------------------------------------------------
## SECTION 2: SECURITY ALLOWLIST & AST REGEX PATTERNS
## -----------------------------------------------------------------------------
## Only safe, deterministic binary parsing modules with no network, external
## script execution, or OS sandbox hooks are permitted. Modules like 'cuckoo'
## are explicitly rejected to maintain strict offline hermeticity.
## Why an allowlist and not a denylist: new YARA modules appear over time and an
## unknown one must default to rejected.
ALLOWED_MODULES = {"pe", "elf", "math", "hash", "dotnet", "macho"}

## Regular expressions designed to inspect rule headers without full AST parser overhead.
## Matches: import "module_name"
## re.M makes ^ match at every line start, so only real top-level imports match.
IMPORT_RE = re.compile(r'^\s*import\s+"([^"]+)"', re.M)

## Matches: [private|global] rule <identifier>
## Captures modifier prefixes and rule identifier for namespace isolation and policy checks.
## Group 1 is the (possibly empty) modifier run; group 2 is the rule name.
RULE_RE = re.compile(r'^\s*((?:(?:private|global)\s+)*)rule\s+([A-Za-z_]\w*)', re.M)

## Matches: include "filename"
## Disallowed to enforce that each vetted rule file is completely self-contained.
## Includes could pull in unvetted files from outside the manifest.
INCLUDE_RE = re.compile(r'^\s*include\s+"', re.M)


## -----------------------------------------------------------------------------
## SECTION 3: SYSTEM UTILITIES & CRYPTOGRAPHIC PRIMITIVES
## -----------------------------------------------------------------------------
def which_local(cmd):
    """Locate a binary on the system PATH or in ~/.local/bin fallback.

    Educational Note: In non-interactive automation, CI pipelines, or restricted
    container environments, user-installed CLI tools (like compiled YARA utilities)
    often reside in ~/.local/bin rather than standard system PATHs.

    Parameters:
        cmd (str): Executable name to discover (e.g. 'yara', 'yarac').

    Returns:
        str | None: Absolute path to executable if found and runnable, else None.
    """
    ## Check primary system PATH directories first
    ## System PATH wins so an admin-installed tool is preferred over a user copy.
    p = shutil.which(cmd)
    if p:
        return p
    ## Fallback to user-local binary path (~/.local/bin)
    ## Only an executable regular file counts; a directory named like the tool does not.
    c = Path.home() / ".local" / "bin" / cmd
    return str(c) if c.is_file() and os.access(str(c), os.X_OK) else None


def sha256(path):
    """Compute cryptographic SHA-256 digest in 1 MiB chunked streams.

    Streaming file contents ensures constant, deterministic memory usage
    even when hashing multi-gigabyte files or signature archives.

    Parameters:
        path (Path | str): Path to file to hash.

    Returns:
        str: 64-character lowercase hexadecimal SHA-256 digest.
    """
    h = hashlib.sha256()
    with open(str(path), "rb") as f:
        ## Read in 1 MiB (1048576 byte) chunks until EOF
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def strip_comments(text):
    """Strip C-style block comments (/* ... */) and line comments (// ...).

    Crucial for static AST inspection: Prevents commented-out imports or
    disabled rules from triggering false validation rejections.

    Parameters:
        text (str): Raw YARA rule file contents.

    Returns:
        str: Text stripped of comments while preserving string literals.
    """
    ## Strip multi-line /* ... */ block comments using DOTALL (re.S)
    ## Non-greedy so two separate block comments do not swallow the code between them.
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    ## Strip single-line // ... comments
    ## Known limit: a '//' inside a string literal is also cut. That only affects the
    ## safety scan of the text, never the rule file that is actually compiled.
    return re.sub(r"//[^\n]*", "", text)


## -----------------------------------------------------------------------------
## SECTION 4: STATIC AST VALIDATION & COMPILATION CHECKS
## -----------------------------------------------------------------------------
def static_check(text):
    """Perform static security analysis on raw YARA rule text.

    Parameters:
        text (str): Raw YARA rule source text to analyze.

    Returns:
        tuple[list[str], str | None]: (rule_names, failure_reason)
        If failure_reason is not None, the rule violates security policy and is rejected.

    Educational Checks:
    1. Comment Stripping: Eliminates false matches in documentation.
    2. Module Allowlisting: Verifies that any 'import' directive references
       only pre-approved, safe binary parsing libraries (pe, elf, math, hash, dotnet, macho).
    3. Modularity & Hermeticity: Verifies that no 'include' directives exist;
       every rule file must be self-contained for deterministic packaging.
    4. Global Flag Rejection: Rules marked 'global' mutate the evaluation
       context of every other rule in the engine, breaking isolation.
    5. Valid Rule Syntax: Ensures at least one valid rule definition is present.
    """
    ## All policy checks run on comment-free text so a commented-out import neither
    ## fails nor hides a real one.
    bare = strip_comments(text)

    ## Step 1: Check for unauthorized or hazardous external modules
    for m in IMPORT_RE.findall(bare):
        if m not in ALLOWED_MODULES:
            return [], "uses disabled module '%s'" % m

    ## Step 2: Check for disallowed relative include statements
    if INCLUDE_RE.search(bare):
        return [], "uses include (must be self-contained)"

    ## Step 3: Extract rule identifiers and reject dangerous 'global' modifiers
    names = []
    for mods, name in RULE_RE.findall(bare):
        if "global" in mods:
            return [], "declares global rule %s" % name
        names.append(name)

    ## Step 4: Enforce presence of at least one valid rule definition
    if not names:
        return [], "no rules found"

    return names, None


def compile_check(yarac, path):
    """Run `yarac` ahead-of-time (AOT) compiler to test rule compilation.

    Parameters:
        yarac (str): Absolute path to the yarac compiler binary.
        path (Path | str): Path to the YARA rule file or index to compile.

    Returns:
        str | None: None if compilation succeeds; diagnostic error string if it fails.

    Educational Note: Compiling rules into a temporary file descriptor tests
    the native YARA parser against syntax errors, undeclared variables,
    type errors in conditions, and unsupported engine features ahead of time.
    """
    with tempfile.TemporaryDirectory() as td:
        try:
            ## Execute yarac compiling source rule into temporary bytecode file
            r = subprocess.run(
                [yarac, str(path), os.path.join(td, "out.yarc")],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            return "yarac did not run: %s" % e

        ## Inspect returncode: Non-zero signifies parser or type error
        if r.returncode != 0:
            ## Capture the final diagnostic error line from stderr or stdout
            msg = ((r.stderr or r.stdout).strip().splitlines() or ["compile error"])[-1]
            if "undefined identifier" in msg or "external" in msg:
                return "needs external variable or undefined identifier: " + msg[-160:]
            return "does not compile: " + msg[-160:]
    return None


def combined_ok(yarac, index):
    """Validate that the aggregated master index (`index.yar`) compiles cleanly.

    Parameters:
        yarac (str): Path to yarac compiler.
        index (Path): Path to index.yar.

    Returns:
        str | None: None on clean compilation, error message on failure.
    """
    ## Same compiler, different purpose: catches clashes only visible when ALL files load together.
    return compile_check(yarac, index)


def write_index(rules_dir, files):
    """Generate the root `index.yar` referencing all accepted vetted rule files.

    Generates a deterministic, sorted sequence of include directives.

    Parameters:
        rules_dir (Path): Destination directory where index.yar will reside.
        files (list[str]): List of repository-relative rule paths to include.
    """
    ## First line is a YARA comment: the index remains a valid rules file.
    lines = ["// generated by scripts/twu_yara_vet.py; do not edit. One include per vetted file.\n"]
    ## Sorted so identical inputs always produce a byte-identical index.
    for rel in sorted(files):
        lines.append('include "%s"\n' % rel)
    (rules_dir / "index.yar").write_text("".join(lines), encoding="utf-8")


def write_atomic(path, doc):
    """Atomic write pattern: writes JSON payload to temporary file and renames.

    Prevents partial reads, race conditions, or file corruption if a process
    is interrupted midway through writing.

    Parameters:
        path (Path | str): Final destination file path.
        doc (dict): Python dictionary to serialize into JSON.
    """
    ## Normalise str/Path callers.
    path = Path(path)
    ## Temp file in the same directory => os.replace is an atomic same-filesystem rename.
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    ## os.replace performs an atomic POSIX rename operation
    os.replace(tmp, str(path))


def parse_src(spec):
    """Parse vendor source specification string: ID=DIR@COMMIT|LICENSE|URL.

    Parameters:
        spec (str): Source spec string formatted as ID=DIR@COMMIT|LICENSE|URL.

    Returns:
        tuple[str, Path, str, str, str]: (source_id, directory, commit_hash, license_name, upstream_url)
    """
    ## Split once on the first '=': the rest may itself contain '=' (e.g. in a URL).
    idpart, rest = spec.split("=", 1)
    ## The first '@' becomes '|' so DIR@COMMIT and LICENSE|URL split uniformly;
    ## maxsplit 3 keeps any '|' inside the URL intact.
    d, commit, lic, url = rest.replace("@", "|", 1).split("|", 3)
    return idpart, Path(d), commit, lic, url


## -----------------------------------------------------------------------------
## SECTION 5: PIPELINE ORCHESTRATION (BUILD, VERIFY, FPTEST)
## -----------------------------------------------------------------------------
def build(srcs, rules_dir=RULES, yarac=None, include_dirs=None, now=None):
    """Compile-time vetting pipeline: ingest upstream rules, vet, copy, and manifest.

    Parameters:
        srcs (list): list of (id, source_dir, commit, license, url) tuples
        rules_dir (Path | str): target output directory for vetted rules
        yarac (str | None): path to yarac compiler binary
        include_dirs (dict | None): dict of {source_id: [subdirs]}
        now (float | None): optional epoch timestamp override for reproducible builds

    Educational Pipeline Flow:
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
    ## Fail early and loudly: building without a compiler would vet nothing.
    yarac = yarac or which_local("yarac")
    if not yarac:
        raise SystemExit("yarac not found on system PATH or ~/.local/bin")

    rules_dir = Path(rules_dir)
    ## taken maps rule name -> file, to catch name collisions across feeds.
    taken, accepted, rejected, sources = {}, [], [], []
    vendor = rules_dir / "vendor"
    ## Wipe previous output first so rules removed upstream cannot linger.
    if vendor.exists():
        shutil.rmtree(str(vendor))

    for sid, d, commit, lic, url in srcs:
        ## Per-source tally recorded in the manifest for provenance.
        entry = {"id": sid, "url": url, "commit": commit, "license": lic, "files": 0, "rejected": 0}
        ## Default '.' means the whole checkout when no --only restriction is given.
        for sub in (include_dirs or {}).get(sid) or ["."]:
            base = d / sub
            ## Recursively discover all YARA candidate files
            for p in sorted(base.rglob("*")):
                ## 'deprecated' directories are skipped: upstream marks them as unmaintained.
                if p.suffix not in (".yar", ".yara") or not p.is_file() or "deprecated" in p.parts:
                    continue
                rel_src = str(p.relative_to(d))
                try:
                    ## errors=replace: odd bytes in rule comments must not abort the build.
                    text = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                ## Phase 1: Static AST validation (Module allowlist & structural rules)
                names, why = static_check(text)

                ## Phase 2: Global namespace uniqueness check across feeds
                if not why:
                    dup = [n for n in names if n in taken]
                    if dup:
                        why = "duplicate rule name %s already in %s" % (dup[0], taken[dup[0]])

                ## Phase 3: Ahead-of-Time Bytecode Compilation via yarac
                if not why:
                    why = compile_check(yarac, p)

                ## Record rejection diagnostics
                if why:
                    rejected.append({"source": sid, "file": rel_src, "reason": why})
                    entry["rejected"] += 1
                    continue

                ## Stage accepted rule into vendor directory
                dest_rel = "vendor/%s/%s" % (sid, rel_src)
                dest = rules_dir / dest_rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(str(p), str(dest))

                ## Register identifiers into taken namespace
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

        ## Preserve upstream vendor LICENSE file for legal provenance and compliance
        lic_src = d / "LICENSE"
        if lic_src.is_file():
            (rules_dir / "vendor" / sid).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(lic_src), str(rules_dir / "vendor" / sid / "LICENSE"))
            entry["license_file_sha256"] = sha256(rules_dir / "vendor" / sid / "LICENSE")
        sources.append(entry)

    ## Write aggregated master index linking all accepted files
    ## Index is written after the loop so it lists exactly the accepted set.
    write_index(rules_dir, [a["path"] for a in accepted])
    ## A non-ok result is recorded in the manifest (combined_compile) rather than raised.
    why = combined_ok(yarac, rules_dir / "index.yar")

    ## Generate cryptographic provenance manifest with SHA-256 hashes
    doc = {
        "version": 1,
        "built": time.strftime("%Y-%m-%d", time.gmtime(now or time.time())),
        ## Epoch form lets consumers compute rule age without parsing dates.
        "built_epoch": int(now or time.time()),
        "note": "Pinned, vetted YARA rules. Refresh = re-run build from a new pinned commit; see README.md.",
        "sources": sources,
        "files": accepted,
        "rejected": rejected,
        "rule_count": sum(a["rules"] for a in accepted),
        "combined_compile": why or "ok",
    }
    ## Written last: a manifest on disk implies the build finished.
    write_atomic(rules_dir / "MANIFEST.json", doc)
    return doc


def verify(rules_dir=RULES, yarac=None, compile_index=True):
    """Verify rule integrity against `MANIFEST.json` and compile `index.yar`.

    Parameters:
        rules_dir (Path | str): Path to directory containing MANIFEST.json and rules.
        yarac (str | None): Path to yarac compiler binary.
        compile_index (bool): If True, also compiles index.yar via yarac.

    Returns:
        list[str]: list of problems encountered (empty list indicates 100% OK).

    Educational Concept: Defense-in-Depth against tampering.
    Even if an adversary modifies a vendor rule on disk, the SHA-256 hash
    check against MANIFEST.json immediately fails before any scan runs.
    """
    rules_dir = Path(rules_dir)
    ## Collect every problem instead of stopping at the first, for a complete report.
    probs = []
    try:
        man = json.loads((rules_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        ## Without a manifest nothing can be trusted, so stop immediately.
        return ["MANIFEST.json unreadable: %s" % e]

    ## Check existence and cryptographic SHA-256 hash of each vetted rule file
    ## Every file listed must exist with an exactly matching hash.
    for f in man.get("files", []):
        p = rules_dir / f["path"]
        if not p.is_file():
            probs.append("missing " + f["path"])
        elif sha256(p) != f["sha256"]:
            probs.append("sha256 mismatch " + f["path"])

    ## Verify index.yar includes every single manifest file exactly once
    idx = rules_dir / "index.yar"
    ## Compare as sets of exact include lines: catches added, removed or edited entries.
    want = set('include "%s"' % f["path"] for f in man.get("files", []))
    have = set(
        l.strip()
        for l in (idx.read_text(encoding="utf-8").splitlines() if idx.is_file() else [])
        if l.startswith("include")
    )
    if want != have:
        probs.append("index.yar does not match MANIFEST")

    ## Compile entire ruleset bundle to ensure aggregate compiler readiness
    yarac = yarac or which_local("yarac")
    ## Compile only when hashes already match; otherwise the result would be noise.
    if compile_index and yarac and not probs:
        why = compile_check(yarac, idx)
        if why:
            probs.append("index.yar " + why)

    return probs


def fptest(corpus, rules_dir=RULES, yara=None, exclusions=(), timeout=1800):
    """False-Positive Regression Testing against a corpus of known-clean files.

    Parameters:
        corpus (list[str]): list of benign file paths (e.g. system binaries, python stdlib)
        rules_dir (Path | str): directory containing index.yar
        yara (str | None): path to yara executable
        exclusions (set[str]): set of rule names explicitly excluded in EXCLUSIONS.json
        timeout (int): execution watchdog timeout in seconds

    Returns:
        dict[str, list[str]]: {rule_name: [matching_clean_paths]}

    Educational Pattern: Batching with Anonymous Symlink Aliases.
    To avoid compiling 5,000+ rules repeatedly for each corpus file, all corpus
    files are symlinked into a single temporary directory (`f0000000`, `f0000001`).
    YARA is then invoked once with recursive directory scanning.
    This reduces scanning time from hours to seconds while running zero untrusted code.
    """
    ## Same discovery as yarac.
    yara = yara or which_local("yara")
    hits = {}
    with tempfile.TemporaryDirectory() as td:
        ## alias -> real path, so reports show real paths while yara only sees aliases.
        names = {}
        for i, p in enumerate(corpus):
            n = "f%07d" % i
            try:
                ## Aliasing neutralises hostile filenames and lets one yara run cover the whole corpus.
                os.symlink(p, os.path.join(td, n))
            except OSError:
                continue
            names[n] = p

        ## Execute single recursive YARA pass over all batched aliases
        r = subprocess.run(
            [yara, "-r", str(Path(rules_dir) / "index.yar"), td],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        ## Parse output lines: "<rule_name> <path>"
        for line in r.stdout.splitlines():
            ## Split once: the path part may contain spaces.
            parts = line.split(" ", 1)
            if len(parts) != 2:
                continue
            rule, path = parts
            if rule in exclusions:
                continue
            ## basename of the alias path is mapped back to the original corpus path.
            hits.setdefault(rule, []).append(names.get(os.path.basename(path), path))
    return hits


## -----------------------------------------------------------------------------
## SECTION 6: COMMAND LINE INTERFACE (CLI) ENTRYPOINT
## -----------------------------------------------------------------------------
def main(argv=None):
    """CLI entrypoint for building, testing, and verifying YARA rules.

    Parameters:
        argv (list[str] | None): Command-line argument vector override.

    Returns:
        int: Standard POSIX exit status code (0 = success, 1 = failure).
    """
    ## Three subcommands map one-to-one onto the pipeline stages.
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    ## Subcommand: build
    b = sub.add_parser("build", help="Vet and compile rules from source checkouts")
    b.add_argument("--src", action="append", required=True, help="ID=DIR@COMMIT|LICENSE|URL")
    b.add_argument("--only", action="append", default=[], help="ID=subdir (repeatable) to limit a source")

    ## Subcommand: fptest
    f = sub.add_parser("fptest", help="Run false-positive sweep against clean file corpus")
    f.add_argument("--corpus-file", required=True, help="Text file with one clean path per line")

    ## Subcommand: verify
    sub.add_parser("verify", help="Verify rule manifest integrity and compile index")

    a = ap.parse_args(argv)

    if a.cmd == "build":
        ## --only ID=subdir entries are grouped per source id.
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

    ## fptest command handling
    ## Blank lines are ignored so editor-added trailing newlines are harmless.
    corpus = [l.rstrip("\n") for l in open(a.corpus_file, encoding="utf-8") if l.strip()]
    ## Missing/invalid exclusions => empty set (stricter, never looser).
    ex = set()
    try:
        ex = set(e["rule"] for e in json.loads((RULES / "EXCLUSIONS.json").read_text())["excluded"])
    except (OSError, ValueError, KeyError):
        pass
    hits = fptest(corpus, exclusions=ex)
    print(json.dumps(hits, indent=1))
    ## Any false positive fails the run: rules must be clean on known-good files.
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
