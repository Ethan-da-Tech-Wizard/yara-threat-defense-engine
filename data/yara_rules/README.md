# Vetted YARA rules

Rules for `scripts/twu_scan.py`, kept in the repo so every box gets identical rules through Syncthing and can rebuild offline.
Nothing here is fetched at scan time. `MANIFEST.json` records source URL, pinned commit, license and the sha256 of every file;
`twu_scan.py status` re-checks the hashes on every run.

## Sources and licenses
| Source | Pinned commit | License | Used |
|---|---|---|---|
| https://github.com/Neo23x0/signature-base | de3c7252c22b3376352b5a68defa46459a12a693 | Detection Rule License 1.1 (MIT-like; keep author, link, license name when sharing) | 721 files (`yara/`) |
| https://github.com/reversinglabs/reversinglabs-yara-rules | e0a0be54aa1e11ccfd6854e4f19e9476f328fd84 | MIT | 308 files (`yara/`) |
| Yara-Rules/rules | 0f93570 | GPL-2.0 | NOT used: AGENTS.md refuses GPL-2.0-only |
| YARA-Forge | n/a | mixed per-rule | NOT used: release bundle, not one pinned license |

`local_selftest.yar` is our own EICAR rule (not in the vetted index; the vendored `SUSP_Just_EICAR` also catches EICAR).
Each vendor folder keeps its upstream LICENSE file.

## Vetting rules
A file is rejected if it fails `yarac`, imports a module outside pe/elf/math/hash/dotnet/macho, needs external variables
(the scanner supplies none), declares a global rule, includes other files, or repeats a rule name. The rejected list with reasons
is in `MANIFEST.json` (`rejected`). Rules that fire on clean files are disabled in `EXCLUSIONS.json` (scan time filter; vendored files stay byte-identical).

## Refresh (offline procedure, never automatic; PROPOSE-class action `update_yara_rules`)
1. Pick the new commit hash from the official GitHub repo and download only that: `curl -sSfL -o x.tgz https://codeload.github.com/<owner>/<repo>/tar.gz/<commit>`; unpack into an empty scratch folder.
2. Read the LICENSE again.
3. `python3 scripts/twu_yara_vet.py build --src "ID=DIR@COMMIT|LICENSE|URL" ... --only signature-base=yara --only reversinglabs=yara`
4. Build a clean-file list (system binaries, apps, python stdlib, repo scripts) and run `python3 scripts/twu_yara_vet.py fptest --corpus-file LIST`; add any rule that fires on a clean file to `EXCLUSIONS.json` with the reason.
5. `python3 scripts/twu_yara_vet.py verify` and `python3 scripts/twu_scan.py status`; run `python3 -m unittest scripts.test_twu_scan`.
Last false-positive run (2026-11-07, this Mac): 11,272 clean files, 0 hits outside this repo's own security-test fixtures; one rule disabled.
