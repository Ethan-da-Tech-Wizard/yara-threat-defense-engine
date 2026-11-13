# YARA Threat Defense Engine

This Python project explores combining YARA rule matching and ClamAV scanning with event-driven scanning and rule-management utilities. The repository includes scripts, tests, and an indexed collection of third-party rules.

**Status:** Experimental security tooling. A scan with no matches is not proof that a file is safe. Results depend on scanner availability, permissions, rule and signature coverage, configuration, and the files actually scanned. The project's security and failure-handling claims have not been independently verified in this review.

## Requirements

The project metadata declares Python 3.10 or newer. Scanning and rule checks depend on separately installed YARA and ClamAV tools and their rule/signature data; Python package metadata alone does not install those engines. Review [the rule inventory and licensing notes](data/yara_rules/README.md) before using or redistributing rules.

## Use

From the repository root, inspect the commands and scanner status:

```sh
python3 scripts/twu_scan.py --help
python3 scripts/twu_scan.py status
python3 scripts/twu_scan.py scan /path/to/target --json
python3 scripts/twu_yara_vet.py verify
```

Additional event and removable-media options are available through `python3 scripts/twu_scan_event.py --help`. The scanner also exposes signature-update commands; inspect the help and understand the network and system effects before applying updates.

Run the repository's unit tests with:

```sh
python3 -m unittest scripts/test_twu_scan.py scripts/test_twu_yara_vet.py scripts/test_twu_scan_event.py
```

These commands are drawn from the source and previous documentation and were not run in this review. A test result applies only to the specific cases and environment tested. Partial scans, skipped files, timeouts, missing tools, and scan errors need separate attention.

## Explore

[Scanner](scripts/twu_scan.py) · [Event scanner](scripts/twu_scan_event.py) · [Rule vetting](scripts/twu_yara_vet.py) · [Rule inventory](data/yara_rules/README.md) · [Tests](scripts/)

## License

Project code is distributed under the [MIT License](LICENSE). Vendored YARA rules retain their respective upstream licenses and attribution requirements; see the [rule inventory](data/yara_rules/README.md) and the licenses in the vendor directories. YARA, ClamAV, and other tools also have separate terms.
