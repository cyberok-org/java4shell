# Validation of this publication

Checked on 2026-11-18. These are defensive-tool and packaging checks, separate
from the vulnerability experiments summarized in [EVIDENCE.md](EVIDENCE.md).

| Check | Result |
| --- | --- |
| Python inventory/CLI and source-search regression tests | 28 tests passed locally |
| Version-boundary subcases | Includes 17 introduction boundary, four fixed baselines, historical branches and vulnerable 25.0.4.1 |
| Missing/contradictory evidence | Missing CPU/flags, unreadable exports and mixed CPU capabilities remain unknown |
| Mitigations / parsing | Both workaround flags, jcmd and PrintFlagsFinal forms, CPU spelling aliases and OpenJ9 distinction exercised |
| Diagnostic JVM environment | Java option variables removed from helper process; no target code or agent executed by tests |
| Source-search helper | Java/Kotlin, multiline calls, whitespace in paths, no-match and missing-root exit codes passed |
| Semgrep 1.185.0 | All three rule test groups passed with positive/negative annotated Java fixtures |
| Public source links | Tomcat, Spring Security, Elasticsearch, auth0 java-jwt and protobuf linked implementations fetched and decoder calls confirmed |
| Selected evidence | SHA-256 manifest verified against included log excerpts |
| Publication hygiene | Selected text/log files checked for lab hostnames, personal local paths, private address literals and common secret formats; public attribution retained |

Commands:

```bash
python3 -m unittest discover -s tests -v
SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  semgrep --test --config semgrep tests/semgrep
bash -n safechecks/scan-source.sh
```

The optional source-search tests are skipped if ripgrep is unavailable. Install
`rg` to exercise them. Python tests ran on Python 3.15.2; Semgrep ran in an isolated
Python 3.12 environment. The workflow uses Python 3.12 and installs ripgrep.

On this macOS host, Semgrep needed `SSL_CERT_FILE` pointing to an installed CA
bundle even for local tests. No certificate verification was disabled. The CLI's
test runner also required `--config semgrep` (directory); passing the individual
rule file with a separate fixture directory hit a runner path-handling exception.
The documented directory form passed.

Not covered: a clean-application false-positive corpus, exhaustive Kotlin parsing,
interprocedural taint analysis, package-signature/backport attestation, Windows
binary probing, or new exploitation runs against deployed products. This pack's
tests never execute attack fixtures, contact target services or modify a JVM.
