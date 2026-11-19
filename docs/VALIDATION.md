# Validation of this publication

Checked on 2026-11-18; updated 2026-11-19 (five-part version strings, cached/`var` decoders and method references). These are defensive-tool and packaging checks, separate
from the vulnerability experiments summarized in [EVIDENCE.md](EVIDENCE.md).

| Check | Result |
| --- | --- |
| Python inventory/CLI, source-search and ModSecurity shape regression tests | 39 tests passed locally and in CI |
| IDS result validation | Five scorer regression tests passed, including wrong/extra SIDs, missing alerts, changed gaps, unknown flows and malformed output |
| Version-boundary subcases | Includes 17 introduction boundary, four fixed baselines, historical branches, vulnerable 25.0.4.1, Oracle's five-part last-affected builds and the unknown band before the fix baseline |
| Missing/contradictory evidence | Missing CPU/flags, unreadable exports and mixed CPU capabilities remain unknown |
| Mitigations / parsing | Both workaround flags, jcmd and PrintFlagsFinal forms, CPU spelling aliases and OpenJ9 distinction exercised |
| Diagnostic JVM environment | Java option variables removed from helper process; no target code or agent executed by tests |
| Source-search helper | Java/Kotlin, multiline calls, cached decoder fields, method references, MIME exclusion, whitespace in paths, no-match and missing-root exit codes passed |
| Semgrep 1.185.0 | All eleven rule test groups passed; positive/negative fixtures cover size boundaries, fields/names, typed and `var` receivers, cached decoder fields, method references, MIME exclusions/review aliases and library wrappers |
| ModSecurity shipped-pattern tests | 35 core cases, 26 additional opt-in cases, every length from 1 through 259, and 512 valid Base64/Base64url controls; patterns read from the published configs |
| Suricata / Snort engines | Both passed the 442-case offline PCAP suite against digest-pinned images; exact SID sets checked and three expected gaps recorded separately |
| Public source links | Tomcat, Spring Security, Elasticsearch, auth0 java-jwt and protobuf linked implementations fetched and decoder calls confirmed |
| Selected evidence | SHA-256 manifest verified against included log excerpts |
| Publication hygiene | Selected text/log files checked for lab hostnames, personal local paths, private address literals and common secret formats; public attribution retained |

Commands:

```bash
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s ids/tests -v
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

## ModSecurity engine check

The separate `modsecurity` CI job builds Debian Bookworm with Apache and
`libapache2-mod-security2`, checks the actual configuration syntax, and replays
the same 35 synthetic cases to a static server inside a container with
`--network none`, no published ports, a non-root user and all capabilities dropped.
It asserts expected rule IDs and unchanged HTTP status for the log-only policy.
No Java backend is present. Package versions are printed by the runner; raw request
and engine logs remain inside the disposable container. This is engine/connector
validation, not a product-exploitation test or a production false-positive study.

The core-only configuration passes 35 cases. With the optional HTTP extension,
61 cases pass, including query/form decoding, cookies, later JWT segments, selected
custom headers and plain-text bodies. Plain-text inspection requires the included
phase-1 `forceRequestBodyVariable` setup; a regex-only test did not establish that
the variable would exist on the real engine.

The tested packages are Apache `2.4.71-1~deb12u1` and ModSecurity
`2.9.7-1+deb12u2`. The optional JSON setup is exercised, including URL-safe values,
JSON escapes and nested fields. Legacy Solr headers remain outside the targeted
WAF rules. ModSecurity v3/nginx and other connectors are not tested by this job
and need deployment-specific verification.

## Experimental IDS engine checks

The [IDS module](../ids/README.md) retains 378 upstream synthetic cases and adds
35 core WAF cases, 26 optional WAF cases and three transport cases. Request bytes
from the upstream suite were preserved; descriptions were translated to English.
The generated PCAP uses documentation-only addresses and is never sent to a JVM.

| Engine | Expected indicators | Negative controls | Reference cases | Recorded gaps |
| --- | --- | --- | --- | --- |
| Suricata 7.0.17 | 75/75 exact SID sets | 358/358 no alerts | 6/6 expected results | 3 |
| Snort 3.10.0.0 | 75/75 exact SID sets | 358/358 no alerts | 6/6 expected results | 3 |

All 442 expectations passed on each engine. The three recorded gaps are two
escaped-JSON cases and one query with percent-encoded alphabet characters. The
corresponding parsed-value WAF cases pass. These gaps are not counted as detected
indicators; a changed gap makes the test fail until reviewed.

The engine runs use no network, no host mounts, no published ports and no Linux
capabilities. Suricata runs as its image's `suricata` account to read its supplied
configuration without granting root permission overrides. The runner checks both
process/container exit status and exact alert IDs, rather than accepting any
local-rule alert as success. TCP-split Basic/NiFi and chunked form cases pass.

[VALIDATION.json](../ids/VALIDATION.json) records versions, image digests, rule
hashes and counts for the checked snapshot. [engines.json](../ids/engines.json)
pins the tested images. CI uploads the full per-case JSON report. Results concern
synthetic indicator coverage, not successful exploitation, production false-positive
rates, exhaustive protocol parsing or throughput/regex-cost measurements.
