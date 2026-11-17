# CyberOK Defense Tools — Java4Shell

Defensive tooling and a technical assessment of the HotSpot Base64 decoding
memory-corruption issue tracked in our campaign as **Java4Shell / CVE-2026-114938**.

**The memory corruption is real. A laboratory denial-of-service scenario does
not imply that every Java service can be crashed on demand.** Exploitation of
this path requires an affected JVM, x86-64 with **AVX-512 VBMI and BW**, an enabled
intrinsic, and attacker-controlled data reaching the relevant decoder. Update
affected runtimes; prioritize exposed applications and reused destination buffers.
There is no evidence here supporting a blanket shutdown of Java infrastructure.

This repository publishes **runtime inventory and source-review tools**, not an
exploit or an active remote vulnerability probe. RCE is **not demonstrated by
our evidence**. The link between the tracked CVE and JDK-8393212 was inferred
from source and patch analysis; do not mistake this repository for an official
CNA/vendor advisory. See [evidence and limits](docs/EVIDENCE.md).

## Contents

| Component | Purpose |
| --- | --- |
| [Runtime inventory](safechecks/README.md) | Offline exports or a local diagnostic JVM; version, CPU features and effective flags; JSON output and explicit unknown results |
| [Semgrep rules](semgrep/README.md) | Java Basic/URL decoder inventory and caller-supplied-buffer review candidates |
| [Lightweight source search](safechecks/scan-source.sh) | Optional ripgrep search for Java/Kotlin call sites, including multiline calls |
| [Technical analysis](docs/ANALYSIS.md) | Root cause, CPU gating, allocation behavior, JIT effects and exploitation limits |
| [Surface matrix](docs/SURFACES.md) | Product/library paths, version caveats and evidence level |
| [Response guide](docs/RESPONSE.md) | Updates, verified interim JVM options, operational verification and telemetry |
| [Evidence](docs/EVIDENCE.md) | Sanitized control logs, provenance, supported conclusions and open questions |

## Quick start

Python 3.9+ is sufficient for the inventory tool; it has no third-party dependencies.

```bash
# Inspect a trusted Java binary in a NEW diagnostic JVM (not a running service).
python3 safechecks/inventory_j4s.py --java /path/to/jdk/bin/java --json

# Offline assessment: all three exports must come from the same target environment.
python3 safechecks/inventory_j4s.py \
  --version-file /path/to/exports/version.txt \
  --cpuinfo /path/to/exports/cpuinfo.txt \
  --flags-file /path/to/exports/flags.txt --json

# Synthetic example: expected exit code 1 (runtime prerequisites present).
python3 safechecks/inventory_j4s.py \
  --version-file examples/version.txt --cpuinfo examples/cpuinfo.txt \
  --flags-file examples/flags.txt --json

# Review your source. Semgrep is an optional, separately installed dependency.
semgrep scan --config semgrep/java4shell.yaml --metrics=off /path/to/source

# Java/Kotlin text search without Semgrep; requires rg (ripgrep).
bash safechecks/scan-source.sh /path/to/source
```

Inventory exit codes: **0** = modeled path excluded or mitigated, **1** = runtime
prerequisites present, **2** = unknown/incomplete. Exit 1 is not proof of network
reachability or exploitation. Exit 0 is scoped to this defect and the supplied
runtime evidence; it is not an assertion that the application is secure.

## What we established

- The accelerated decoder can write a full 64-byte vector at a short padded
  tail. Part of that store exceeds the destination allocation; the short forms
  studied produced up to 62 bytes beyond a normally allocated destination.
- A caller-supplied, long-lived destination made adjacent live-object corruption
  repeatable in the laboratory. This is the priority code pattern to review.
- Common product call sites use a newly allocated destination. Corruption can be
  externally silent because the store may land in unused allocation space.
  **No visible crash does not mean no corruption, and does not prove safety.**
- Product-level paths were exercised in Elasticsearch, Tomcat and Spring
  Security laboratory configurations without an observed crash in those runs.
  Static call-site evidence for other products is labeled separately.
- The fixed JDK 21 control and the disabled-intrinsic control preserved the
  adjacent canary; the vulnerable default control corrupted it, three runs each.
- Both `-XX:-UseBASE64Intrinsics` and `-XX:UseAVX=2` prevented the observed store
  in the campaign's mitigation checks.

## Runtime scope

The following is the **campaign's version model**, not a replacement for your
JDK supplier's advisory or backport records:

| HotSpot line | Modeled affected releases | Fix baseline used by this pack |
| --- | --- | --- |
| 17 | 17.0.6 through releases before 17.0.21.1 | 17.0.21.1 |
| 21 | 21.0.0 through releases before 21.0.13.1 | 21.0.13.1 |
| 25 | 25.0.0 through releases before 25.0.5.1 | 25.0.5.1 |
| 27 | 27.0.0 through releases before 27.0.1.1 | 27.0.1.1 |
| 18/19/20/22/23/24/26 | Historical affected non-LTS lines | Verify supplier backports or migrate |
| Community 8 / 11 | Investigated upstream trees lack the affected decode intrinsic | Outside this mechanism |

**A fourth version component alone does not mean fixed:** 25.0.4.1 was a
vulnerable laboratory build. Oracle's separate **8u-perf** lineage needs vendor
confirmation; the inventory deliberately returns unknown for that label.
Custom builds and backports require package/vendor evidence beyond a version string.

Hardware requirements are real: AVX-512 alone is insufficient; the vulnerable
branch requires VBMI **and** BW visible to the JVM. ARM/AArch64 and AVX2-only
environments do not enter this branch. VM/cloud CPU masking matters. OpenJ9 and
GraalVM Native Image do not use this HotSpot intrinsic; a GraalVM **JVM** distribution
must not be confused with a native image.

Only the JDK Basic/URL decoding paths are in scope. `getMimeDecoder()` and the
streaming `wrap(InputStream)` route do not use the affected path in the reviewed
implementation. A product using another Base64 codec is not automatically affected
through that codec.

## Actions

1. Inventory the actual service JVM, including bundled JDKs and container images.
2. Update to your supplier's fixed build and restart the affected processes.
3. If an update is pending, evaluate `-XX:-UseBASE64Intrinsics`; check the effective
   setting in the service after restart. Measure performance on your workload.
4. Review untrusted-input paths and especially `decode(src, dst)` with reused
   destination arrays. A source-rule finding needs manual data-flow review.
5. Use operational telemetry for investigation, not as a vulnerability oracle.
   This pack does not ship a remote trigger, crash scanner or a claim of a reliable
   exploit-attribution signature. [Response details](docs/RESPONSE.md).

## Validation

```bash
python3 -m unittest discover -s tests -v
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  .venv/bin/semgrep --test --config semgrep tests/semgrep
```

The tests exercise classification boundaries, missing evidence, mitigation flags,
CLI failure semantics and source-rule positives/negatives. They do not execute
the vulnerability. [Validation details](docs/VALIDATION.md).

## References

- [OpenJDK JDK-8393212 backport: Base64 optimization improvements](https://github.com/openjdk/jdk27u/commit/564fc7de7effb8a4558604a6339f1b62f3017230)
- [JDK 17u Base64 implementation](https://github.com/openjdk/jdk17u/blob/jdk-17.0.21-ga/src/java.base/share/classes/java/util/Base64.java)
- [JDK 17u x86 stub generator](https://github.com/openjdk/jdk17u/blob/jdk-17.0.21-ga/src/hotspot/cpu/x86/stubGenerator_x86_64.cpp)
- [OpenJDK vulnerability advisory index](https://openjdk.org/groups/vulnerability/advisories/)
- [Companion PHP defense-tool repository](https://github.com/scadastrangelove/php2shell)

---

(c) 2026 АО «Сайбер ОК» / JSC CyberOK. See [LICENSE](LICENSE) for the
copyright and usage notice. This repository follows the companion project's notice.
