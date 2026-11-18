# CyberOK Defense Tools — Java4Shell

Defensive tooling and a technical assessment of the HotSpot Base64 decoding
memory-corruption issue tracked in our campaign as **Java4Shell / CVE-2026-114938**.

**Calif now reports application-specific remote code execution, including
unauthenticated attacks. Prompt remediation is warranted.** Exploitation of
this path requires an affected JVM, x86-64 with **AVX-512 VBMI and BW**, an enabled
intrinsic, and attacker-controlled data reaching the relevant decoder. Update
affected runtimes; prioritize exposed applications, reported RCE targets and
custom code with reused destination buffers.
There is no evidence here supporting a blanket shutdown of Java infrastructure.

This repository publishes **runtime inventory, source-review tools and passive
ModSecurity indicators**, not an
exploit or an active remote vulnerability probe. Our campaign reproduced memory
corruption and laboratory DoS; **we have not independently reproduced Calif's
product RCE chains**. See [evidence and limits](docs/EVIDENCE.md).

## Disclosure update — 2026-11-18

[Calif's technical disclosure](https://calif.io/java4shell/) reports RCE in default
application configurations, subject to the vulnerable JVM and CPU prerequisites:

| Reported access requirement | Products named by Calif |
| --- | --- |
| **Unauthenticated RCE** | Keycloak, Atlassian Jira, Atlassian Confluence, JFrog Artifactory, Jenkins, PingFederate |
| **Authenticated RCE** | Apache Kafka Broker, Apache Solr, Elasticsearch, Gerrit, Netflix Spinnaker |

Calif also reports RCE in example Spring Boot and Apache Struts applications.
Its publication includes technical analysis, a demonstration and a bounded local
PoC; product-specific exploit chains are withheld at this review snapshot.
There is no universal exploit: application-specific chains are required.
These are **Calif's reported results**, distinct from our own tests below.

Our pre-authentication Elasticsearch decoder finding does not establish pre-auth
RCE; Calif places Elasticsearch in its authenticated category. Tomcat's absence
from their list does not establish safety. Neither the disclosure nor our lab
results alone establish exploitation in the wild.

The CVE is now listed in the official
[OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
and [Oracle security update](https://www.oracle.com/security-alerts/cspunov2026.html).
See [vendor response and release status](docs/VENDOR-STATUS.md): an open PR,
a mitigation and a released product with a fixed runtime are different states.

## Products to prioritize for runtime updates: quiet sinks

**Do not wait for a crash before patching a reachable affected runtime.** The
campaign found JDK Base64 call paths in the products below. They use freshly
allocated output arrays: the memory write can be externally silent, and an
ordinary authentication error or healthy service does not establish safety.
"Quiet sink" names this allocation pattern; it does not guarantee a quiet outcome.

This is an **update-prioritization list**, conditional on the
[runtime prerequisites](#runtime-scope) and the named feature being reachable.
It does not mean every release or deployment of each product is exploitable.
The defect is in the JVM: a product update is sufficient only if it actually
replaces/fixes the runtime used by the service.

| Product / stack | Reviewed route to JDK Base64 | Evidence and scope |
| --- | --- | --- |
| **Apache Tomcat / TomEE** | Basic authentication; Tomcat also has HTTP/2 decoding paths | Tomcat switch: 9.0.89 / 10.1.23, also 11.x; TomEE 10.x/11 inherits newer Tomcat. Tomcat lab + source; TomEE dependency review |
| **Spring Boot applications using Spring Security** | Servlet HTTP Basic credential conversion before authentication | Security 5.8/6.x and reviewed main; Boot 3.2.5/Security 6.2.x lab. Not every Boot application enables HTTP Basic |
| **Elasticsearch** | Basic / API-key decoding; separate SAML IdP signature path | Basic lab on 8.11.4; other paths source-reviewed. Check the bundled or explicitly configured JDK |
| **Jetty, Jenkins, Solr, Zimbra** | Basic/authentication handling in product filters or the embedded container | Source-reviewed paths; Solr Basic must be configured, Zimbra entry concerns its Jetty path |
| **Jira / Confluence Data Center** | Seraph Basic credential decoding | Bytecode-reviewed Seraph 4.0.4/5.0.7/6.0.2; deployed JVM/version remains decisive |
| **Neo4j, SonarQube** | HTTP authentication parsing | Source-reviewed paths; version and feature details in the matrix |
| **Keycloak** | SAML artifact decoding | Campaign source record for the SAML artifact path; do not generalize the separate JWT-path negative result |
| **Openfire, Kafka, Apache James** | SASL initial response, SCRAM fields, or mail authentication decoding | Source-reviewed protocol paths; authentication mechanism and protocol state matter |
| **NiFi, ActiveMQ Classic** | Encoded proxied-entity handling; ActiveMQ web/REST authentication | Source-reviewed paths; not a claim about every messaging protocol |
| **JDK HTTP server / Jolokia JVM agent** | JDK `BasicAuthenticator` | Source-reviewed JDK path and Jolokia agent subclass; other Jolokia packaging differs |
| **Open Liberty** | HTTP/2 `HTTP2-Settings` decoding | Source-reviewed h2c path; this is distinct from the reviewed Basic-auth codec |

Library-level entry points also widen the update scope: **protobuf-java-util
4.33.0** JSON `bytes` parsing, **SnakeYAML** `!!binary`, **pac4j**, **Spring
Base64Utils**, **auth0 java-jwt 3.15.0+**, **fusionauth-jwt**, and the campaign's
reviewed **Quarkus, Micronaut, RESTEasy, Helidon and fastjson2** paths. Applications must
actually pass untrusted data through the named feature. Older protobuf and JWT
library versions can use different codecs; package presence alone is insufficient.

**Product-level runs:** the documented Elasticsearch, Tomcat and Spring Security
runs exercised decoding paths without an observed JVM crash. **Other entries:**
source, bytecode or dependency evidence, not a reproduced product DoS. No reused
destination-buffer call site was established in the audited product paths.

See the [full product/library matrix](docs/SURFACES.md) for named call sites,
version qualifications, negative paths and unresolved candidates. If a listed
path is reachable on an affected runtime, schedule the runtime update even when
normal monitoring is silent; use the verified interim mitigation if rollout must
wait. Review custom reused buffers urgently, without downgrading fresh-array paths
or the applications for which Calif reports RCE.

## Contents

| Component | Purpose |
| --- | --- |
| [Runtime inventory](safechecks/README.md) | Offline exports or a local diagnostic JVM; version, CPU features and effective flags; JSON output and explicit unknown results |
| [Semgrep rules](semgrep/README.md) | Ten Java rules for decoder inventory, destination size/lifetime review and Spring/protobuf/SnakeYAML entry points |
| [Lightweight source search](safechecks/scan-source.sh) | Optional ripgrep search for Java/Kotlin call sites, including multiline calls |
| [ModSecurity indicators](modsecurity/README.md) | Nine log-only HTTP detectors for selected malformed Base64 shapes; optional JSON parser setup, synthetic tests and explicit coverage limits |
| [Technical analysis](docs/ANALYSIS.md) | Root cause, CPU gating, allocation behavior, JIT effects and exploitation limits |
| [Surface matrix](docs/SURFACES.md) | Product/library paths, version caveats and evidence level |
| [Response guide](docs/RESPONSE.md) | Updates, verified interim JVM options, operational verification and telemetry |
| [Vendor status](docs/VENDOR-STATUS.md) | Dated advisory and PR checks; distinction between proposals, mitigations and verified shipped fixes |
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

For WAF integration, see the [ModSecurity deployment guide](modsecurity/README.md).
The supplied rules default to `pass + log`; they do not prove backend exposure or
replace the JVM update. JSON inspection requires phase-1 body/parser setup.

Inventory exit codes: **0** = modeled path excluded or mitigated, **1** = runtime
prerequisites present, **2** = unknown/incomplete. Exit 1 is not proof of network
reachability or exploitation. Exit 0 is scoped to this defect and the supplied
runtime evidence; it is not an assertion that the application is secure.

## What we established

- The accelerated decoder can write a full 64-byte vector at a short padded
  tail. Part of that store exceeds the destination allocation; the short forms
  studied produced up to 62 bytes beyond a normally allocated destination.
- A caller-supplied, long-lived destination made adjacent live-object corruption
  repeatable in the laboratory. This is an important custom-code review pattern.
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
vulnerable laboratory build. Oracle's advisory explicitly lists **8u511b33-perf**
as affected. This separate **8u-perf** lineage is not covered by the community-8
exclusion; the inventory deliberately returns unknown for that label and requires
manual vendor-build verification. Unknown does not mean unaffected.
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
2. Update to your supplier's fixed build and restart the affected processes;
   prioritize exposed services and the applications in Calif's RCE report.
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
CLI failure semantics, source-rule positives/negatives and the shipped WAF patterns.
The isolated ModSecurity test uses a static Apache server and no Java backend.
These checks do not execute the vulnerability. [Validation details](docs/VALIDATION.md).

## References

- [Calif: Java4Shell — Write once, RCE everywhere](https://calif.io/java4shell/)
- [OpenJDK vulnerability advisory, 2026-11-17](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
- [Oracle Critical Security Patch Update, November 2026](https://www.oracle.com/security-alerts/cspunov2026.html)
- [OpenJDK JDK-8393212 backport: Base64 optimization improvements](https://github.com/openjdk/jdk27u/commit/564fc7de7effb8a4558604a6339f1b62f3017230)
- [JDK 17u Base64 implementation](https://github.com/openjdk/jdk17u/blob/jdk-17.0.21-ga/src/java.base/share/classes/java/util/Base64.java)
- [JDK 17u x86 stub generator](https://github.com/openjdk/jdk17u/blob/jdk-17.0.21-ga/src/hotspot/cpu/x86/stubGenerator_x86_64.cpp)
- [OpenJDK vulnerability advisory index](https://openjdk.org/groups/vulnerability/advisories/)
- [Companion PHP defense-tool repository](https://github.com/scadastrangelove/php2shell)

---

(c) 2026 АО «Сайбер ОК» / JSC CyberOK. See [LICENSE](LICENSE) for the
copyright and usage notice. This repository follows the companion project's notice.
