# Response and operational verification

## Prioritization

Start with services on an affected runtime and VBMI+BW-capable hardware that decode
untrusted Basic/URL Base64. Prioritize custom code that reuses destination arrays,
internet-facing or cross-trust-boundary decoding, and bundled runtimes that would
not be replaced by a host OS update. Authentication does not protect a parser that
runs before credential verification.

An excluded CPU path changes the priority for this defect. It does not mean the
runtime should stop receiving security updates. Record guest CPU features and
reassess if instances migrate to another hardware class.

## Apply the runtime fix

Obtain a fixed build from the runtime/product supplier. The pack models the
17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 baselines. Vendor-specific backports
need vendor/package evidence; a version-only rule cannot validate them. Do not
infer that every non-LTS branch is permanently unfixable: supplier support differs.

Rebuild/redeploy container images as needed, replace embedded JDKs through a
supported product update, restart the service, and verify the build of the running
process. Checking a shell's default `java` is not sufficient.

## Interim mitigations verified in the campaign

| JVM option | Effect | Operational consideration |
| --- | --- | --- |
| `-XX:-UseBASE64Intrinsics` | Disable accelerated Base64 intrinsics | Narrower change; benchmark Base64-heavy workloads |
| `-XX:UseAVX=2` | Exclude AVX-512 paths more broadly | Can affect unrelated optimized operations; broader performance impact |

Apply the option through the service's documented JVM-option mechanism and
restart. These options apply to the JVM receiving them, not every process on the
host. Inspect effective flags in that process, using operator-approved diagnostic
tools such as `jcmd <pid> VM.flags -all`. Some JVM releases require unlocking
diagnostic options before accepting a particular flag; check startup errors and
the actual value instead of assuming an option was applied.

The inventory's `--java` mode launches a separate JVM and intentionally ignores
inherited Java option variables. Use same-process exported flags when assessing
an existing service's mitigation. A mitigation is not a security update.

## Source triage

Semgrep findings are candidates. Trace decoder construction, input provenance and
destination lifetime. A field, pool-like name or two arguments alone does not prove
that a live adjacent object will be damaged. Fresh destinations do not remove the
defect; they can make its effect less visible.

The safe correction is a patched runtime. Changing application allocation patterns
solely to make crashes harder is not a complete remediation. Merely catching decode
exceptions also fails to undo a write that has already occurred.

## Telemetry and network detection limits

Unexpected JVM exits, fatal-error files (`hs_err_pid*.log`), collector crashes and
bursts of decoder/authentication errors can support investigation. They are
**nonspecific**: malformed credentials and unrelated JVM defects produce similar
events. Preserve timestamps, runtime build/options and relevant request metadata
with your normal data-handling controls. Avoid collecting credentials merely to
enable a detection rule.

The reviewed product paths often returned ordinary 401 responses without a
fatal-error file. A 401, successful health check or absence of `hs_err` is not proof
that no write occurred. A reported Elasticsearch crash from a separate campaign
session lacked the corroborating fatal-error artifact in the reviewed publication
inputs; this repository does not count it as an independently verified result.

Unlike the PHP companion pack, this release does not claim validated Suricata,
Sigma, WAF or Nuclei signatures for exploitation. Blocking all long Base64 values
or every value ending in padding would reject legitimate traffic and miss other
entry points. A pattern-only alert cannot establish JVM version, CPU capabilities,
JIT execution or memory corruption. No validated PCAP-based detector accompanies
this release.

Active trigger-based checks can themselves corrupt process memory. Use the passive
inventory and code-review tools for deployment assessment. The tools in this pack
do not send traffic or attempt a denial of service.
