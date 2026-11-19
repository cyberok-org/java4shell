# Runtime inventory and source search

## Inventory modes

`inventory_j4s.py` uses only the Python standard library and makes no network
requests. It does not generate Base64 input, attach to a JVM, modify configuration,
enumerate remote hosts or scan listening services.

### Offline exports (preferred for running services)

Collect version, CPU and effective flags from the **same service environment**.
For example, an operator can save the service's startup version/build details,
`/proc/cpuinfo` from its container/VM, and `jcmd <pid> VM.flags -all` output using
the appropriate account. `jcmd` is a separate operator action, not run by this tool.
Use `jcmd <pid> VM.version` or deployment metadata to cross-check that an installed
binary's version really matches the running process. The parser accepts normal
`java -version`/modern `java --version` text, not arbitrary deployment JSON.

```bash
python3 safechecks/inventory_j4s.py --version-file version.txt \
  --cpuinfo cpuinfo.txt --flags-file flags.txt --json
```

Both `PrintFlagsFinal` assignments and `jcmd` `-XX:` forms are supported. `VM.flags`
without `-all` can omit default settings: missing values return unknown, rather
than assuming the vulnerable default. Missing/unreadable explicit files return
unknown with exit 2. An empty or unrecognized CPU export is not a negative result.

For ARM exports where no CPU-feature file is available, use `--arch aarch64` or
`--arch arm64`. Otherwise the tool never substitutes the analysis workstation's
architecture for the remote/exported host's architecture. Feature masking by the
hypervisor must be reflected in the export.

### Trusted local binary

```bash
python3 safechecks/inventory_j4s.py --java /opt/jdk/bin/java --json
```

This executes a **new JVM** with `-XX:+PrintFlagsFinal -version`. It is not an
assessment of an existing service's options. The helper removes `JAVA_TOOL_OPTIONS`,
`JDK_JAVA_OPTIONS` and `_JAVA_OPTIONS` from the child environment to avoid implicitly
loading agents or applying unrelated application options; removed variable names
are listed, never their values. It still executes the binary you supply: use only
a trusted installed JVM. Offline mode executes no Java.

Local CPU collection supports Linux `/proc/cpuinfo` and macOS `sysctl`; unsupported
or unreadable feature sources remain unknown. Native Windows can use offline
exports. CPU collection is about this host, not every host in a cluster.

## Results and automation

| Verdict | Exit | Meaning |
| --- | --- | --- |
| `potentially_exposed` | 1 | Modeled version, CPU and effective flags satisfy runtime prerequisites; application reachability and patch provenance still need review |
| `not_affected` | 0 | A modeled prerequisite is excluded or the version is in the fixed range |
| `mitigated` | 0 | Supplied effective flags disable the affected path; runtime still needs updating |
| `unknown` | 2 | Missing, contradictory or unsupported evidence, or collection failure |

JSON includes the version classification, CPU status, parsed flags and collection
scope. There is no automatic fleet discovery; invoke once per exported runtime and
retain unknown results in your remediation queue. Runtime names/paths need not be
sent to any service. All version logic is visible in `FIXED` and `version_status`.

Limitations: custom security backports, vendor-specific versioning, locally modified
JVMs, CPU migration after collection, stale files and unrecognized early-access
builds cannot be resolved by string inspection. The historical version model does
not establish vendor support policy. An Oracle 8u-perf label remains unknown to
this classifier; [Oracle's advisory](https://www.oracle.com/security-alerts/cspunov2026.html)
explicitly lists 8u511b33-perf as affected. Manually verify this separate lineage;
the unknown result and community OpenJDK 8 exclusion do not clear it.

## Lightweight Java/Kotlin search

```bash
bash safechecks/scan-source.sh /path/to/source
```

Requires `rg` (ripgrep). It prints Basic/URL decoder calls, every Basic/URL decoder
acquisition (`getDecoder()` / `getUrlDecoder()`, so cached fields and method
references are listed even though their later `decode(x)` calls carry no factory
name) and two-argument `.decode` candidates with file/line context. It does not compile or execute target code.
Exit codes follow ripgrep: 0 matches, 1 no matches, 2 error/incomplete scan.
Normal ignore files and hidden-file exclusions apply; pass `--hidden` and/or
`--no-ignore` after the root if you deliberately need broader coverage.

This is a text search: comments, strings and unrelated decoders may match; aliases,
wrappers, generated/archived code and complex argument expressions can be missed.
It does not prove receiver type, buffer reuse, or network reachability. Semgrep
provides a narrower Java review path; neither tool is a complete data-flow analysis.
