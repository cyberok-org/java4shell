# Evidence, provenance and limits

Publication snapshot: **2026-11-18**. This is a curated report from the supplied
research campaign plus publication-time tests of the defensive tools. It is not
a claim that the vulnerability experiments were rerun while assembling this pack.

## Included control artifacts

The [evidence directory](../evidence/) contains selected version/VM, canary-result
and relevant flag lines from the campaign logs. Hostnames, account names, directory
paths, network details and unrelated output are not included. File hashes are
recorded in [manifest.json](../evidence/manifest.json).

The JDK 21 control pair used a capable AMD Zen 4 lab machine and a destination
array adjacent to a canary array. Three runs per configuration were recorded:

| Configuration | Result | Artifact |
| --- | --- | --- |
| Temurin 21.0.13+9, default intrinsic/AVX flags | Canary length corrupted, 3/3 | [vulnerable-default.txt](../evidence/vulnerable-default.txt) |
| Vulnerable build with Base64 intrinsic disabled | Canary length preserved, 3/3 | [vulnerable-intrinsic-disabled.txt](../evidence/vulnerable-intrinsic-disabled.txt) |
| Corretto build reporting Java 21.0.13.1, default flags | Canary length preserved, 3/3 | [fixed-default.txt](../evidence/fixed-default.txt) |

Both default configurations recorded `UseBASE64Intrinsics=true` and `UseAVX=3`:
[vulnerable flags](../evidence/vulnerable-flags.txt),
[fixed flags](../evidence/fixed-flags.txt). Campaign records identify the fixed
package as Corretto 21.0.13.1.2. The selected lines record the JVM's own version;
they do not independently authenticate a downloaded package or vendor signature.

The corrupted canary length in this subset is `0x9aa6699a`; the intact length is
`0x40`. Some earlier narrative notes transposed hex digits. The published logs
take precedence over prose. The canary results directly show adjacent-object
corruption, not execution of a system command or a product-level process crash.

**Limitations:** the fixed/vulnerable comparison is cross-vendor. Matching default
flags and the source guard strengthen the fix interpretation but do not make the
two binaries otherwise identical. A same-vendor pair is not included. The active
harness and trigger inputs are not part of this defensive release.

## Broader campaign observations

The campaign recorded a 64-byte tail store, repeatable live-neighbor corruption
in the reused-buffer layout (9/9 fresh JVMs across Serial/G1), and clean mitigation
controls for both Base64-intrinsic disabling and the AVX limit. Those broader logs
are not all included in this pack; the selected JDK 21 controls above are the
public, inspectable subset.

Product-level runs exercised Elasticsearch 8.11.4, Tomcat 11, Tomcat 9.0.89 and
Spring Boot 3.2.5 with Spring Security 6.2.x. The documented runs observed normal
error responses and no fatal-error file. Decode reachability and some JIT
compilation evidence were recorded. They do not prove that the native store ran
on every request or that a specific product can never crash.

A separate-session Elasticsearch crash was mentioned in later notes, but its
corroborating `hs_err` artifact was not supplied in the reviewed evidence set.
It is not counted as a verified product crash here. This is why the report says
"no crash in the documented runs", rather than "product DoS is impossible".

## Source evidence

The publication re-read the public
[JDK-8393212 backport commit](https://github.com/openjdk/jdk27u/commit/564fc7de7effb8a4558604a6339f1b62f3017230).
It adds the short-tail fallback guard to `generate_base64_decodeBlock()`.
The campaign had independently analyzed the Java caller and the x86 stub in
JDK 17u/21u snapshots and matched them to the observed store behavior.

Product matrix entries derive from the campaign's source/bytecode review. The
matrix distinguishes dynamic product work, static call sites and unresolved
candidates. It incorporates later corrections: protobuf 4.33.0 versus older Guava
paths; auth0 java-jwt 3.15.0 versus 3.14.0; unresolved Vert.x Basic evidence;
and the unestablished jmx_exporter inheritance claim.

## What this release does not establish

- An official CVE-to-JDK-fix assignment on behalf of the vendor.
- RCE, arbitrary 64-byte attacker control, or a practical exploit chain.
- A measured universal probability of crashing one-argument decoder call sites.
- A safe, decisive remote vulnerable/patched oracle.
- Exploitation in the wild, an IOC set, or attribution of crashes to this defect.
- Complete call-graph coverage across every listed product/version/plugin.
- Vendor availability or support policy for every JDK distribution.

## Publication hygiene

Only the explicitly selected evidence lines and newly prepared public tools/docs
are included. The original research notebook, lab scripts, target inventories,
credentials, private paths and host identifiers are excluded. Public repository
owner names and upstream author/product names are intentional attribution, not
laboratory environment identifiers. Git author metadata uses the repository owner's
public GitHub identity and account-specific noreply address rather than a local mailbox.
