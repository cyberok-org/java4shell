# Technical analysis

## Defect and affected operation

The reviewed code is HotSpot's x86 `generate_base64_decodeBlock()` intrinsic,
called from `java.util.Base64.Decoder`. The source-level guard installed by
[JDK-8393212](https://github.com/openjdk/jdk27u/commit/564fc7de7effb8a4558604a6339f1b62f3017230)
routes a final fragment shorter than one complete Base64 unit to the Java fallback.
The campaign associated that change with Java4Shell through source and patch
analysis. CVE-2026-114938 is now officially listed by
[OpenJDK](https://openjdk.org/groups/vulnerability/advisories/2026-11-17) and
[Oracle](https://www.oracle.com/security-alerts/cspunov2026.html). Use supplier
advisories for affected packages and supported fixes; the campaign's source-level
association is not an official CVE-to-commit assignment.

The affected tail logic first derives the output count from complete four-character
units, then subtracts padding. A fragment shorter than a complete unit can begin
with zero output bytes; subtracting padding underflows the machine-sized count.
The subsequent mask construction enables all lanes rather than none. A vector
store then writes 64 bytes to the destination position.

**Store width is not the same as overflow length.** Some bytes can remain inside
the allocated destination. In the short default-allocation forms studied, 62 bytes
crossed the allocation boundary. The artifact descriptions occasionally used
"64-byte overflow" as shorthand; this pack distinguishes the two quantities.

The Java wrapper validates the ending after the intrinsic returns. Catching an
`IllegalArgumentException` therefore does not roll back the native write. A normal
HTTP authentication failure is compatible with already-corrupted memory.

An early source-read hypothesis was retracted during the campaign: the padding
reads are in bounds after the source offset adjustment. The established defect is
an **out-of-bounds write**, not the initially suspected out-of-bounds read.

## Why the processor restriction matters

The affected code is generated only for the appropriate x86 vector feature branch.
The critical requirements are AVX-512 **VBMI** plus **BW**; AVX2 or generic AVX-512
support is insufficient. Relevant hardware examples include Intel Ice Lake and
later compatible implementations and AMD Zen 4/5. Check actual guest-visible
features instead of deciding from a marketing name.

The JVM also gates installation/use of the intrinsic. `UseBASE64Intrinsics` has a
false declaration default in the reviewed source but can be enabled automatically
by CPU initialization. Reading the declaration alone led to a misleading early
assessment; inspect the **effective runtime value**. The campaign validated that
disabling Base64 intrinsics or restricting `UseAVX` to 2 prevented the observed
store on a capable lab host. A CPU inventory result on an incapable host is a
configuration check, not a separate dynamic exploitation experiment.

ARM/AArch64, a guest without the requisite feature exposure, OpenJ9 and GraalVM
Native Image do not execute this particular HotSpot x86 stub. This does not confer
immunity from other defects or from a different component decoding the same input.

## Decoder and input routing

Basic and URL decoders can reach the intrinsic; the reviewed MIME and streaming
paths do not. The vulnerable behavior concerns a malformed short padded final
fragment after accelerated block processing. Java 17's acceleration threshold
differs from the newer studied lines, so a test appropriate for one line cannot
automatically establish a negative result on another.

This defense pack contains no executable JVM exploit driver. Source-review
fixtures use abstract inputs; WAF tests generate synthetic malformed tokens for
pattern checks against a static server with no Java backend. Runtime inventory
does not invoke a decoder.

## Two destination-allocation patterns

### Caller-supplied destination

`decode(src, dst)` can write into an existing byte array. If `dst` is retained or
reused, another live object can be adjacent to it when the intrinsic runs. The
campaign's long-lived-buffer laboratory layout repeatedly corrupted the adjacent
array header, including its length. The broader campaign recorded 9/9 successes
across Serial and G1 configurations; the published fixed-build control subset
records three vulnerable, three mitigated and three fixed runs.

This is a practical reason to prioritize custom parsers, buffer pools and
thread-local scratch arrays. It is **not** proof that every two-argument call
will crash: capacity, object placement, JIT state and data flow still matter.
The audit did not identify this reused-destination form in the reviewed product
paths. That is a bounded search result, not a claim about all versions or plugins.

### Newly allocated destination

The ordinary one-argument array/String call allocates its destination immediately
before decoding. The overflow can land in unused thread-local allocation buffer
(TLAB) space. A later allocation may initialize that space and hide the corruption.
This explains why a real memory write need not produce a visible error or crash.

The store can also cross an allocation/region boundary or damage a live neighbor.
Garbage collector, heap occupancy, concurrency and allocation history change the
outcome. Consequently, **"quiet" describes an observed or plausible effect, not
a security boundary**. We publish no numeric per-request crash probability: simple
TLAB geometry estimates do not constitute a measured exploitation rate.

Exception-driven deoptimization can also remove the compiled fast path. Sending
many requests is not evidence that the vulnerable machine-code store executed
on every request. Product path reachability, compilation evidence and a confirmed
native store are different levels of observation.

## Denial of service and RCE

Corrupting JVM object headers can invalidate object layout and later crash the
process or garbage collector. The research supports a laboratory DoS scenario and
repeatable live-object corruption; the published control logs directly demonstrate
the latter. They do not establish reliable remote crashes of every listed product.

The observed output pattern is largely fixed. Full control over the first byte
and partial control over the next byte do not constitute an arbitrary 64-byte
write; in the ordinary allocation these initial bytes are in bounds. Our own
tests did not demonstrate end-to-end code execution.

That is a limit of our experiments, not an impact ceiling. In its
[public disclosure](https://calif.io/java4shell/), Calif reports composing the
corruption into information disclosure and application-specific RCE. Fresh output
arrays and initially quiet corruption are not protection against such chains.
See the [reported product/access list](../README.md#disclosure-update--2026-11-18).
We have not independently reproduced those chains and do not assign a new score.

## Why patching remains necessary

The CPU restriction materially reduces the exposed fleet, and allocation behavior
can make exploitation difficult. Neither changes the existence of a native write
past the Java allocation boundary. Fix the runtime, prioritize exposed services
and reported RCE targets, review custom reused-buffer paths, and verify the
runtime actually serving requests after restart.
Updating an OS JDK does not replace a bundled JDK in an application image.
