# Technical analysis

## Defect and affected operation

The reviewed code is HotSpot's x86 `generate_base64_decodeBlock()` intrinsic,
called from `java.util.Base64.Decoder`. The source-level guard installed by
[JDK-8393212](https://github.com/openjdk/jdk27u/commit/564fc7de7effb8a4558604a6339f1b62f3017230)
routes a final fragment shorter than one complete Base64 unit to the Java fallback.
The campaign associated that change with the reported Java4Shell CVE. The observed
memory defect and the official CVE-to-patch assignment are distinct claims: the
former is backed by the local control results, while the latter needs the supplier's
advisory as the authoritative reference.

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

This defense pack intentionally contains no trigger generator or exploit driver.
The source-review fixtures are calls with abstract inputs, not malicious byte
sequences. Runtime inventory does not invoke a decoder.

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

The observed output pattern is largely fixed. The campaign's corrected analysis
gave full control over the first byte and partial control over the next byte, not
an arbitrary 64-byte write. No arbitrary pointer construction or end-to-end code
execution was demonstrated. This limitation must not be turned into a proof that
RCE is impossible. We do not assign a new CVSS score or borrow a CPU-wide maximum
as if it were an official score for this specific defect.

## Why patching remains necessary

The CPU restriction materially reduces the exposed fleet, and allocation behavior
can make exploitation difficult. Neither changes the existence of a native write
past the Java allocation boundary. Fix the runtime, review custom reused-buffer
paths first, and verify the runtime actually serving requests after restart.
Updating an OS JDK does not replace a bundled JDK in an application image.
