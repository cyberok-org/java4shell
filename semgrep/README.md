# Java source-review rules

```bash
semgrep scan --config semgrep/java4shell.yaml --metrics=off /path/to/source
```

Use `--json` or `--sarif` for integration. By default Semgrep reports matches without
failing the process; use `--error` if your review policy requires findings to produce
a nonzero exit status. Install the tested version from `requirements-dev.txt` when
reproducing these checks. Rules run locally; disable metrics as above.

| Rule | Severity | Intended use |
| --- | --- | --- |
| `java4shell-two-argument-decode` | WARNING | Direct JDK Basic/URL call with caller-supplied destination, fresh or reused |
| `java4shell-decoder-variable-review` | WARNING | Typed `Base64.Decoder` receiver with two arguments; trace its factory and lifetime |
| `java4shell-one-argument-inventory` | INFO | Direct JDK Basic/URL one-argument call, including fresh-destination surfaces |
| `java4shell-inline-large-buffer-review` | WARNING | Inline destination with a statically evaluable size above 1024 bytes; capacity-review heuristic |
| `java4shell-inline-buffer-review` | WARNING | Inline fresh destination of any size, including unknown/dynamic sizes |
| `java4shell-field-destination-review` | WARNING | Qualified destination field such as `this.data` or `owner.data`; review lifetime |
| `java4shell-buffer-name-review` | WARNING | Destination name suggesting a buffer, pool, cache, thread-local or shared storage; review reuse |
| `java4shell-spring-base64utils-inventory` | INFO | Spring's one-argument `decode` / `decodeFromString` wrappers |
| `java4shell-protobuf-json-review` | WARNING | Protobuf JSON parser `merge`; verify library version and reachable `bytes` fields |
| `java4shell-snakeyaml-load-review` | WARNING | SnakeYAML `load`; verify constructor behavior and reachable `!!binary` tags |

There are **ten rules**. The original three IDs are retained for existing
integrations. Additional review rules intentionally overlap: a large inline
destination can produce the generic, inline and large-buffer findings for one
call. Group by location when triaging; findings are not independent vulnerabilities.
Severity indicates review category, not an exploitability rating. In particular,
an INFO inventory match is not evidence that a fresh-array path has low impact.

The typed-variable rule deliberately requires review of the factory: a variable
may hold `getMimeDecoder()`, which is not affected by this intrinsic. Direct MIME
calls, streaming wrappers and unrelated codec libraries are not direct-rule matches.
The destination heuristics use the same direct-factory or typed-receiver scope;
they do not match every method named `decode` or infer a decoder type from its
variable name. The rules do not claim that a field or a variable named `buf`
proves buffer reuse. Typed MIME aliases remain review candidates in these rules
as well; trace the factory before treating them as affected paths.

The **1024-byte cutoff is only a triage heuristic**, inherited from the supplied
rule update. It is not the vulnerable input threshold, a safe capacity boundary
or proof of a deterministic write. Smaller and dynamic arrays still match the
general inline rule. Compare destination capacity with the logical output length:
an oversized array may contain the native write within its allocation while bytes
beyond the intended output change. Application impact requires evidence about
subsequent reads, retained references and exception handling. Inline allocation
alone establishes none of those conditions.

Wrapper findings also need review. The protobuf decoder path was verified in
`protobuf-java-util` 4.33.0; reviewed 4.32.0/3.25.x implementations use Guava.
`merge` without reachable `bytes` fields does not establish Base64 exposure.
SnakeYAML requires a constructor that accepts `!!binary`; custom constructors
may differ. See the [version-qualified surface matrix](../docs/SURFACES.md).

For each finding determine:

1. Is this actually `java.util.Base64`, using Basic or URL decoding?
2. Can untrusted input reach it, and is it processed before authentication?
3. Is `dst` freshly allocated, retained in a field, pooled, or thread-local?
4. How does capacity compare with logical output, and can altered bytes be read
   after a decode exception? Is any neighboring live object actually at risk?
5. Are version, CPU and runtime-flag prerequisites present in deployment?
6. Is the supplier's security fix already backported to the deployed build?

Limitations: these are syntactic/local type-assisted candidates, not taint analysis.
Indirect wrappers, static imports, inferred receiver types and dependency bytecode
may be missed. The rules target Java; use the text-search helper for Kotlin.
No finding is a confirmed vulnerability solely because a rule matched.
The wrapper inventory is not exhaustive: Spring URL-safe helper methods,
unresolved fluent protobuf parser chains, SnakeYAML `loadAll`/`loadAs` and
application-specific wrappers need separate review. A clean scan does not clear
the application or its runtime.

The removed prototype rule for `Spring Base64Utils.decode(src, dst)` is **not**
included: the assumed two-argument API was not established. The new Spring rule
checks the real one-argument wrappers instead.

Tests: `semgrep --test --config semgrep tests/semgrep`.
Fixtures are inert snippets; they are never compiled or run.
Positive and negative fixtures cover all ten rules, the 1024/1025 capacity boundary,
dynamic sizes, typed decoder variables, MIME aliases requiring review, and
unrelated codecs/classes that must not match.
