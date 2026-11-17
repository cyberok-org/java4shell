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

The typed-variable rule deliberately requires review of the factory: a variable
may hold `getMimeDecoder()`, which is not affected by this intrinsic. Direct MIME
calls, streaming wrappers and unrelated codec libraries are not direct-rule matches.
The rules do not claim that a field or a variable named `buf` proves buffer reuse.

For each finding determine:

1. Is this actually `java.util.Base64`, using Basic or URL decoding?
2. Can untrusted input reach it, and is it processed before authentication?
3. Is `dst` freshly allocated, retained in a field, pooled, or thread-local?
4. Are version, CPU and runtime-flag prerequisites present in deployment?
5. Is the supplier's security fix already backported to the deployed build?

Limitations: these are syntactic/local type-assisted candidates, not taint analysis.
Indirect wrappers, static imports, inferred receiver types and dependency bytecode
may be missed. The rules target Java; use the text-search helper for Kotlin.
No finding is a confirmed vulnerability solely because a rule matched.

The removed prototype rule for `Spring Base64Utils.decode(src, dst)` is **not**
included: the assumed two-argument API was not established. Library wrappers that
delegate one-argument decoding remain relevant but require ordinary call-graph review.

Tests: `semgrep --test --config semgrep tests/semgrep`.
Fixtures are inert snippets; they are never compiled or run.
