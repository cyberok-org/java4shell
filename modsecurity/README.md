# ModSecurity: passive HTTP indicators

[`CVE-2026-114938-java4shell.conf`](CVE-2026-114938-java4shell.conf) contains
**nine log-only detectors**, IDs **11493801–11493809**. They recognize selected
malformed Base64/base64url shapes at HTTP entry points. A match is an investigation
signal, **not proof of an affected JVM, successful memory corruption or exploitation**.
The rules make no requests and do not decode Base64 in the WAF.

## Coverage

| ID | Variable / route | Scope |
| --- | --- | --- |
| 11493801–03 | `Authorization: Basic` | Padded tails of one, two or three characters after complete 64-character blocks |
| 11493804 | `Proxy-Authorization: Basic` | Same Basic alphabet and length shape |
| 11493805 | `Authorization: ApiKey` | Elasticsearch-style credential token shape |
| 11493806 | `Authorization: Bearer` | First JWT segment only, using the URL-safe alphabet; two following nonempty unpadded segments |
| 11493807 | `X-ProxiedEntitiesChain` | NiFi double-wrapped encoded element, including one within a chain |
| 11493808 | `SolrAuthV2` | Final space-delimited signature token; verified parser uses the JDK Basic decoder |
| 11493809 | Parsed JSON `ARGS` values | Basic or URL-safe whole-value shape; only when `REQBODY_PROCESSOR` is JSON |

The modeled shape is complete 64-character blocks followed by a malformed padded
tail of 1–3 characters. The minimum is 65 characters for the newer studied JDK
lines. The rules intentionally also flag lengths below JDK 17's 129-character
threshold: the WAF cannot infer which JVM receives a request. For a verified
17-only backend you can raise the block repetition from `+` to `{2,}` in a local
copy and retest; this pack does not supply a separate 17-only configuration.

Valid Base64 tokens do not satisfy the anchored patterns. This does **not** imply
zero operational false positives: broken clients, fuzzing, security tests and a
JSON field that merely contains similar text can match without an affected decoder.
Correlate with the [runtime inventory](../safechecks/README.md) and application path.

## Deployment

Merge the include into your existing ModSecurity policy. Choose paths that exist
on your WAF and check for rule-ID collisions before reloading it.

```apache
# Keep your existing engine, audit, parser-error and body-limit policies.
# Rules need SecRuleEngine On or DetectionOnly to run.

# Optional: only if your policy does not already enable/select the JSON processor.
Include /etc/modsecurity/java4shell/json-body-setup.conf

Include /etc/modsecurity/java4shell/CVE-2026-114938-java4shell.conf
```

[`json-body-setup.conf`](json-body-setup.conf) enables request-body access and
selects the JSON processor for `application/json` / `application/*+json` in phase 1,
using setup ID **11493810**. This changes body parsing, so reuse your existing
JSON setup when present. Retain appropriate body-size/depth limits and handling
for parser errors and truncated requests. Include the setup before the detectors.

The JSON detector checks decoded scalar values, including escaped/nested JSON,
not raw-body text or JSON member names. Restrict its `ARGS` target to the actual
Base64-bearing fields where your API schema permits. The raw `REQUEST_BODY`
variable is not a portable substitute for parsed JSON values, and enabling body
access in phase 2 is too late. See the [ModSecurity reference manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29).

Header rules run in phase 1; the JSON rule runs in phase 2. Every detector uses
`pass,log,t:none` and does not add CRS anomaly scores. They do not disable other
rules or override your existing blocking policy. Start with this log-only mode;
any later blocking policy should be evaluated against your application's traffic
and field semantics. These indicators are not a complete virtual patch.

## Logging and privacy

The rule messages contain fixed descriptions and IDs, with no `capture` or
`logdata` action. That does **not** sanitize an existing WAF's audit/debug logs:
its policy may record credentials, request headers or JSON bodies. Review audit
parts, redaction, log access and retention on the actual engine/connector before
deployment. No production request samples, lab account names or host identifiers
are included here. The test runner prints only synthetic case names and rule IDs.

## Coverage limits

- This pack does not cover every input path. JWT segments after the first, alternate
  token layouts, YAML, HTTP/2 settings/priority fields, SAML, non-HTTP Kafka/SASL,
  SMTP/IMAP and arbitrary application-specific encodings need separate handling.
- `X-Solr-Certificate` is not covered by the SolrAuthV2 rule. Its legacy processing
  was not verified here. Likewise, the JWT rule does not assert a Keycloak JWT sink.
- Header duplication, normalization and intermediary/backend parsing differences
  depend on the connector. Test with your deployment, including request limits.
- JSON escaping is handled by the selected parser; unsupported encodings, parser
  errors, omitted bodies and truncation can prevent inspection. A negative result
  is not evidence that the service is safe.
- Header whitespace handling is limited to horizontal spaces/tabs around the
  scheme/token. No URL decoding or other transformations are applied to headers.
- The engine cannot observe JVM build, CPU feature exposure, effective flags,
  JIT state or whether an application reaches a decoder. Update the runtime even
  if no alert or crash has appeared.

## Changes from the prepared draft

The publication preserves the nine detector IDs and log-only intent, with these
corrections: use 64-character blocks rather than a broader four-character-unit
condition; use the URL alphabet for JWT; recognize NiFi's encoded-element wrapper;
match the verified `SolrAuthV2` token boundary instead of an arbitrary suffix of
`X-Solr-Certificate`; inspect parsed JSON values after phase-1 setup; and correct
the hardware requirement to AVX-512 **VBMI + BW**. Tests read the shipped rule file
so the checked patterns cannot silently drift from the published configuration.

## Reproduce the checks

```bash
# Pattern/control tests; no third-party Python dependencies and no JVM execution.
python3 -m unittest discover -s tests -p 'test_modsecurity.py' -v

# Actual Apache/ModSecurity checks against a static server inside one container.
# Build downloads Debian packages. The test run has no external network or host ports.
docker build -f tests/modsecurity/Dockerfile -t java4shell-modsecurity-test .
docker run --rm --network none --cap-drop ALL \
  --security-opt no-new-privileges java4shell-modsecurity-test
```

The engine test loads the real configuration and sends only synthetic transactions
to container loopback. There is no Java application, public listener or vulnerable
backend. The test cases include intentional coverage gaps and clean padded Base64
to distinguish detector behavior from an exploitation claim. See
[validation details](../docs/VALIDATION.md) for the tested engine and limits.
