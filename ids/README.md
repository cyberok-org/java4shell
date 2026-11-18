# Experimental IDS indicators: Suricata and Snort 3

**Opt-in, alert-only network indicators.** These rules identify selected malformed
Base64 shapes in visible HTTP traffic. They do not determine JVM version, CPU
features, decoder reachability, memory corruption or successful exploitation.
They are not a virtual patch. Keep the runtime update as the remediation.

## Source and adaptation

Based on [jsik22/java4shell-detection](https://github.com/jsik22/java4shell-detection),
reviewed at [e7d3ddb969b93799e6d31e13da5b300590e8f01a](https://github.com/jsik22/java4shell-detection/tree/e7d3ddb969b93799e6d31e13da5b300590e8f01a).
The original rules, synthetic request cases and PCAP construction are used under
the [MIT license](LICENSE), with attribution retained. This directory, including
our adaptations, is separately licensed under MIT; the repository's general
notice does not override that license.

Adaptations include dedicated ApiKey, proxy Basic, NiFi and Solr indicators;
separate form-value handling; exclusion of JSON member names from the body
heuristic; a Basic-auth alphabet restricted to standard Base64 (Bearer retains
URL-safe handling); English fixture descriptions; exact-SID assertions; explicit gap
accounting; and additional cases shared with our ModSecurity tests. The imported
request shapes are test data, not validated product exploit chains.

## Rules and scope

| SID | Route | Qualification |
| --- | --- | --- |
| 9114938 | Authorization Basic; Suricata also uses this SID for Bearer | Broad malformed-padding indicator |
| 9114939 | Authorization Bearer, Snort only | Includes JWT segments, not just the first |
| 9114940 | Raw query parameter values | Recognizes literal padding and selected URL encodings |
| 9114941 | Non-form request body, HUNT | Text/JSON heuristic, not a JSON parser; excludes recognizable JSON member names |
| 9114942 | Other request headers, HUNT | Excludes standard headers and the separately handled product headers |
| 9114943 | Cookie values, HUNT | Distinguishes values from empty-value cookie names |
| 9114950 | Authorization ApiKey | JDK Basic-alphabet shape used by this pack |
| 9114951 | NiFi `X-ProxiedEntitiesChain` | Double-wrapped encoded elements |
| 9114952 | `SolrAuthV2` | Final signature token |
| 9114953 | Proxy-Authorization Basic | JDK Basic-alphabet shape |
| 9114954 | URL-encoded form values, HUNT | Keeps empty-value form names out of the generic body heuristic |

The inherited HUNT/authentication patterns start at a **32-character prefix** and
work in four-character groups. This intentionally includes anomalies below the
intrinsic's modeled input threshold and lengths outside its 64-character block
shape. The four product-specific SIDs 9114950–9114953 use the narrower block
shape from our WAF pack. Neither family is an exploit-success detector. HUNT
rules can alert on text an application never Base64-decodes; valid Base64 controls
in a synthetic corpus do not establish a production false-positive rate.

The local SID range is not globally assigned. Check for collisions with existing
rules. Load only the file for your engine:

- [Suricata rules](rules/suricata/java4shell.rules)
- [Snort 3 rules](rules/snort3/java4shell.rules)

Follow the engine's existing ruleset inclusion mechanism and validate its complete
configuration before deployment. Start with alerts and a limited monitored scope;
review field semantics before considering any blocking policy. Do not enable all
HTTP body logging just to investigate these indicators.

## Reproducible offline regression

From the repository root, with Python 3.9+ and Docker:

```bash
python3 -m unittest discover -s ids/tests -v
python3 ids/tests/run.py --report ids-results.json
```

The runner acquires the digest-pinned images in [engines.json](engines.json), generates a PCAP
locally, and runs both engines with `--network none`, no host mounts, no published
ports, dropped capabilities and `no-new-privileges`. It never sends the synthetic
requests to a Java application. Image acquisition needs registry access; the
engines process only the generated file. The tested platform is Linux amd64.

The suite retains 378 upstream cases and adds this pack's core/experimental WAF
requests plus TCP-split and chunked-transfer cases. Every case has explicit
per-engine SID expectations. Wrong or extra SIDs, missing alerts, false positives
on negative controls, engine failures and changes to recorded gaps fail the run.
Reference cases are counted separately from positive/negative indicators.

The JSON report records engine versions, image digests, rule hashes, exact SID
results and gaps. CI publishes that report as an artifact. See
[validation results](../docs/VALIDATION.md#experimental-ids-engine-checks) and
[VALIDATION.json](VALIDATION.json) for the reviewed snapshot: Suricata 7.0.17 and
Snort 3.10.0.0 each passed 442 expectations, with 75 expected indicators, 358
negative controls, six reference cases and three explicitly recorded gaps.

## Known limits

- JSON escapes such as escaped padding are not decoded by these regexes. The
  parsed-JSON ModSecurity rule handles the tested case instead.
- Raw-URI matching recognizes `%2B`, `%2F` and `%3D`, not arbitrary percent-encoded
  alphabet characters. Parsed query inspection in the optional WAF rules covers
  the tested encoded-alphabet case.
- These differences are recorded as explicit IDS gaps in the shared cases, not
  counted as successful detections. A previously missed case starting to alert
  requires review and an expectation update.
- TLS must be terminated/decrypted at an authorized observation point. Encrypted
  traffic is not made inspectable by installing these rules.
- HTTP/2, upgraded WebSockets, multipart file contents, compressed bodies, parser
  limits, duplicate-header ambiguities and non-HTTP protocols are not validated
  by this suite. One segmented and one chunked route are not exhaustive parser
  differential tests.
- No production traffic corpus or withheld Calif RCE chain was tested. An alert
  is an investigation lead; no alert does not clear a deployment.

For application source review and deployment gates, use the [Semgrep](../semgrep/README.md)
and [runtime inventory](../safechecks/README.md) tools alongside these indicators.
