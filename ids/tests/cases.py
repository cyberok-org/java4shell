"""Expected SID sets are explicit, independent of the rule regexes.

Upstream positives include broad anomaly indicators, not proven JVM triggers.
The pack cases are imported from the WAF tests to keep requests identical while
recording the engines' intentionally different coverage.
"""
import sys
from pathlib import Path

from upstream_fixtures import CASES, auth, req

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
from test_modsecurity import cases as core_cases
from test_modsecurity_experimental import cases as extended_cases


def sids(sid):
    return {'suricata': [9114938 if sid == 9114939 else sid], 'snort': [sid]} if sid else {'suricata': [], 'snort': []}


def case(name, group, request, sid=0, description='', gaps=(), splits=()):
    return {'id': name, 'group': group, 'request': request, 'expected': sids(sid),
            'description': description or name, 'known_gaps': list(gaps), 'splits': list(splits)}


def all_cases():
    upstream = {
        **{'S-P%02d' % n: 9114938 for n in range(1, 14)},
        'S-P08': 9114939, 'S-P13': 9114939,
        'S-Q01': 9114940, 'S-Q02': 9114940, 'S-J01': 9114941,
        'S-F01': 9114954, 'S-G02': 9114943, 'S-G03': 9114942,
        'R-auth-padded': 9114938, 'R-query-padded': 9114940,
        'R-body-padded': 9114954, 'P-text-body': 9114941,
        'G-auth-35': 9114938, 'G-auth-49': 9114938,
        'G-bearer-jwt-seg': 9114939, 'G-bearer-concat': 9114939,
        'H-att-scheme': 9114942, 'H-att-cookie': 9114943,
        'H-att-api': 9114942, 'H-att-kv': 9114942, 'H-att-token-url': 9114942,
    }
    result = []
    for name, group, expected, description, request in CASES:
        if expected is True and name not in upstream:
            raise ValueError('Missing explicit SID expectation: ' + name)
        result.append(case(name, 'upstream-reference' if expected is None else 'upstream-' + group,
                           request, upstream.get(name, 0), description))

    core = {
        **{name: 9114938 for name in ('basic-tail1', 'basic-tail2', 'basic-tail3',
           'basic-double-pad', 'basic-triple-pad', 'basic-two-pads-tail3', 'basic-17-floor',
           'basic-scheme-space', 'basic-below-floor', 'basic-wrong-block-residue')},
        'proxy-basic': 9114953, 'api-key': 9114950,
        'jwt-url-alphabet': 9114939, 'jwt-second-segment-gap': 9114939,
        'jwt-standard-alphabet-gap': 9114939,
        'nifi-double-wrapped': 9114951, 'nifi-multiple-elements': 9114951,
        'solr-v2-final-token': 9114952, 'solr-legacy-not-covered': 9114942,
        'json-basic': 9114941, 'json-url': 9114941, 'json-escaped': 9114941,
        'json-nested': 9114941, 'json-other-field': 9114941,
        'json-embedded-in-text': 9114941, 'text-body-not-covered': 9114941,
    }
    for name, headers, body, waf_expected in core_cases():
        gaps = ('suricata', 'snort') if name == 'json-escaped' else ()
        item = case('pack-' + name, 'pack-core', req('POST', '/synthetic', list(headers.items()), body),
                    core.get(name, 0), gaps=gaps)
        item['modsecurity_ids'] = sorted(waf_expected)
        result.append(item)

    extended = {
        'query-literal': 9114940, 'query-encoded': 9114940,
        'query-encoded-alphabet': 9114940, 'query-duplicate': 9114940,
        'form-encoded': 9114954, 'form-duplicate': 9114954,
        'cookie-value': 9114943, 'jwt-second-segment': 9114939,
        'jwt-third-segment': 9114939,
        'custom-token': 9114942, 'custom-apikey': 9114942,
        'custom-csrf': 9114942, 'custom-unlisted-gap': 9114942,
        'text-whole-value': 9114941, 'text-embedded-gap': 9114941,
        'json-not-form': 9114941, 'json-escaped-remains-covered': 9114941,
    }
    for name, headers, body, path, waf_expected in extended_cases():
        gaps = ('suricata', 'snort') if name in ('query-encoded-alphabet', 'json-escaped-remains-covered') else ()
        item = case('extended-' + name, 'pack-extended', req('POST', path, list(headers.items()), body),
                    extended.get(name, 0), gaps=gaps)
        item['modsecurity_ids'] = sorted(waf_expected)
        result.append(item)

    token = 'A' * 128 + '='
    request = auth('Basic ' + token)
    offset = request.index(token.encode())
    result.append(case('transport-split-basic', 'transport', request, 9114938,
                       splits=(offset + 63, offset + 128)))
    form = 'data=' + 'A' * 64 + '%3D'
    chunks = (form[:35], form[35:])
    body = ''.join('%x\r\n%s\r\n' % (len(c), c) for c in chunks) + '0\r\n\r\n'
    request = ('POST /synthetic HTTP/1.1\r\nHost: app.example.test\r\n'
               'Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n' + body).encode()
    result.append(case('transport-chunked-form', 'transport', request, 9114954))
    result.append(case('transport-split-nifi', 'transport',
                       req('GET', '/', [('X-ProxiedEntitiesChain', '<<' + token + '>>')]),
                       9114951, splits=(120, 160)))
    ids = [c['id'] for c in result]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate case IDs')
    return result
