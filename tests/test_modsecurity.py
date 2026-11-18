"""Read the shipped PCRE patterns; exercise synthetic data without any JVM."""
import base64
import json
from pathlib import Path
import re
import unittest

CONFIG = Path(__file__).resolve().parents[1] / 'modsecurity/CVE-2026-114938-java4shell.conf'


def cases():
    basic = 'A' * 64 + 'BC='
    url = '_' * 64 + '-_='
    # name, headers, raw body, expected detector IDs
    return [
        ('basic-tail1', {'Authorization': 'Basic ' + 'A' * 64 + '='}, '', {11493801}),
        ('basic-tail2', {'Authorization': 'Basic ' + 'A' * 64 + 'B='}, '', {11493802}),
        ('basic-tail3', {'Authorization': 'Basic ' + basic}, '', {11493803}),
        ('basic-double-pad', {'Authorization': 'Basic ' + 'A' * 64 + '=='}, '', {11493802}),
        ('basic-triple-pad', {'Authorization': 'Basic ' + 'A' * 64 + '==='}, '', {11493803}),
        ('basic-two-pads-tail3', {'Authorization': 'Basic ' + 'A' * 64 + 'B=='}, '', {11493803}),
        ('basic-17-floor', {'Authorization': 'Basic ' + 'A' * 128 + '='}, '', {11493801}),
        ('basic-scheme-space', {'Authorization': 'bAsIc\t ' + basic + '  '}, '', {11493803}),
        ('proxy-basic', {'Proxy-Authorization': 'Basic ' + basic}, '', {11493804}),
        ('api-key', {'Authorization': 'ApiKey ' + basic}, '', {11493805}),
        ('jwt-url-alphabet', {'Authorization': 'Bearer ' + url + '.e30.c2ln'}, '', {11493806}),
        ('nifi-double-wrapped', {'X-ProxiedEntitiesChain': '<<' + basic + '>>'}, '', {11493807}),
        ('nifi-multiple-elements', {'X-ProxiedEntitiesChain': '<CN=sample><<' + basic + '>><CN=proxy>'}, '', {11493807}),
        ('solr-v2-final-token', {'SolrAuthV2': 'node sample 123 ' + basic}, '', {11493808}),
        ('json-basic', {'Content-Type': 'application/json'}, json.dumps({'data': basic}), {11493809}),
        ('json-url', {'Content-Type': 'application/problem+json; charset=utf-8'}, json.dumps({'data': url}), {11493809}),
        ('json-escaped', {'Content-Type': 'application/json'}, json.dumps({'data': basic}).replace('=', r'\u003d'), {11493809}),
        ('json-nested', {'Content-Type': 'application/json'}, json.dumps({'outer': {'data': basic}}), {11493809}),
        ('json-other-field', {'Content-Type': 'application/json'}, json.dumps({'description': basic}), {11493809}),
        ('basic-below-floor', {'Authorization': 'Basic ' + 'A' * 60 + '='}, '', set()),
        ('basic-wrong-block-residue', {'Authorization': 'Basic ' + 'A' * 68 + '='}, '', set()),
        ('basic-valid-padding', {'Authorization': 'Basic ' + 'A' * 66 + '=='}, '', set()),
        ('basic-valid-single-pad', {'Authorization': 'Basic ' + 'A' * 67 + '='}, '', set()),
        ('basic-url-alphabet-rejected', {'Authorization': 'Basic ' + url}, '', set()),
        ('basic-invalid-middle', {'Authorization': 'Basic ' + 'A' * 32 + '!' + 'A' * 31 + '='}, '', set()),
        ('jwt-second-segment-gap', {'Authorization': 'Bearer e30.' + url + '.c2ln'}, '', set()),
        ('jwt-standard-alphabet-gap', {'Authorization': 'Bearer ' + '/' * 64 + 'BC=.e30.c2ln'}, '', set()),
        ('nifi-single-wrapper-not-encoded', {'X-ProxiedEntitiesChain': '<' + basic + '>'}, '', set()),
        ('nifi-valid-encoded', {'X-ProxiedEntitiesChain': '<<' + 'A' * 66 + '==>>'}, '', set()),
        ('solr-valid-signature', {'SolrAuthV2': 'node sample 123 ' + 'A' * 66 + '=='}, '', set()),
        ('solr-legacy-not-covered', {'X-Solr-Certificate': 'node ' + basic}, '', set()),
        ('json-valid-value', {'Content-Type': 'application/json'}, json.dumps({'data': 'A' * 66 + '=='}), set()),
        ('json-key-only', {'Content-Type': 'application/json'}, json.dumps({basic: 'ordinary'}), set()),
        ('json-embedded-in-text', {'Content-Type': 'application/json'}, json.dumps({'data': 'prefix ' + basic}), set()),
        ('text-body-not-covered', {'Content-Type': 'text/plain'}, basic, set()),
    ]


def read_patterns(path=CONFIG):
    text = path.read_text()
    matches = re.findall(r'SecRule\s+(\S+)\s+"@rx ([^"]+)"', text)
    assert len(matches) == 9, 'Expected eight header patterns plus one JSON value pattern'
    return [(11493801 + n, variable, re.compile(pattern.replace(r'\z', r'\Z')))
            for n, (variable, pattern) in enumerate(matches)]


def json_values(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from json_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from json_values(item)
    elif isinstance(value, str):
        yield value


def shape_matches(patterns, headers, body):
    found = set()
    for rule_id, variable, regex in patterns:
        if variable.startswith('REQUEST_HEADERS:'):
            values = [v for k, v in headers.items() if k.lower() == variable.split(':', 1)[1].lower()]
        elif 'json' in headers.get('Content-Type', ''):
            values = list(json_values(json.loads(body)))
        else:
            values = []
        if any(regex.search(value) for value in values):
            found.add(rule_id)
    return found


class ModSecurityShapeTests(unittest.TestCase):
    def test_shipped_patterns_against_cases(self):
        patterns = read_patterns()
        for name, headers, body, expected in cases():
            with self.subTest(case=name):
                self.assertEqual(shape_matches(patterns, headers, body), expected)

    def test_every_length_residue(self):
        patterns = read_patterns()
        for length in range(1, 260):
            with self.subTest(length=length):
                token = 'A' * (length - 1) + '='
                expected = length >= 65 and length % 64 in (1, 2, 3)
                self.assertEqual(bool(shape_matches(patterns, {'Authorization': 'Basic ' + token}, '')), expected)

    def test_valid_base64_corpus(self):
        patterns = read_patterns()
        for size in range(1, 513):
            raw = bytes((i * 31 + size) % 256 for i in range(size))
            token = base64.b64encode(raw).decode()
            url = base64.urlsafe_b64encode(raw).decode().rstrip('=')
            headers = {'Authorization': 'Basic ' + token, 'Proxy-Authorization': 'Basic ' + token,
                       'X-ProxiedEntitiesChain': '<<' + token + '>>',
                       'SolrAuthV2': 'node sample 123 ' + token}
            with self.subTest(size=size):
                self.assertFalse(shape_matches(patterns, headers, ''))
                self.assertFalse(shape_matches(patterns, {'Authorization': 'Bearer ' + url + '.e30.c2ln'}, ''))

    def test_log_only_actions_and_unique_ids(self):
        text = CONFIG.read_text()
        ids = re.findall(r'id:(\d+)', text)
        self.assertEqual(len(ids), 9)
        self.assertEqual(len(set(ids)), 9)
        self.assertEqual(text.count('pass,log,t:none'), 9)
        self.assertNotRegex(text, r'\b(?:deny|drop|block|capture|logdata):?[,\s]')


if __name__ == '__main__':
    unittest.main()
