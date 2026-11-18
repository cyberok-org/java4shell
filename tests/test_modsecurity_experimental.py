"""Opt-in HTTP coverage, using parsed values rather than whole-request matching."""
import json
from http.cookies import SimpleCookie
from pathlib import Path
import re
import unittest
from urllib.parse import parse_qs, quote

from test_modsecurity import json_values

CONFIG = Path(__file__).resolve().parents[1] / 'modsecurity/experimental-http.conf'


def cases():
    token = 'A' * 64 + '='
    url = '_' * 64 + '-_='
    # name, headers, body, request path, expected IDs with BOTH configs enabled
    return [
        ('query-literal', {}, '', '/synthetic?data=' + token, {11493811}),
        ('query-encoded', {}, '', '/synthetic?data=' + quote('/' * 64 + '=', safe=''), {11493811}),
        ('query-encoded-alphabet', {}, '', '/synthetic?data=' + '%41' * 64 + '%3D', {11493811}),
        ('query-duplicate', {}, '', '/synthetic?data=ordinary&data=' + token, {11493811}),
        ('query-name-only', {}, '', '/synthetic?' + token, set()),
        ('query-valid', {}, '', '/synthetic?data=' + 'A' * 66 + '==', set()),
        ('form-encoded', {'Content-Type': 'application/x-www-form-urlencoded'}, 'data=' + quote(url, safe=''), '/synthetic', {11493812}),
        ('form-duplicate', {'Content-Type': 'application/x-www-form-urlencoded'}, 'data=ordinary&data=' + token, '/synthetic', {11493812}),
        ('form-empty-value-name', {'Content-Type': 'application/x-www-form-urlencoded'}, 'A' * 64 + '=', '/synthetic', set()),
        ('form-valid', {'Content-Type': 'application/x-www-form-urlencoded'}, 'data=' + 'A' * 66 + '==', '/synthetic', set()),
        ('cookie-value', {'Cookie': 'lang=en; session=' + token + '; theme=dark'}, '', '/synthetic', {11493813}),
        ('cookie-empty-value-name', {'Cookie': 'A' * 64 + '=; lang=en'}, '', '/synthetic', set()),
        ('cookie-valid', {'Cookie': 'session=' + 'A' * 66 + '=='}, '', '/synthetic', set()),
        ('jwt-second-segment', {'Authorization': 'Bearer e30.' + url + '.c2ln'}, '', '/synthetic', {11493814}),
        ('jwt-third-segment', {'Authorization': 'Bearer e30.e30.' + url}, '', '/synthetic', {11493814}),
        ('jwt-valid', {'Authorization': 'Bearer e30.e30.c2ln'}, '', '/synthetic', set()),
        ('custom-token', {'X-Auth-Token': token}, '', '/synthetic', {11493815}),
        ('custom-apikey', {'X-Api-Key': url}, '', '/synthetic', {11493815}),
        ('custom-csrf', {'X-CSRF-Token': token}, '', '/synthetic', {11493815}),
        ('custom-unlisted-gap', {'X-Application-Token': token}, '', '/synthetic', set()),
        ('custom-valid', {'X-Auth-Token': 'A' * 66 + '=='}, '', '/synthetic', set()),
        ('text-whole-value', {'Content-Type': 'text/plain; charset=utf-8'}, token, '/synthetic', {11493816}),
        ('text-embedded-gap', {'Content-Type': 'text/plain'}, 'prefix ' + token, '/synthetic', set()),
        ('text-valid', {'Content-Type': 'text/plain'}, 'A' * 66 + '==', '/synthetic', set()),
        ('json-not-form', {'Content-Type': 'application/json'}, json.dumps({'data': token}), '/synthetic', {11493809}),
        ('json-escaped-remains-covered', {'Content-Type': 'application/json'}, json.dumps({'data': token}).replace('=', r'\u003d'), '/synthetic', {11493809}),
    ]


def read_patterns():
    text = CONFIG.read_text()
    ids = [int(value) for value in re.findall(r'id:(\d+)', text) if int(value) != 11493817]
    targets = [(var, rx) for var, rx in re.findall(r'SecRule\s+(\S+)\s+"@rx ([^"]+)"', text)
               if var != 'REQUEST_HEADERS:Content-Type']
    assert len(ids) == len(targets) == 6
    return [(sid, var, re.compile(rx.replace(r'\z', r'\Z')))
            for sid, (var, rx) in zip(ids, targets)]


def shape_matches(headers, body, path):
    headers = {k.lower(): v for k, v in headers.items()}
    result = set()
    for sid, var, regex in read_patterns():
        values = []
        if var == 'ARGS_GET':
            values = [v for vs in parse_qs(path.partition('?')[2], keep_blank_values=True).values() for v in vs]
        elif var == 'ARGS_POST' and headers.get('content-type', '').split(';')[0] == 'application/x-www-form-urlencoded':
            values = [v for vs in parse_qs(body, keep_blank_values=True).values() for v in vs]
        elif var == 'REQUEST_COOKIES':
            cookies = SimpleCookie(); cookies.load(headers.get('cookie', ''))
            values = [v.value for v in cookies.values()]
        elif var.startswith('REQUEST_HEADERS:'):
            values = [headers.get(part.split(':', 1)[1].lower(), '') for part in var.split('|')]
        elif var == 'REQUEST_BODY' and headers.get('content-type', '').split(';')[0] == 'text/plain':
            values = [body]
        if any(regex.search(v) for v in values):
            result.add(sid)
    return result


class ExperimentalModSecurityTests(unittest.TestCase):
    def test_patterns_and_routing(self):
        for name, headers, body, path, expected in cases():
            with self.subTest(case=name):
                self.assertEqual(shape_matches(headers, body, path), expected - {11493809})

    def test_opt_in_log_only_and_ids(self):
        text = CONFIG.read_text()
        self.assertEqual(sorted(map(int, re.findall(r'id:(\d+)', text))), list(range(11493811, 11493818)))
        self.assertEqual(text.count('pass,log,t:none'), 6)
        self.assertNotRegex(text, r'\b(?:deny|drop|block|capture|logdata):?[,\s]')
        core = (CONFIG.parent / 'CVE-2026-114938-java4shell.conf').read_text()
        self.assertNotIn('experimental-http.conf', core)
