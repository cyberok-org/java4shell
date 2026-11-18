# Copyright (c) 2026 jsik22. Adapted under the MIT license in ../LICENSE.
# Source: jsik22/java4shell-detection@e7d3ddb969b93799e6d31e13da5b300590e8f01a
# English descriptions; original request bytes and PCAP helpers retained.
"""Synthetic PCAP fixtures adapted from jsik22/java4shell-detection (MIT). No network I/O. True means an expected indicator, not confirmed exploitation; None is a reference case."""
import base64
import json
import random
import struct
import sys
from urllib.parse import quote
random.seed(114938)
B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
A = 'A'

def rnd(n, alpha=B64):
    return ''.join((random.choice(alpha) for _ in range(n)))

def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def req(method, path, headers, body=''):
    r = f'{method} {path} HTTP/1.1\r\nHost: app.example.test\r\nUser-Agent: fixtures/1.0\r\nAccept: */*\r\n'
    for k, v in headers:
        r += f'{k}: {v}\r\n'
    if body:
        r += f'Content-Length: {len(body.encode())}\r\n'
    return (r + '\r\n' + body).encode()

def auth(v, path='/api/v1/resource'):
    return req('GET', path, [('Authorization', v)])
JWT = '.'.join([b64url(b'{"alg":"HS256","typ":"JWT"}'), b64url(json.dumps({'sub': 'user-1234', 'name': 'Test User', 'iat': 1763424000}).encode()), b64url(bytes((random.getrandbits(8) for _ in range(32))))])
CASES = [
    ('S-P01', 'synthetic', True, 'Basic 64-character prefix and malformed padding', auth('Basic ' + A * 64 + '=')),
    ('S-P02', 'synthetic', True, 'Basic 128-character prefix and malformed padding', auth('Basic ' + A * 128 + '=')),
    ('S-P03', 'synthetic', True, "Basic A*64+'B='", auth('Basic ' + A * 64 + 'B=')),
    ('S-P04', 'synthetic', True, "Basic A*64+'BC='", auth('Basic ' + A * 64 + 'BC=')),
    ('S-P05', 'synthetic', True, "Basic A*64+'B=='", auth('Basic ' + A * 64 + 'B==')),
    ('S-P06', 'synthetic', True, "Basic A*64+'=='", auth('Basic ' + A * 64 + '==')),
    ('S-P07', 'synthetic', True, "Basic A*64+'==='", auth('Basic ' + A * 64 + '===')),
    ('S-P08', 'synthetic', True, "Bearer A*64+'='", auth('Bearer ' + A * 64 + '=')),
    ('S-P09', 'synthetic', True, 'Lowercase header and scheme', req('GET', '/', [('authorization', 'basic ' + A * 64 + '=')])),
    ('S-P10', 'synthetic', True, 'Short anomaly: 32-character prefix', auth('Basic ' + A * 32 + '=')),
    ('S-P11', 'synthetic', True, 'Random 96-character prefix', auth('Basic ' + rnd(96) + '=')),
    ('S-P12', 'synthetic', True, 'Two spaces after scheme', auth('Basic  ' + A * 64 + '=')),
    ('S-P13', 'synthetic', True, 'URL-safe Bearer anomaly', auth('Bearer ' + rnd(64, B64[:62] + '-_') + '-=')),
    ('S-N01', 'synthetic', False, 'Valid two-character padding', auth('Basic ' + A * 64 + 'BC==')),
    ('S-N02', 'synthetic', False, 'Valid single padding', auth('Basic ' + A * 64 + 'BCD=')),
    ('S-N03', 'synthetic', False, 'Unpadded 64-character token', auth('Basic ' + A * 64)),
    ('S-N04', 'synthetic', False, 'Short valid Basic credentials', auth('Basic ' + base64.b64encode(b'user:pass').decode())),
    ('S-N05', 'synthetic', False, 'Long valid Basic credentials', auth('Basic ' + base64.b64encode(b'service-account@example.test:Very-Long-Passw0rd-2026!!').decode())),
    ('S-N06', 'synthetic', False, 'JWT Bearer', auth('Bearer ' + JWT)),
    ('S-N07', 'synthetic', False, 'Opaque unpadded Bearer token', auth('Bearer ' + rnd(40, B64[:62]))),
    ('S-N08', 'synthetic', False, 'Digest authentication', auth('Digest username="u", realm="r", nonce="' + rnd(48, B64[:62]) + '=", uri="/", response="' + rnd(32, '0123456789abcdef') + '"')),
    ('S-N09', 'synthetic', False, 'Valid Base64 form body', req('POST', '/upload', [('Content-Type', 'application/x-www-form-urlencoded')], 'f=' + quote(base64.b64encode(bytes(range(200))).decode(), safe=''))),
    ('S-N10', 'synthetic', False, 'Valid Base64 JSON body', req('POST', '/api', [('Content-Type', 'application/json')], json.dumps({'file': base64.b64encode(bytes(range(150))).decode()}))),
    ('S-N11', 'synthetic', False, 'Valid Base64 query', req('GET', '/d?b=' + quote(base64.b64encode(bytes(range(97))).decode(), safe=''), [])),
    ('S-Q01', 'synthetic', True, 'Query with literal padding', req('GET', '/d?b=' + A * 64 + '=', [])),
    ('S-Q02', 'synthetic', True, 'Query with URL-encoded padding', req('GET', '/d?x=1&b=' + A * 64 + '%3D', [])),
    ('S-J01', 'synthetic', True, 'JSON value with malformed padding', req('POST', '/api', [('Content-Type', 'application/json')], json.dumps({'file': A * 64 + '='}))),
    ('S-F01', 'synthetic', True, 'Form value with URL-encoded padding', req('POST', '/f', [('Content-Type', 'application/x-www-form-urlencoded')], 'data=' + A * 64 + '%3D&x=1')),
    ('S-N12', 'synthetic', False, 'Valid URL-encoded SAML form', req('POST', '/sso/acs', [('Content-Type', 'application/x-www-form-urlencoded')], 'SAMLResponse=' + quote(base64.b64encode(bytes((random.getrandbits(8) for _ in range(301)))).decode(), safe='') + '&RelayState=%2Fhome')),
    ('S-N13', 'synthetic', False, 'Valid padded data URI in JSON', req('POST', '/api/avatar', [('Content-Type', 'application/json')], json.dumps({'img': 'data:image/png;base64,' + base64.b64encode(bytes((random.getrandbits(8) for _ in range(500)))).decode()}))),
    ('S-N14', 'synthetic', False, 'Ordinary login form', req('POST', '/login', [('Content-Type', 'application/x-www-form-urlencoded')], 'username=alice&password=S3cr3t%3D%3D&remember=1')),
    ('S-N15', 'synthetic', False, 'Hex signature query without padding', req('GET', '/file?X-Amz-Signature=' + rnd(64, '0123456789abcdef') + '&X-Amz-Expires=300', [])),
    ('S-N16', 'synthetic', False, 'Ordinary static path and query', req('GET', '/static/js/app.min.js?v=' + rnd(40, '0123456789abcdef') + '&lang=ko', [])),
    ('S-N17', 'synthetic', False, 'Valid ViewState form', req('POST', '/page.aspx', [('Content-Type', 'application/x-www-form-urlencoded')], '__VIEWSTATE=' + quote(base64.b64encode(bytes((random.getrandbits(8) for _ in range(149)))).decode(), safe='') + '&btn=OK')),
    ('S-N18', 'synthetic', False, 'JWT and UUID in JSON', req('POST', '/api/refresh', [('Content-Type', 'application/json')], json.dumps({'token': JWT, 'id': '00000000-0000-4000-8000-0000000a4b2f'}))),
    ('S-G01', 'synthetic', None, 'Short reference outside indicator floor', auth('Basic ' + A * 28 + '=')),
    ('S-G02', 'synthetic', True, 'Cookie anomaly', req('GET', '/', [('Cookie', 'session=' + A * 64 + '=')])),
    ('S-G03', 'synthetic', True, 'Custom-header anomaly', req('GET', '/', [('X-Auth-Token', A * 64 + '=')])),
]
CTRL = base64.b64encode(b'probe').decode()
SLASH130 = '/' * 128 + '=='
SLASH128 = '/' * 126 + '=='
for label, val, expect in [('control', CTRL, False), ('padded', SLASH130, True), ('badtail', SLASH128, None)]:
    src = 'r3dvei1/java4shell RemoteAttack'
    CASES.append((f'R-auth-{label}', 'poc-shape', expect, f'{src} auth {label}', req('GET', '/d', [('Authorization', 'Basic ' + val)])))
    CASES.append((f'R-query-{label}', 'poc-shape', expect, f'{src} query {label}', req('GET', '/d?b=' + quote(val, safe=''), [])))
    CASES.append((f'R-body-{label}', 'poc-shape', expect, f'{src} form body {label}', req('POST', '/d', [('Content-Type', 'application/x-www-form-urlencoded')], 'b=' + quote(val, safe=''))))
CASES.append(('P-text-body', 'poc-shape', True, "Pwned-test/cve-2026-114938-java17-PoC POST text/plain A*128+'='", req('POST', '/probe', [('Content-Type', 'text/plain')], A * 128 + '=')))
SRC_G = 'Ghost-Bx1/java-exploits'
CASES.append(('G-auth-35', 'poc-shape', True, f'{SRC_G} public request shape: 35-character Basic token', req('GET', '/', [('Authorization', 'Basic ' + A * 34 + '=')])))
CASES.append(('G-auth-49', 'poc-shape', True, f'{SRC_G} public request shape: 49-character Basic token', req('GET', '/', [('Authorization', 'Basic ' + A * 48 + '=')])))
CASES.append(('G-bearer-jwt-seg', 'poc-shape', True, f'{SRC_G} public request shape: anomaly in middle JWT segment', req('GET', '/api/v1/', [('Authorization', 'Bearer eyJhbGciOiJIUzI1NiJ9.' + A * 32 + '=.fakesig')])))
CASES.append(('G-bearer-concat', 'poc-shape', True, f'{SRC_G} public request shape: concatenated Bearer token', req('GET', '/api/', [('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' + A * 34 + '=')])))
CASES.append(('G-spray-32', 'poc-shape', None, f'{SRC_G} reference: valid unpadded token, not a trigger assertion', req('GET', '/', [('Authorization', 'Basic ' + A * 32)])))
CASES.append(('G-spel-junk', 'poc-shape', None, f'{SRC_G} reference: non-Base64 prefix, no trigger assertion', req('GET', '/', [('Authorization', 'Basic dXNlcjoke{T(x)}' + A * 32 + '=')])))
CASES.append(('S-N19', 'synthetic', False, 'Valid three-segment JWT', auth('Bearer ' + JWT)))
REAL = [
    ('H-cookie-jsess', [('Cookie', 'JSESSIONID=' + rnd(32, '0123456789ABCDEF') + '; lang=ko')]),
    ('H-cookie-b64', [('Cookie', 'session=' + base64.b64encode(bytes(range(48))).decode() + '; theme=dark')]),
    ('H-cookie-b64pad', [('Cookie', 'state=' + base64.b64encode(bytes(range(50))).decode() + '; a=1')]),
    ('H-cookie-uuid', [('Cookie', '00000000-0000-4000-8000-0000000a4b2f=11111111-2222-4333-8444-555555555555; SESSIONID=' + rnd(32, '0123456789ABCDEF'))]),
    ('H-cookie-jwt', [('Cookie', 'id_token=' + JWT)]),
    ('H-ws-key', [('Upgrade', 'websocket'), ('Connection', 'Upgrade'), ('Sec-WebSocket-Key', base64.b64encode(bytes(range(16))).decode()), ('Sec-WebSocket-Version', '13')]),
    ('H-req-id', [('X-Request-ID', '7f1c2a4e-9b3d-4e8a-a1f0-3c5d6e7f8a9b')]),
    ('H-traceparent', [('traceparent', '00-' + rnd(32, '0123456789abcdef') + '-' + rnd(16, '0123456789abcdef') + '-01')]),
    ('H-etag', [('If-None-Match', 'W/"' + rnd(40, '0123456789abcdef') + '"')]),
    ('H-csrf', [('X-CSRF-Token', rnd(43, B64[:62] + '-_'))]),
    ('H-sig', [('Signature', 'sig1=:' + base64.b64encode(bytes(range(64))).decode() + ':'), ('Signature-Input', 'sig1=("@authority");created=1700000000;keyid="' + rnd(43, B64[:62] + '-_') + '";tag="web-bot-auth"')]),
    ('H-digest', [('Digest', 'sha-256=' + base64.b64encode(bytes(range(32))).decode())]),
    ('H-amz', [('X-Amz-Security-Token', base64.b64encode(bytes(range(200))).decode())]),
    ('H-apikey', [('X-Api-Key', base64.b64encode(bytes(range(33))).decode())]),
]
for cid, hs in REAL:
    CASES.append((cid, 'real-headers', False, 'Representative benign header ' + cid, req('GET', '/', hs)))
CASES.append(('H-cookie-emptyname', 'real-headers', False, 'Long cookie name with empty value', req('GET', '/', [('Cookie', 'lang=ko; refreshToken=' + JWT + '; popup_today_close_00000000-0000-4000-8000-000000000000=')])))
CASES.append(('H-cookie-emptyname-mid', 'real-headers', False, 'Empty-value cookie between other cookies', req('GET', '/', [('Cookie', 'popup_today_close_00000000-0000-4000-8000-000000000000=; lang=ko')])))
CASES.append(('S-N20', 'synthetic', False, 'Long form field name with empty value', req('POST', '/f', [('Content-Type', 'application/x-www-form-urlencoded')], 'a=1&popup_today_close_00000000-0000-4000-8000-000000000000=')))
CASES.append(('H-kv-emptyname', 'real-headers', False, 'Custom-header key/value list with an empty value', req('GET', '/', [('X-Prefs', 'theme=dark; popup_today_close_00000000-0000-4000-8000-000000000000=')])))
CASES.append(('H-att-scheme', 'real-headers', True, 'Custom-header scheme followed by anomaly', req('GET', '/', [('X-Auth', 'Token ' + A * 64 + '=')])))
CASES.append(('H-att-cookie', 'real-headers', True, 'Cookie anomaly after another cookie', req('GET', '/', [('Cookie', 'lang=ko; session=' + A * 64 + '=; theme=dark')])))
CASES.append(('H-att-api', 'real-headers', True, 'Custom API-key header anomaly', req('GET', '/', [('X-Api-Key', A * 128 + '=')])))
CASES.append(('H-att-kv', 'real-headers', True, 'Custom-header key/value anomaly', req('GET', '/', [('X-Session', 'v=1; data=' + A * 64 + '=')])))
CASES.append(('H-att-token-url', 'real-headers', True, 'URL-safe custom-header anomaly', req('GET', '/', [('X-Token', rnd(64, B64[:62] + '-_') + 'Ab=')])))
for i in range(300):
    raw = bytes((random.getrandbits(8) for _ in range(random.randint(8, 180))))
    val = 'Bearer ' + b64url(raw) if i % 3 == 0 else 'Basic ' + base64.b64encode(raw).decode()
    CASES.append((f'B{i:03d}', 'benign-bulk', False, 'Generated valid authentication token', auth(val)))

def _csum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 65535) + (s >> 16)
    return ~s & 65535

def _ip(ip):
    return bytes((int(x) for x in ip.split('.')))

def _pkt(src, dst, sport, dport, seq, ack, flags, payload=b''):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack('!BBH', 0, 6, 20 + len(payload))
    tcp = tcp[:16] + struct.pack('!H', _csum(pseudo + tcp + payload)) + tcp[18:]
    iph = struct.pack('!BBHHHBBH4s4s', 69, 0, 40 + len(payload), random.getrandbits(16), 16384, 64, 6, 0, _ip(src), _ip(dst))
    iph = iph[:10] + struct.pack('!H', _csum(iph)) + iph[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + iph + tcp + payload
