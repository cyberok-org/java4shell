"""Compare exact SID sets, including explicit known gaps. No traffic replay here."""
import json
from collections import defaultdict

LOCAL_SIDS = {9114938, 9114939, 9114940, 9114941, 9114942, 9114943,
              9114950, 9114951, 9114952, 9114953, 9114954}


def load_hits(engine, text):
    hits = defaultdict(set)
    for line in text.splitlines():
        if not line.lstrip().startswith('{'):
            continue
        event = json.loads(line)
        if engine == 'suricata':
            if event.get('event_type') != 'alert':
                continue
            sid = int(event['alert']['signature_id'])
            if sid not in LOCAL_SIDS:
                raise ValueError('Unexpected alert SID: %s' % sid)
            if event.get('src_ip') != '192.0.2.10':
                raise ValueError('Unexpected alert direction')
            port = int(event['src_port'])
        else:
            if 'rule' not in event:
                continue
            sid = int(event['rule'].split(':')[1])
            if sid not in LOCAL_SIDS or event.get('dir') != 'C2S':
                raise ValueError('Unexpected Snort alert SID/direction')
            address, port = event['src_ap'].rsplit(':', 1)
            if address != '192.0.2.10':
                raise ValueError('Unexpected Snort alert source')
            port = int(port)
        hits[port].add(sid)
    return hits


def score(index, engine, hits):
    failures, gaps, rows = [], [], []
    for port in set(hits) - set(index):
        failures.append('Alert on unknown fixture port %s' % port)
    counts = {'indicator': 0, 'negative': 0, 'reference': 0, 'known_gap': 0}
    for port, item in index.items():
        actual = hits.get(port, set())
        expected = set(item['expected'][engine])
        known = engine in item['known_gaps']
        if known:
            if not expected:
                raise ValueError('Known gap requires a nonempty intended SID set')
            counts['known_gap'] += 1
            gaps.append(item['id'])
            passed = not actual
            if actual:
                failures.append(item['id'] + ': known gap changed; review and update expectations')
        else:
            category = 'reference' if item['group'] == 'upstream-reference' else 'indicator' if expected else 'negative'
            counts[category] += 1
            passed = actual == expected
            if not passed:
                failures.append('%s: expected %s; got %s' % (item['id'], sorted(expected), sorted(actual)))
        rows.append({'id': item['id'], 'passed': passed, 'expected': sorted(expected),
                     'actual': sorted(actual), 'known_gap': known})
    return {'engine': engine, 'cases': len(index), 'counts': counts,
            'known_gaps': gaps, 'failures': failures, 'results': rows}
