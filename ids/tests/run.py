#!/usr/bin/env python3
"""Run both IDS engines against offline PCAPs in disposable isolated containers.

No host mounts, published ports, Java backend or live traffic. Image acquisition
needs registry access; engine execution uses --network none. Engine failures,
unexpected SIDs and changes to recorded gaps fail the run.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from fixtures import main as build_fixtures
from score import load_hits, score

ROOT = Path(__file__).resolve().parents[1]


def command(args, timeout=180, include_stderr=False):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Command failed (%s): %s\n%s' %
                           (result.returncode, ' '.join(args[:3]), (result.stdout + result.stderr)[-5000:]))
    return result.stdout + (result.stderr if include_stderr else '')


def run_engine(engine, image, platform, work, index):
    command(['docker', 'pull', '--platform', platform, image], timeout=600)
    image_info = json.loads(command(['docker', 'image', 'inspect', image]))[0]
    engine_commands = {
        'suricata': '''set -eu
mkdir -p /tmp/j4s-output
suricata -V
suricata -c /etc/suricata.dist/suricata.yaml --set classification-file=/etc/suricata.dist/classification.config --set reference-config-file=/etc/suricata.dist/reference.config -T -S /tmp/j4s/rules/suricata/java4shell.rules -l /tmp/j4s-output
suricata -c /etc/suricata.dist/suricata.yaml --set classification-file=/etc/suricata.dist/classification.config --set reference-config-file=/etc/suricata.dist/reference.config --runmode single -r /tmp/j4s/fixtures.pcap -S /tmp/j4s/rules/suricata/java4shell.rules -k none -l /tmp/j4s-output
''',
        'snort': '''set -eu
mkdir -p /tmp/j4s-output
/home/snorty/snort3/bin/snort -V
/home/snorty/snort3/bin/snort -c /home/snorty/snort3/etc/snort/snort.lua -R /tmp/j4s/rules/snort3/java4shell.rules --warn-all -T
/home/snorty/snort3/bin/snort -c /home/snorty/snort3/etc/snort/snort.lua -R /tmp/j4s/rules/snort3/java4shell.rules -r /tmp/j4s/fixtures.pcap -k none -A alert_json -q > /tmp/j4s-output/alerts.json
''',
    }
    # The image's config is owned by this account; root with all capabilities
    # dropped cannot bypass its file permissions. Offline replay needs no caps.
    user = ['--user', 'suricata'] if engine == 'suricata' else []
    cid = command(['docker', 'create', '--platform', platform, '--network', 'none',
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                   *user, '--entrypoint', 'sh', image, '-c', engine_commands[engine]]).strip()
    try:
        command(['docker', 'cp', str(work / 'input') + '/.', cid + ':/tmp/j4s'])
        logs = command(['docker', 'start', '-a', cid], timeout=300, include_stderr=True)
        state = json.loads(command(['docker', 'inspect', cid]))[0]['State']
        if state['ExitCode'] != 0 or state.get('OOMKilled'):
            raise RuntimeError('%s container failed: %s' % (engine, state['ExitCode']))
        output = work / engine
        command(['docker', 'cp', cid + ':/tmp/j4s-output', str(output)])
        alerts = output / ('eve.json' if engine == 'suricata' else 'alerts.json')
        result = score(index, engine, load_hits(engine, alerts.read_text()))
        result['image'] = image
        result['image_digests'] = image_info.get('RepoDigests', [])
        result['engine_version_lines'] = [line.strip() for line in logs.splitlines()
                                          if 'Suricata version' in line or 'Snort++' in line]
        result['rules_sha256'] = hashlib.sha256((ROOT / 'rules' / ('snort3' if engine == 'snort' else engine) / 'java4shell.rules').read_bytes()).hexdigest()
        return result
    finally:
        command(['docker', 'rm', '-f', cid])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, default=Path('ids-results.json'))
    args = parser.parse_args()
    images = json.loads((ROOT / 'engines.json').read_text())
    report = {'checked_at': datetime.now(timezone.utc).isoformat(),
              'scope': 'synthetic offline PCAP indicators; no JVM or exploitation test', 'engines': []}
    with tempfile.TemporaryDirectory(prefix='java4shell-ids-') as directory:
        work = Path(directory)
        (work / 'input').mkdir()
        shutil.copytree(ROOT / 'rules', work / 'input/rules')
        build_fixtures(work / 'input/fixtures.pcap', work / 'index.json')
        index = {int(port): item for port, item in json.loads((work / 'index.json').read_text()).items()}
        for engine in ('suricata', 'snort'):
            try:
                result = run_engine(engine, images[engine], images['platform'], work, index)
            except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
                result = {'engine': engine, 'failures': [str(error)]}
            report['engines'].append(result)
            print(engine, json.dumps({k: v for k, v in result.items() if k != 'results'}), flush=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')
    return int(any(result['failures'] for result in report['engines']))


if __name__ == '__main__':
    sys.exit(main())
