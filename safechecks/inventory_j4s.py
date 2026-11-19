#!/usr/bin/env python3
"""Offline Java4Shell runtime inventory. No payloads, attachment or network I/O."""
import argparse
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

# Oracle/OpenJDK 2026-11-17 name the last affected builds in five-part form
# ("17.0.21.0.3 and earlier"); the fix baselines are the X.1 releases. A build
# between the two (for example 17.0.21.0.4) needs vendor evidence: unknown.
AFFECTED_MAX = {17: (17, 0, 21, 0, 3), 21: (21, 0, 13, 0, 3),
                25: (25, 0, 5, 0, 3), 27: (27, 0, 1, 0, 3)}
FIXED = {17: (17, 0, 21, 1, 0), 21: (21, 0, 13, 1, 0),
         25: (25, 0, 5, 1, 0), 27: (27, 0, 1, 1, 0)}
HISTORICAL_LINES = {18, 19, 20, 22, 23, 24, 26}


def parse_version(text):
    # Up to five components: Oracle builds such as "27.0.1.0.3" use all five.
    match = re.search(r'\b(?:openjdk|java)(?:\s+version)?\s+"?(\d+(?:[._]\d+){0,4})(?=[+\s"-]|$)', text)
    if not match:
        return None
    parts = tuple(map(int, re.split(r'[._]', match.group(1))))
    return parts + (0,) * (4 - len(parts))


def _padded(version):
    return version + (0,) * (5 - len(version))


def version_status(text):
    version = parse_version(text)
    if version is None or re.search(r'\d-ea\b|\d-internal\b', text, re.I):
        return 'unknown'
    major = version[0]
    # Oracle's separate 8u-perf lineage must not inherit the community-8 result.
    if (major == 8 or version[:2] == (1, 8)) and re.search(r'\d[^\s"]*-perf\b', text, re.I):
        return 'unknown'
    if major in (8, 11) or version[:2] == (1, 8):
        return 'outside_range'
    if major in HISTORICAL_LINES:
        return 'historical_affected'
    if major not in FIXED or version[1] != 0:
        return 'unknown'
    full = _padded(version)
    if major == 17 and full < (17, 0, 6, 0, 0):
        return 'outside_range'
    # Compare the entire version: 25.0.4.1 predates 25.0.5.1 and is NOT fixed.
    if full >= FIXED[major]:
        return 'fixed_range'
    if full <= AFFECTED_MAX[major]:
        return 'affected_range'
    return 'unknown'


def cpu_status(text, architecture=None):
    if architecture and architecture.lower() in ('aarch64', 'arm64'):
        return 'excluded'
    if not text.strip():
        return 'unknown'
    groups = re.findall(r'^\s*(?:flags|Features)\s*:\s*(.*)$', text, re.M | re.I)
    if not groups:
        # Accept an exported feature list, but not arbitrary lscpu/error output.
        if ':' in text or 'error' in text.lower():
            return 'unknown'
        groups = [text]
    capabilities = []
    for group in groups:
        tokens = set(re.split(r'[\s,]+', group.lower()))
        if not tokens.intersection({'avx', 'avx2', 'avx512bw', 'sse', 'sse2', 'fp', 'asimd'}):
            return 'unknown'
        capabilities.append(bool(tokens.intersection({'avx512_vbmi', 'avx512vbmi'})) and 'avx512bw' in tokens)
    if all(capabilities):
        return 'present'
    if any(capabilities):
        return 'unknown'  # heterogeneous/partial export: don't silently clear the host
    return 'excluded'


def parse_flags(text):
    flags = {}
    for name, kind in [('UseBASE64Intrinsics', 'bool'), ('UseAVX', 'int')]:
        values = re.findall(r'\b' + name + r'\s*:?=\s*(true|false|\d+)\b', text)
        if kind == 'bool':
            values += ['true' if sign == '+' else 'false' for sign in
                       re.findall(r'-XX:([+-])UseBASE64Intrinsics\b', text)]
        if len(set(values)) == 1:
            value = values[0]
            if kind == 'bool' and value in ('true', 'false'):
                flags[name] = value == 'true'
            elif kind == 'int' and value.isdigit():
                flags[name] = int(value)
    return flags


def assess(version_text, cpu_text, flags_text, architecture=None):
    status = version_status(version_text)
    cpu = cpu_status(cpu_text, architecture)
    flags = parse_flags(flags_text)
    version = parse_version(version_text)
    result = {'version': '.'.join(map(str, version)) if version else None,
              'version_status': status, 'cpu_avx512_vbmi_bw': cpu,
              'effective_flags': flags, 'scope': 'runtime prerequisites; application reachability not tested'}
    if 'openj9' in version_text.lower():
        verdict, reason = 'not_affected', 'OpenJ9 does not use the HotSpot intrinsic'
    elif cpu == 'excluded':
        verdict, reason = 'not_affected', 'required CPU path unavailable in the supplied environment'
    elif status in ('outside_range', 'fixed_range'):
        verdict, reason = 'not_affected', 'version outside the modeled affected range; verify vendor backports/build provenance'
    elif flags.get('UseBASE64Intrinsics') is False or flags.get('UseAVX', 3) < 3:
        verdict, reason = 'mitigated', 'supplied effective flags disable the affected path'
    elif status == 'unknown' or cpu == 'unknown':
        verdict, reason = 'unknown', 'version or CPU evidence missing/unrecognized'
    elif flags.get('UseBASE64Intrinsics') is True and flags.get('UseAVX') == 3:
        verdict, reason = 'potentially_exposed', 'known runtime prerequisites present; inspect application data flow and vendor patch status'
    else:
        verdict, reason = 'unknown', 'effective intrinsic/AVX flags incomplete or unrecognized'
    result.update(verdict=verdict, reason=reason)
    if status == 'historical_affected':
        result['support_note'] = 'historical non-LTS line; check supplier backports or migrate to a maintained release'
    return result


def collect_cpu():
    path = Path('/proc/cpuinfo')
    if path.exists():
        return path.read_text(errors='replace'), platform.machine()
    if platform.system() == 'Darwin':
        result = subprocess.run(['sysctl', '-n', 'machdep.cpu.features', 'machdep.cpu.leaf7_features'],
                                capture_output=True, text=True, timeout=10)
        return result.stdout, platform.machine()
    return '', platform.machine()


def probe_binary(path):
    # This is a fresh diagnostic JVM, NOT the running application's configuration.
    # Prevent inherited options from loading Java/native agents in this helper JVM.
    environment = dict(os.environ)
    removed = []
    for name in ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS'):
        if name in environment:
            removed.append(name)
            environment.pop(name)
    result = subprocess.run([path, '-XX:+PrintFlagsFinal', '-version'], env=environment,
                            capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise ValueError('diagnostic JVM exited with code %d; use offline exports for unsupported VMs' % result.returncode)
    return result.stdout + '\n' + result.stderr, removed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--java', help='trusted Java executable; inspect a NEW diagnostic JVM')
    mode.add_argument('--version-file', type=Path, help='offline java -version output from the target')
    parser.add_argument('--cpuinfo', type=Path, help='target CPU feature export; mandatory in offline mode')
    parser.add_argument('--flags-file', type=Path, help='effective target PrintFlagsFinal or jcmd VM.flags output')
    parser.add_argument('--arch', help='target architecture, e.g. aarch64; never inferred from this host for offline exports')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    removed = []
    try:
        if args.java:
            version, removed = probe_binary(args.java)
            flags = version
            cpu, architecture = ('', args.arch) if args.cpuinfo else collect_cpu()
            scope = 'new diagnostic JVM; application startup flags are not inherited'
        else:
            version = args.version_file.read_text(errors='replace')
            cpu, flags, architecture = '', '', args.arch
            scope = 'offline exports; caller must supply files from the SAME target runtime'
        if args.cpuinfo:
            cpu = args.cpuinfo.read_text(errors='replace')
            architecture = args.arch  # never combine foreign export with local architecture
        if args.flags_file:
            flags = args.flags_file.read_text(errors='replace')
        report = assess(version, cpu, flags, architecture)
        report['collection'] = scope
        if removed:
            report['ignored_option_variables'] = removed
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report = {'verdict': 'unknown', 'reason': str(error)}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print('%s: %s' % (report['verdict'], report['reason']))
        if 'collection' in report:
            print(report['collection'])
    return {'potentially_exposed': 1, 'unknown': 2}.get(report['verdict'], 0)


if __name__ == '__main__':
    sys.exit(main())
