import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('inventory', ROOT / 'safechecks/inventory_j4s.py')
inv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inv)
CPU = 'flags : sse2 avx2 avx512bw avx512_vbmi\n'
FLAGS = 'bool UseBASE64Intrinsics = true {product}\nint UseAVX = 3\n'


class VersionTests(unittest.TestCase):
    def test_version_boundaries(self):
        cases = {'17.0.5': 'outside_range', '17.0.6': 'affected_range',
                 '17.0.21': 'affected_range', '17.0.21.1': 'fixed_range',
                 '21': 'affected_range', '21.0.13': 'affected_range',
                 '21.0.13.1': 'fixed_range', '21.0.14': 'fixed_range',
                 '25.0.4.1': 'affected_range', '25.0.5': 'affected_range',
                 '25.0.5.1': 'fixed_range', '27.0.1': 'affected_range',
                 '27.0.1.1': 'fixed_range', '11.0.33': 'outside_range',
                 '1.8.0_402': 'outside_range', '19.0.2': 'historical_affected',
                 '28': 'unknown', '21.1.0': 'unknown'}
        for version, expected in cases.items():
            with self.subTest(version=version):
                self.assertEqual(inv.version_status('openjdk version "%s"' % version), expected)

    def test_vendor_build_suffix(self):
        self.assertEqual(inv.parse_version('openjdk version "21.0.13.1+4-LTS"'), (21, 0, 13, 1))

    def test_unquoted_format(self):
        self.assertEqual(inv.parse_version('openjdk 21.0.13 2026-10-20'), (21, 0, 13, 0))

    def test_ea_unknown(self):
        self.assertEqual(inv.version_status('openjdk version "28-ea"'), 'unknown')

    def test_perf_not_cleared(self):
        self.assertEqual(inv.version_status('java version "1.8.0_511-perf"'), 'unknown')

    def test_invalid_version(self):
        self.assertIsNone(inv.parse_version('java: command not found'))


class EvidenceTests(unittest.TestCase):
    def report(self, version='21.0.13', cpu=CPU, flags=FLAGS, arch=None):
        return inv.assess('openjdk version "%s"' % version, cpu, flags, arch)

    def test_prerequisites_present(self):
        self.assertEqual(self.report()['verdict'], 'potentially_exposed')

    def test_missing_cpu_is_unknown(self):
        self.assertEqual(self.report(cpu='')['verdict'], 'unknown')

    def test_error_text_is_unknown(self):
        self.assertEqual(self.report(cpu='error: permission denied')['verdict'], 'unknown')

    def test_vbmi2_does_not_imply_vbmi(self):
        self.assertEqual(self.report(cpu='sse2 avx2 avx512bw avx512_vbmi2')['verdict'], 'not_affected')

    def test_both_cpu_features_required(self):
        for cpu in ('avx2 avx512bw', 'avx2 avx512_vbmi'):
            with self.subTest(cpu=cpu):
                self.assertEqual(self.report(cpu=cpu)['verdict'], 'not_affected')

    def test_cpu_alias(self):
        self.assertEqual(self.report(cpu='AVX2 AVX512BW AVX512VBMI')['verdict'], 'potentially_exposed')

    def test_mixed_cpu_export(self):
        self.assertEqual(self.report(cpu=CPU + 'flags : sse2 avx2\n')['verdict'], 'unknown')

    def test_arm_explicit(self):
        self.assertEqual(self.report(cpu='', arch='aarch64')['verdict'], 'not_affected')

    def test_flags_required(self):
        for flags in ('', 'UseBASE64Intrinsics = true', 'UseAVX = 3'):
            with self.subTest(flags=flags):
                self.assertEqual(self.report(flags=flags)['verdict'], 'unknown')

    def test_both_workarounds(self):
        for flags in ('UseBASE64Intrinsics = false', '-XX:-UseBASE64Intrinsics', '-XX:UseAVX=2'):
            with self.subTest(flags=flags):
                self.assertEqual(self.report(flags=flags)['verdict'], 'mitigated')

    def test_jcmd_positive(self):
        self.assertEqual(self.report(flags='-XX:+UseBASE64Intrinsics -XX:UseAVX=3')['verdict'], 'potentially_exposed')

    def test_conflicting_export(self):
        self.assertEqual(self.report(flags=FLAGS + 'UseBASE64Intrinsics = false')['verdict'], 'unknown')

    def test_fixed_version_without_flags(self):
        self.assertEqual(self.report(version='21.0.13.1', flags='')['verdict'], 'not_affected')

    def test_older_four_component_version(self):
        self.assertEqual(self.report(version='25.0.4.1')['verdict'], 'potentially_exposed')

    def test_openj9(self):
        self.assertEqual(inv.assess('openjdk version "21.0.13"\nEclipse OpenJ9 VM', CPU, '')['verdict'], 'not_affected')

    def test_arch_not_inferred_for_exports(self):
        with patch.object(inv.platform, 'machine', return_value='arm64'):
            self.assertEqual(self.report()['verdict'], 'potentially_exposed')


class CLITests(unittest.TestCase):
    def test_offline_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'version').write_text('openjdk version "21.0.13"')
            (root / 'cpu').write_text(CPU)
            (root / 'flags').write_text(FLAGS)
            base = ['--version-file', str(root / 'version'), '--json']
            for extra, expected in [([], 2), (['--cpuinfo', str(root / 'cpu'), '--flags-file', str(root / 'flags')], 1),
                                    (['--cpuinfo', str(root / 'missing')], 2), (['--arch', 'arm64'], 0)]:
                with self.subTest(extra=extra), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(inv.main(base + extra), expected)
                    self.assertIn('verdict', json.loads(output.getvalue()))

    def test_probe_does_not_load_option_agents(self):
        result = subprocess.CompletedProcess([], 0, FLAGS, 'openjdk version "21.0.13"')
        with patch.dict(os.environ, {'JAVA_TOOL_OPTIONS': '-javaagent:secret.jar', '_JAVA_OPTIONS': '-XX:UseAVX=2'}), \
             patch.object(inv.subprocess, 'run', return_value=result) as run:
            _, removed = inv.probe_binary('/trusted/java')
            self.assertNotIn('JAVA_TOOL_OPTIONS', run.call_args.kwargs['env'])
            self.assertNotIn('_JAVA_OPTIONS', run.call_args.kwargs['env'])
            self.assertIn('JAVA_TOOL_OPTIONS', removed)

    def test_failed_probe_is_unknown(self):
        with patch.object(inv, 'probe_binary', side_effect=ValueError('JVM failed')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(inv.main(['--java', '/trusted/java', '--json']), 2)
            self.assertEqual(json.loads(output.getvalue())['verdict'], 'unknown')


if __name__ == '__main__':
    unittest.main()
