from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'safechecks/scan-source.sh'


@unittest.skipUnless(shutil.which('rg'), 'ripgrep is optional')
class SourceSearchTests(unittest.TestCase):
    def test_java_kotlin_and_spaces(self):
        with tempfile.TemporaryDirectory(prefix='source with spaces ') as folder:
            root = Path(folder)
            (root / 'A.java').write_text('Base64.getDecoder()\n  .decode(src, dst);\n')
            (root / 'B.kt').write_text('decoder.decode(source, reused)\n')
            result = subprocess.run(['bash', str(SCRIPT), folder], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn('A.java', result.stdout)
            self.assertIn('B.kt', result.stdout)

    def test_no_matches(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'A.java').write_text('Base64.getEncoder().encode(input);\n')
            result = subprocess.run(['bash', str(SCRIPT), folder], capture_output=True)
            self.assertEqual(result.returncode, 1)

    def test_missing_root(self):
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run(['bash', str(SCRIPT), str(Path(folder) / 'missing')], capture_output=True)
            self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
