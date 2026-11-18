import unittest

from score import load_hits, score


class ScoringTests(unittest.TestCase):
    def fixture(self, expected=(9114950,), gaps=()):
        return {20000: {'id': 'sample', 'group': 'pack-core',
                        'expected': {'suricata': list(expected)}, 'known_gaps': list(gaps)}}

    def test_wrong_rule_is_not_a_pass(self):
        self.assertTrue(score(self.fixture(), 'suricata', {20000: {9114938}})['failures'])

    def test_missing_and_extra_alerts_fail(self):
        self.assertTrue(score(self.fixture(), 'suricata', {})['failures'])
        self.assertTrue(score(self.fixture(), 'suricata', {20000: {9114950, 9114942}})['failures'])
        self.assertTrue(score(self.fixture(expected=()), 'suricata', {20000: {9114950}})['failures'])

    def test_known_gap_must_be_explicit_and_stable(self):
        index = self.fixture(gaps=('suricata',))
        self.assertFalse(score(index, 'suricata', {})['failures'])
        self.assertTrue(score(index, 'suricata', {20000: {9114950}})['failures'])

    def test_unknown_flow_fails(self):
        self.assertTrue(score(self.fixture(), 'suricata', {20000: {9114950}, 30000: {9114950}})['failures'])

    def test_corrupt_output_fails(self):
        with self.assertRaises(ValueError):
            load_hits('suricata', '{invalid json')


if __name__ == '__main__':
    unittest.main()
