import unittest
from pathlib import Path

class PublicDataPolicyTests(unittest.TestCase):
    def test_policy_and_guard_exist(self):
        root = Path(__file__).resolve().parents[1]
        self.assertTrue((root / 'SECURITY-DATA.md').is_file())
        self.assertTrue((root / 'scripts/check_public_data.py').is_file())
        self.assertTrue((root / '.github/workflows/public-data-guard.yml').is_file())

if __name__ == '__main__':
    unittest.main()
