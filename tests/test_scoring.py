import unittest

from tce.scoring import priority_band, priority_score


class ScoringTests(unittest.TestCase):
    def test_weighted_score(self):
        priority = {
            "crown_jewel_criticality": 5,
            "threat_relevance": 4,
            "attack_path_feasibility": 4,
            "exposure": 4,
            "control_weakness": 3,
            "detection_gap": 5,
        }
        self.assertEqual(priority_score(priority), 4.30)
        self.assertEqual(priority_band(4.30), "P0")

    def test_bounds(self):
        with self.assertRaises(ValueError):
            priority_score({"crown_jewel_criticality": 6})


if __name__ == "__main__":
    unittest.main()
