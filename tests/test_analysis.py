import unittest

from tce.analysis import choke_points, coverage_summary


class AnalysisTests(unittest.TestCase):
    def test_choke_point(self):
        entities = {
            "TS-001": {
                "kind": "scenario",
                "data": {
                    "id": "TS-001",
                    "title": "x",
                    "confidence": "medium",
                    "priority": {
                        "crown_jewel_criticality": 5,
                        "threat_relevance": 4,
                        "attack_path_feasibility": 4,
                        "exposure": 4,
                        "control_weakness": 3,
                        "detection_gap": 5,
                    },
                    "attack_path": {"steps": [{"architecture_node_id": "NODE-IDP"}]},
                },
            }
        }
        self.assertEqual(choke_points(entities)[0]["node"], "NODE-IDP")

    def test_coverage(self):
        entities = {
            "DU-001": {
                "kind": "detection_use_case",
                "data": {
                    "id": "DU-001",
                    "coverage": {
                        "telemetry": "covered",
                        "analytic": "partial",
                        "correlation": "missing",
                        "validation": "unknown",
                        "response": "covered",
                    },
                },
            }
        }
        result = coverage_summary(entities)
        self.assertEqual(result["telemetry"], 100.0)
        self.assertEqual(result["analytic"], 50.0)
        self.assertEqual(result["correlation"], 0.0)
        self.assertIsNone(result["validation"])


if __name__ == "__main__":
    unittest.main()
