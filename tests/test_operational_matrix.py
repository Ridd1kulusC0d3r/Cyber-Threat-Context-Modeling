import unittest

from tce.io import load_case
from tce.operational_matrix import build_operational_matrix


CASE_DIR = "examples/cases/enterprise-identity"


class OperationalMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entities, cls.errors = load_case(CASE_DIR)

    def test_builds_matrix_from_case(self):
        self.assertFalse(self.errors)
        matrix = build_operational_matrix(self.entities)
        self.assertEqual(matrix["name"], "TCEM Operational Matrix")
        self.assertTrue(matrix["rows"])
        row = matrix["rows"][0]
        self.assertEqual(row["scenario_id"], "TS-001")
        self.assertIn("CTX-IDENTITY", row["threat_context_ids"])
        self.assertTrue(any(x["id"] == "T1078" for x in row["attack_techniques"]))
        self.assertEqual(row["detection_status"], "covered")
        self.assertIn("DEC-001", row["decision_ids"])

    def test_matrix_keeps_visibility_and_detection_distinct(self):
        matrix = build_operational_matrix(self.entities)
        row = matrix["rows"][0]
        self.assertIn(row["telemetry_status"], {"partial", "covered", "missing", "unknown"})
        self.assertIn(row["detection_status"], {"partial", "covered", "missing", "unknown"})
        self.assertIn("visibility_model", matrix["meta"])


if __name__ == "__main__":
    unittest.main()
