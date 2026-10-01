import json
import tempfile
import unittest
from pathlib import Path

from tce.detection import compile_backlog, correlation_patterns, sigma_document
from tce.history import build_snapshot, diff_snapshots
from tce.io import load_case
from tce.telemetry import evaluate_case_telemetry, schema_mappings
from tce.validation import validate_entities
from tce.validation_harness import evaluate_logic, run_validation


CASE_DIR = "examples/cases/enterprise-identity"


class V04Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entities, cls.errors = load_case(CASE_DIR)

    def test_example_case_is_valid(self):
        self.assertFalse(self.errors)
        self.assertFalse(validate_entities(self.entities))
        self.assertIn("DSP-001", self.entities)
        self.assertEqual(self.entities["DSP-001"]["kind"], "detection_specification")

    def test_telemetry_health_and_schema_bridge(self):
        result = evaluate_case_telemetry(self.entities)
        self.assertEqual(len(result["contracts"]), 1)
        contract = result["contracts"][0]
        self.assertGreater(contract["health_score"], 0)
        self.assertIn("target.resource", contract["missing_fields"])
        mappings = schema_mappings(["user.id", "source.ip"])
        self.assertEqual(mappings["user.id"]["ecs"], "user.id")
        self.assertEqual(mappings["source.ip"]["asim"], "SrcIpAddr")

    def test_backlog_is_scenario_driven(self):
        rows = compile_backlog(self.entities)
        self.assertTrue(rows)
        row = next(item for item in rows if item.get("detection_specification_id") == "DSP-001")
        self.assertEqual(row["scenario_id"], "TS-001")
        self.assertIn("partial telemetry", row["reasons"])

    def test_sigma_export_is_deterministic_shape(self):
        spec = self.entities["DSP-001"]["data"]
        document = sigma_document(spec)
        self.assertEqual(document["status"], "experimental")
        self.assertIn("detection", document)
        self.assertIn("attack.t1078", document["tags"])

    def test_validation_fixture_passes(self):
        result = run_validation(self.entities, "VAL-001", CASE_DIR)
        self.assertTrue(result["passed"])
        self.assertEqual(result["results"][0]["matches"], 1)

    def test_ordered_sequence_logic(self):
        events = [
            {"user": {"id": "a"}, "event": {"action": "one"}},
            {"user": {"id": "b"}, "event": {"action": "two"}},
            {"user": {"id": "a"}, "event": {"action": "two"}},
        ]
        logic = {
            "pattern": "ordered-sequence",
            "group_by": ["user.id"],
            "stages": [
                {"all": [{"field": "event.action", "op": "eq", "value": "one"}]},
                {"all": [{"field": "event.action", "op": "eq", "value": "two"}]},
            ],
        }
        result = evaluate_logic(logic, events)
        self.assertEqual(result["matches"], 1)
        self.assertEqual(result["matched_event_indexes"], [0, 2])

    def test_correlation_pattern_catalog(self):
        ids = {item["id"] for item in correlation_patterns()}
        self.assertIn("ordered-sequence", ids)
        self.assertIn("threshold", ids)

    def test_snapshot_diff_detects_change(self):
        before = build_snapshot(self.entities)
        after = json.loads(json.dumps(before))
        after["generated_at"] = "later"
        after["coverage"]["validation"] = 100
        before["coverage"]["validation"] = 50
        after["entities"]["DSP-001"]["sha256"] = "changed"
        diff = diff_snapshots(before, after)
        self.assertIn("DSP-001", diff["entities"]["changed"])
        self.assertEqual(diff["coverage"]["validation"]["delta"], 50)


if __name__ == "__main__":
    unittest.main()
