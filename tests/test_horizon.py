import tempfile
import unittest
from pathlib import Path

import yaml

from tce.conformance import evaluate_horizon_conformance
from tce.environment_import import environment_from_csv
from tce.horizon_intelligence import redframeworks_signal_candidates
from tce.horizon import (
    candidate_scenarios,
    diff_horizon_files,
    environments,
    horizon_assessment,
    write_assessment,
    write_candidate_scenarios,
    write_preemptive_actions,
)
from tce.io import load_case
from tce.validation import validate_entities


CASE_DIR = "examples/cases/enterprise-identity"


class HorizonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entities, cls.parse_errors = load_case(CASE_DIR)

    def test_horizon_conformance(self):
        result = evaluate_horizon_conformance(self.entities)
        self.assertTrue(result["passed"])

    def test_environment_loads_and_validates(self):
        self.assertFalse(self.parse_errors)
        self.assertIn("ENV-ENTERPRISE", self.entities)
        self.assertEqual(self.entities["ENV-ENTERPRISE"]["kind"], "environment_state")
        self.assertFalse(validate_entities(self.entities))

    def test_horizon_maps_enterprise_paths(self):
        result = horizon_assessment(
            self.entities,
            max_hops=5,
            limit=25,
            attack_index=None,
            budget=6,
        )
        self.assertEqual(result["environment_id"], "ENV-ENTERPRISE")
        self.assertGreaterEqual(result["summary"]["candidate_paths"], 2)
        self.assertIn("NODE-IDP", result["reached_crown_jewel_nodes"])
        self.assertTrue(result["candidate_paths"])
        self.assertTrue(all(row["forecast"]["review_required"] for row in result["candidate_paths"]))
        self.assertTrue(all(row["forecast"]["accepted_score"] is None for row in result["candidate_paths"]))

    def test_detection_by_absence_is_automatic(self):
        result = horizon_assessment(self.entities, limit=25, attack_index=None)
        gaps = result["detection_by_absence"]
        self.assertTrue(gaps)
        missing = {item for row in gaps for item in row["missing_telemetry"]}
        self.assertIn("identity-config-change", missing)

    def test_weighted_chokepoints_have_defensive_leverage(self):
        result = horizon_assessment(self.entities, limit=25, attack_index=None)
        rows = result["choke_points"]
        self.assertTrue(rows)
        self.assertTrue(all("defensive_leverage" in row for row in rows))
        self.assertTrue(any(row["node_id"] == "NODE-IDP" for row in rows))

    def test_budget_optimizer_uses_marginal_coverage(self):
        result = horizon_assessment(
            self.entities,
            limit=25,
            attack_index=None,
            budget=5,
        )
        actions = result["preemptive_actions"]
        self.assertLessEqual(actions["spent"], 5)
        self.assertTrue(actions["selected"])
        self.assertIsNotNone(actions["estimated_portfolio_risk_reduction"])
        self.assertTrue(all(row["review_required"] for row in actions["selected"]))

    def test_candidate_scenarios_remain_review_only(self):
        result = horizon_assessment(self.entities, limit=10, attack_index=None)
        env = environments(self.entities)[0]
        rows = candidate_scenarios(result["candidate_paths"], env)
        self.assertTrue(rows)
        self.assertTrue(all(row["status"] == "candidate" for row in rows))
        self.assertTrue(all(row["review_required"] for row in rows))

    def test_horizon_outputs_round_trip(self):
        result = horizon_assessment(self.entities, limit=10, attack_index=None, budget=4)
        env = environments(self.entities)[0]
        with tempfile.TemporaryDirectory() as tmp:
            assessment_path = Path(tmp) / "assessment.json"
            scenarios_path = Path(tmp) / "scenarios.yaml"
            actions_path = Path(tmp) / "actions.yaml"
            write_assessment(result, assessment_path)
            write_candidate_scenarios(result, env, scenarios_path)
            write_preemptive_actions(result, actions_path)
            self.assertTrue(assessment_path.exists())
            self.assertTrue(yaml.safe_load(scenarios_path.read_text())["review_required"])
            actions = yaml.safe_load(actions_path.read_text())
            self.assertTrue(actions["review_required"])

    def test_horizon_diff_detects_score_change(self):
        before = horizon_assessment(self.entities, limit=10, attack_index=None)
        with tempfile.TemporaryDirectory() as tmp:
            before_path = Path(tmp) / "before.json"
            after_path = Path(tmp) / "after.json"
            write_assessment(before, before_path)
            after = horizon_assessment(self.entities, limit=10, attack_index=None)
            after["candidate_paths"][0]["forecast"]["proposed_score"] += 5
            write_assessment(after, after_path)
            diff = diff_horizon_files(before_path, after_path)
            self.assertTrue(diff["paths"]["score_changes"])

    def test_architecture_fallback(self):
        entities, errors = load_case("examples/reference-cases/cloud-control-plane")
        self.assertFalse(errors)
        result = horizon_assessment(entities, attack_index=None)
        self.assertTrue(result["derived_environment"])

    def test_redframeworks_candidates_remain_review_gated(self):
        enrichment = {
            "contexts": [
                {
                    "context_id": "CTX-IDENTITY",
                    "domain_packs": [
                        {
                            "domain_pack_id": "identity",
                            "found": True,
                            "adversaries": [
                                {"id": "apt29", "source_tier": "A"}
                            ],
                            "campaigns": [
                                {"id": "solarwinds-compromise", "source_tier": "A"}
                            ],
                            "source": {"updated": "2026-10-01"},
                        }
                    ],
                }
            ]
        }
        rows = redframeworks_signal_candidates(self.entities, enrichment)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "candidate")
        self.assertTrue(rows[0]["review_required"])
        self.assertIn("NODE-IDP", rows[0]["target_ids"])
        self.assertIn("T1078", rows[0]["technique_ids"])

    def test_csv_environment_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            assets = tmp / "assets.csv"
            relationships = tmp / "relationships.csv"
            assets.write_text(
                "id,name,type,trust_zone,internet_exposure,entry_point,crown_jewel_ids\n"
                "A,Edge,service,edge,direct,true,\n"
                "B,Critical,control-plane,core,none,false,CJ-001\n",
                encoding="utf-8",
            )
            relationships.write_text(
                "id,from,to,type,trust_boundary,required_telemetry\n"
                "R1,A,B,connects_to,edge-to-core,network-connection\n",
                encoding="utf-8",
            )
            output = tmp / "environment.yaml"
            environment_from_csv(
                assets,
                relationships,
                output,
                snapshot_at="2026-10-13T00:00:00Z",
            )
            data = yaml.safe_load(output.read_text(encoding="utf-8"))
            self.assertEqual(data["environment_state"]["assets"][0]["id"], "A")
            self.assertEqual(data["environment_state"]["relationships"][0]["id"], "R1")


if __name__ == "__main__":
    unittest.main()
