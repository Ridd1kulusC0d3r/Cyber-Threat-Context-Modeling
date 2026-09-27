import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tce.entity_resolution import canonical_name, resolve_entities
from tce.knowledge_graph import build_operational_graph
from tce.standards.attack import AttackIndex
from tce.standards.attack_flow import attack_flow_to_scenario, scenario_to_attack_flow
from tce.standards.opencti import normalize_entity, snapshot_to_evidence
from tce.standards.taxii import pull_collection


class V031Tests(unittest.TestCase):
    def attack_index(self):
        technique_ref = "attack-pattern--00000000-0000-4000-8000-000000000001"
        strategy_ref = "x-mitre-detection-strategy--00000000-0000-4000-8000-000000000002"
        analytic_ref = "x-mitre-analytic--00000000-0000-4000-8000-000000000003"
        component_ref = "x-mitre-data-component--00000000-0000-4000-8000-000000000004"
        return AttackIndex({
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": technique_ref,
                    "name": "Valid Accounts",
                    "description": "Use valid accounts.",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1078"}],
                },
                {
                    "type": "x-mitre-data-component",
                    "id": component_ref,
                    "name": "User Account Authentication",
                    "description": "Authentication events.",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "DC0008"}],
                    "x_mitre_log_sources": [{"name": "identity:audit", "channel": "auth"}],
                },
                {
                    "type": "x-mitre-analytic",
                    "id": analytic_ref,
                    "name": "Analytic 0001",
                    "description": "Correlate suspicious account use.",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "AN0001"}],
                    "x_mitre_platforms": ["Identity Provider"],
                    "x_mitre_log_source_references": [{
                        "x_mitre_data_component_ref": component_ref,
                        "name": "identity:audit",
                        "channel": "auth",
                    }],
                    "x_mitre_mutable_elements": [{"field": "TimeWindow", "description": "Tune window."}],
                },
                {
                    "type": "x-mitre-detection-strategy",
                    "id": strategy_ref,
                    "name": "Suspicious account activity",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "DET0001"}],
                    "x_mitre_analytic_refs": [analytic_ref],
                },
                {
                    "type": "relationship",
                    "id": "relationship--00000000-0000-4000-8000-000000000005",
                    "relationship_type": "detects",
                    "source_ref": strategy_ref,
                    "target_ref": technique_ref,
                },
            ]
        })

    def scenario(self):
        return {
            "id": "TS-001",
            "title": "Identity scenario",
            "objective": "Defensive visibility",
            "confidence": "medium",
            "attack_path": {
                "steps": [{
                    "order": 1,
                    "behavior": "Use a privileged identity",
                    "attack_techniques": ["T1078"],
                    "architecture_node_id": "NODE-IDP",
                }]
            },
        }

    def test_detection_profile(self):
        profile = self.attack_index().detection_profile("T1078")
        strategy = profile["detection_strategies"][0]
        self.assertEqual(strategy["id"], "DET0001")
        self.assertEqual(strategy["analytics"][0]["id"], "AN0001")
        self.assertEqual(strategy["data_components"][0]["id"], "DC0008")

    def test_detection_metadata_enters_graph(self):
        entities = {
            "TS-001": {
                "kind": "scenario",
                "data": self.scenario(),
                "source": "memory",
            }
        }
        graph = build_operational_graph(entities, attack_index=self.attack_index())
        self.assertIn("ATTACK::DET0001", graph)
        self.assertIn("ATTACK::AN0001", graph)
        self.assertIn("ATTACK::DC0008", graph)

    def test_attack_flow_roundtrip_to_review_draft(self):
        attack = self.attack_index()
        bundle = scenario_to_attack_flow(self.scenario(), attack)
        draft = attack_flow_to_scenario(bundle, attack)
        self.assertEqual(draft["scenario"]["attack_path"]["steps"][0]["attack_techniques"], ["T1078"])
        self.assertTrue(draft["scenario"]["x_tce_import"]["review_required"])
        self.assertFalse(draft["scenario"]["x_tce_import"]["auto_merge"])

    def test_opencti_snapshot_to_evidence(self):
        snapshot = {
            "source": "OpenCTI",
            "collected_at": "2026-09-27T00:00:00Z",
            "entities": [{
                "id": "x1",
                "standard_id": "malware--abc",
                "entity_type": "Malware",
                "name": "Example Malware",
                "description": "External CTI description.",
                "external_references": [],
            }],
        }
        data = snapshot_to_evidence(snapshot)
        self.assertEqual(len(data["evidence_items"]), 1)
        self.assertTrue(data["import_metadata"]["review_required"])
        self.assertFalse(data["import_metadata"]["auto_merge"])

    def test_opencti_normalization(self):
        row = normalize_entity("campaign", {
            "id": "1",
            "standard_id": "campaign--1",
            "name": "Campaign A",
            "aliases": ["A"],
        })
        self.assertEqual(row["entity_type"], "campaign")
        self.assertEqual(row["aliases"], ["A"])

    def test_entity_resolution(self):
        incoming = [{"name": "Example Threat", "aliases": ["ET"]}]
        existing = [{"id": "X-1", "name": "Example Threat", "aliases": []}]
        result = resolve_entities(incoming, existing)
        self.assertEqual(result[0]["status"], "matched")
        self.assertEqual(result[0]["score"], 1.0)
        self.assertEqual(canonical_name("Exámple-Threat"), "example threat")

    @patch("tce.standards.taxii.requests.get")
    def test_taxii_pull(self, mock_get):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "objects": [{"type": "malware", "id": "malware--1"}],
            "more": False,
        }
        mock_get.return_value = response
        bundle = pull_collection("https://example.test/taxii/collections/1")
        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(len(bundle["objects"]), 1)
        self.assertEqual(bundle["x_tce_pages"], 1)


if __name__ == "__main__":
    unittest.main()
