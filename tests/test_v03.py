import unittest

from tce.ai.config import AIConfig
from tce.ai.evidence_packet import EvidencePacket
from tce.knowledge_graph import build_operational_graph
from tce.standards.attack import AttackIndex
from tce.standards.attack_flow import EXTENSION_ID, scenario_to_attack_flow
from tce.standards.navigator import export_navigator_layer
from tce.standards.stix_export import export_case_stix


class V03Tests(unittest.TestCase):
    def setUp(self):
        self.attack = AttackIndex({
            "objects": [{
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-000000000001",
                "name": "Valid Accounts",
                "description": "Use valid accounts.",
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": "T1078",
                }],
            }]
        })
        self.entities = {
            "TS-001": {
                "kind": "scenario",
                "data": {
                    "id": "TS-001",
                    "title": "Identity scenario",
                    "objective": "Test defensive visibility.",
                    "confidence": "medium",
                    "attack_path": {
                        "steps": [{
                            "order": 1,
                            "behavior": "Use a privileged identity",
                            "attack_techniques": ["T1078"],
                            "architecture_node_id": "NODE-IDP",
                        }]
                    },
                },
                "source": "memory",
            }
        }

    def test_ai_defaults_on(self):
        config = AIConfig()
        self.assertTrue(config.gliner_enabled)
        self.assertTrue(config.qwen_enabled)

    def test_evidence_packet_stable(self):
        first = EvidencePacket.from_text("same", source_id="EV-X")
        second = EvidencePacket.from_text("same", source_id="EV-X")
        self.assertEqual(first.packet_id, second.packet_id)
        self.assertTrue(first.packet_id.startswith("sha256:"))

    def test_attack_validate(self):
        result = self.attack.validate_ids(["T1078", "T9999"])
        self.assertEqual(result["valid"], ["T1078"])
        self.assertEqual(result["invalid"], ["T9999"])

    def test_attack_flow(self):
        bundle = scenario_to_attack_flow(self.entities["TS-001"]["data"], self.attack)
        types = [obj["type"] for obj in bundle["objects"]]
        self.assertIn("attack-flow", types)
        action = next(obj for obj in bundle["objects"] if obj["type"] == "attack-action")
        self.assertEqual(action["technique_id"], "T1078")
        self.assertIn(EXTENSION_ID, action["extensions"])

    def test_knowledge_graph(self):
        graph = build_operational_graph(self.entities, attack_index=self.attack)
        self.assertIn("ATTACK::T1078", graph)
        self.assertTrue(graph.has_edge("TS-001", "ATTACK::T1078"))

    def test_navigator(self):
        layer = export_navigator_layer(self.entities)
        self.assertEqual(layer["techniques"][0]["techniqueID"], "T1078")

    def test_stix(self):
        bundle = export_case_stix(self.entities)
        self.assertEqual(bundle["type"], "bundle")
        self.assertTrue(any(obj["type"] == "note" for obj in bundle["objects"]))


if __name__ == "__main__":
    unittest.main()
