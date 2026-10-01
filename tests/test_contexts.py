import unittest

from tce.context import assess_contexts, load_context_catalog, suggest_context_lenses
from tce.integrations.redframeworks import RedFrameworksIndex
from tce.io import load_case
from tce.validation import validate_entities


class ContextTests(unittest.TestCase):
    def test_catalog_is_broad(self):
        catalog = load_context_catalog()
        self.assertGreaterEqual(len(catalog), 20)
        for lens_id in (
            "identity-access",
            "cloud-multicloud",
            "ai-genai",
            "ics-ot",
            "third-party-saas",
            "resilience-recovery",
            "security-control-plane",
        ):
            self.assertIn(lens_id, catalog)

    def test_suggestions_are_deterministic(self):
        entities = {
            "CASE-1": {
                "kind": "case",
                "data": {
                    "id": "CASE-1",
                    "name": "Cloud identity",
                    "mission": "Protect cloud identity and SaaS administration",
                    "scope": ["identity", "cloud", "saas"],
                },
                "source": "memory",
            }
        }
        ids = {item["lens_id"] for item in suggest_context_lenses(entities)}
        self.assertIn("identity-access", ids)
        self.assertIn("cloud-multicloud", ids)
        self.assertIn("third-party-saas", ids)

    def test_example_case_has_contexts(self):
        entities, errors = load_case("examples/cases/enterprise-identity")
        self.assertFalse(errors)
        validation = validate_entities(entities)
        self.assertFalse(validation)
        result = assess_contexts(entities)
        self.assertGreaterEqual(result["modeled_contexts"], 3)
        self.assertFalse(any(g["type"] == "scenario-context" for g in result["gaps"]))

    def test_redframeworks_enrichment_is_review_gated(self):
        datasets = {
            "index": {"updated": "2026-09-30", "counts": {"adversaries": 1}},
            "domain_packs": {"packs": [{
                "id": "identity",
                "name": "Identity & Access",
                "adversaries": ["actor-a"],
                "detections": ["det-a"],
            }]},
            "adversaries": {"adversaries": [{
                "id": "actor-a",
                "name": "Example Actor",
                "attack_id": "G0001",
            }]},
            "campaigns": {"campaigns": [{
                "id": "campaign-a",
                "name": "Example Campaign",
                "actor_ids": ["actor-a"],
            }]},
            "detections": {"detections": [{
                "id": "det-a",
                "attack_id": "T1078",
            }]},
            "emulation_plans": {"plans": [{
                "id": "validation-a",
                "attack_group_id": "G0001",
            }]},
            "ai_security_surface": {"surfaces": []},
            "intelligence_sources": {"sources": [{"id": "source-a", "name": "Source A"}]},
            "verification_v2": {"entries": []},
        }
        index = RedFrameworksIndex(datasets)
        result = index.enrich_domain_pack("identity")
        self.assertTrue(result["found"])
        self.assertEqual(result["adversaries"][0]["id"], "actor-a")
        self.assertEqual(result["campaigns"][0]["id"], "campaign-a")
        self.assertEqual(result["detections"][0]["id"], "det-a")
        self.assertEqual(result["validation_references"][0]["id"], "validation-a")
        self.assertTrue(result["policy"]["review_required"])
        self.assertFalse(result["policy"]["auto_promote_to_evidence"])


if __name__ == "__main__":
    unittest.main()
