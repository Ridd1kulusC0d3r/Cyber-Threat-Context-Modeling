import unittest

from tce.io import load_case
from tce.validation import validate_entities
from tce.validation_harness import run_validation


CASES = {
    "cloud-control-plane": "VAL-CLOUD",
    "software-supply-chain": "VAL-SUPPLY",
    "ai-agent-enterprise": "VAL-AI",
    "critical-saas-third-party": "VAL-SAAS",
    "ics-ot-resilience": "VAL-OT",
}


class ReferenceCaseTests(unittest.TestCase):
    def test_reference_cases_validate_and_replay(self):
        for slug, validation_id in CASES.items():
            with self.subTest(case=slug):
                case_dir = f"examples/reference-cases/{slug}"
                entities, errors = load_case(case_dir)
                self.assertFalse(errors)
                self.assertFalse(validate_entities(entities))
                result = run_validation(entities, validation_id, case_dir)
                self.assertTrue(result["passed"])
                self.assertEqual(result["results"][0]["matches"], 1)


if __name__ == "__main__":
    unittest.main()
