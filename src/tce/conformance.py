from __future__ import annotations

from typing import Any

LEVELS = ("core", "detection", "validated", "operational")


def _kind(entities: dict[str, dict], kind: str) -> list[dict[str, Any]]:
    return [wrapped["data"] for wrapped in entities.values() if wrapped["kind"] == kind]


def evaluate_conformance(entities: dict[str, dict], level: str = "operational") -> dict[str, Any]:
    if level not in LEVELS:
        raise ValueError(f"Unknown conformance level: {level}")

    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, detail: str):
        checks.append({"check": name, "passed": bool(passed), "detail": detail})

    cases = _kind(entities, "case")
    crown = _kind(entities, "crown_jewel")
    contexts = _kind(entities, "threat_context")
    architectures = _kind(entities, "architecture")
    scenarios = _kind(entities, "scenario")
    telemetry = _kind(entities, "telemetry_contract")
    specs = _kind(entities, "detection_specification")
    validations = _kind(entities, "validation")
    decisions = _kind(entities, "decision")
    gaps = _kind(entities, "intelligence_gap")

    check("core.case", bool(cases), "At least one Case object exists.")
    check("core.crown-jewel", bool(crown), "At least one Crown Jewel exists.")
    check("core.threat-context", bool(contexts), "At least one Threat Context exists.")
    check("core.architecture", bool(architectures), "At least one Architecture exists.")
    check("core.scenario", bool(scenarios), "At least one prioritized Threat Scenario exists.")
    check(
        "core.scenario-context-link",
        bool(scenarios) and all(s.get("threat_context_ids") for s in scenarios),
        "Every scenario links to at least one Threat Context.",
    )
    check(
        "core.scenario-crown-jewel-link",
        bool(scenarios) and all(s.get("target_crown_jewels") for s in scenarios),
        "Every scenario links to at least one Crown Jewel.",
    )

    if level in {"detection", "validated", "operational"}:
        check("detection.telemetry-contract", bool(telemetry), "At least one Telemetry Contract exists.")
        check("detection.specification", bool(specs), "At least one Detection Specification exists.")
        check(
            "detection.scenario-spec-link",
            bool(scenarios) and all(s.get("detection_specification_ids") for s in scenarios),
            "Every scenario links to a Detection Specification.",
        )
        check(
            "detection.spec-telemetry-link",
            bool(specs) and all(s.get("telemetry_contract_ids") for s in specs),
            "Every Detection Specification links to Telemetry Contracts.",
        )

    if level in {"validated", "operational"}:
        check("validated.validation", bool(validations), "At least one Validation object exists.")
        check(
            "validated.passed",
            bool(validations) and all(v.get("status") == "passed" for v in validations),
            "All declared validations are currently passed.",
        )
        check(
            "validated.spec-validation-link",
            bool(specs) and all(s.get("validation_ids") for s in specs),
            "Every Detection Specification links to validation evidence.",
        )

    if level == "operational":
        reviewable = crown + contexts + scenarios + telemetry + specs
        check(
            "operational.ownership",
            bool(reviewable) and all(item.get("owner") for item in reviewable),
            "Core defensive objects have explicit owners.",
        )
        check(
            "operational.review-date",
            bool(reviewable) and all(item.get("review_date") for item in reviewable),
            "Core defensive objects have review dates.",
        )
        check(
            "operational.decision-or-gap",
            bool(decisions or gaps),
            "The case contains a Decision or managed Intelligence Gap.",
        )

    failed = [row for row in checks if not row["passed"]]
    return {
        "level": level,
        "passed": not failed,
        "checks": checks,
        "failed_checks": [row["check"] for row in failed],
    }


def evaluate_horizon_conformance(entities: dict[str, dict]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, detail: str):
        checks.append({"check": name, "passed": bool(passed), "detail": detail})

    environments = _kind(entities, "environment_state")
    check("horizon.environment", bool(environments), "At least one enterprise Environment State exists.")

    if environments:
        environment = environments[0]
        nodes = (environment.get("assets", []) or []) + (environment.get("identities", []) or [])
        entry_nodes = [
            item for item in nodes
            if item.get("entry_point")
            or str(item.get("internet_exposure", "")).lower() == "direct"
            or item.get("external") is True
        ]
        crown_nodes = [item for item in nodes if item.get("crown_jewel_ids")]
        signals = environment.get("intelligence_signals", []) or []

        check("horizon.entry-points", bool(entry_nodes), "At least one modeled entry/exposure node exists.")
        check("horizon.crown-jewel-nodes", bool(crown_nodes), "At least one environment node maps to a Crown Jewel.")
        check("horizon.relationships", bool(environment.get("relationships")), "Enterprise trust/dependency relationships are modeled.")
        check("horizon.controls", bool(environment.get("controls")), "Defensive controls are modeled with effectiveness.")
        check("horizon.telemetry", bool(environment.get("telemetry_sources")), "Telemetry sources are modeled for absence analysis.")
        check(
            "horizon.signal-status",
            all(str(signal.get("status", "candidate")).lower() in {"candidate", "accepted", "active", "validated", "confirmed", "expired"} for signal in signals),
            "Every intelligence signal has an explicit review lifecycle state.",
        )
        check(
            "horizon.accepted-forecast-boundary",
            isinstance(environment.get("accepted_forecasts", {}), dict),
            "Accepted analyst forecasts are stored separately from proposed scores.",
        )

    failed = [row for row in checks if not row["passed"]]
    return {
        "extension": "TCE-Horizon",
        "passed": not failed,
        "checks": checks,
        "failed_checks": [row["check"] for row in failed],
    }
