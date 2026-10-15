from __future__ import annotations

from typing import Any

from .analysis import coverage_summary, scored_scenarios


def _by_kind(entities: dict[str, dict], kind: str) -> dict[str, dict[str, Any]]:
    return {
        entity_id: wrapped["data"]
        for entity_id, wrapped in entities.items()
        if wrapped["kind"] == kind
    }


def _status(values: list[str], *, empty: str = "unknown") -> str:
    normalized = [str(value or "").lower() for value in values if value]
    if not normalized:
        return empty
    if all(value in {"passed", "implemented", "ready", "covered", "active"} for value in normalized):
        return "covered"
    if any(value in {"failed", "missing", "blocked"} for value in normalized):
        return "missing"
    if any(value in {"partial", "draft", "experimental", "pending", "proposed"} for value in normalized):
        return "partial"
    return normalized[0]


def _attack_label(technique_id: str, attack_index: Any = None) -> str:
    if attack_index is None:
        return technique_id
    try:
        item = attack_index.get(technique_id)
    except Exception:
        item = None
    if not item:
        return technique_id
    name = item.get("name")
    return f"{technique_id} · {name}" if name else technique_id


def build_operational_matrix(
    entities: dict[str, dict],
    *,
    attack_index: Any = None,
) -> dict[str, Any]:
    scenarios = _by_kind(entities, "scenario")
    contexts = _by_kind(entities, "threat_context")
    telemetry = _by_kind(entities, "telemetry_contract")
    detections = _by_kind(entities, "detection_specification")
    validations = _by_kind(entities, "validation")
    decisions = _by_kind(entities, "decision")
    gaps = _by_kind(entities, "intelligence_gap")
    crown_jewels = _by_kind(entities, "crown_jewel")

    scores = {row["id"]: row for row in scored_scenarios(entities)}
    rows = []

    for scenario_id, scenario in scenarios.items():
        technique_ids = []
        for step in ((scenario.get("attack_path") or {}).get("steps") or []):
            technique_ids.extend(step.get("attack_techniques", []) or [])

        detection_ids = scenario.get("detection_specification_ids", []) or []
        for detection_id in detection_ids:
            technique_ids.extend(detections.get(detection_id, {}).get("attack_techniques", []) or [])
        technique_ids = sorted(set(technique_ids))

        telemetry_ids = scenario.get("telemetry_requirements", []) or []
        validation_ids = scenario.get("validation_ids", []) or []

        linked_decisions = [
            decision_id
            for decision_id, decision in decisions.items()
            if scenario_id in (decision.get("scenario_ids", []) or [])
        ]
        linked_gaps = [
            gap_id
            for gap_id, gap in gaps.items()
            if scenario_id in (gap.get("affected_scenario_ids", []) or [])
        ]

        telemetry_statuses = [
            telemetry.get(entity_id, {}).get("status")
            for entity_id in telemetry_ids
            if entity_id in telemetry
        ]
        detection_statuses = [
            detections.get(entity_id, {}).get("status")
            for entity_id in detection_ids
            if entity_id in detections
        ]
        validation_statuses = [
            validations.get(entity_id, {}).get("status")
            for entity_id in validation_ids
            if entity_id in validations
        ]

        score = scores.get(scenario_id, {})
        rows.append({
            "scenario_id": scenario_id,
            "title": scenario.get("title", scenario_id),
            "band": score.get("band"),
            "score": score.get("score"),
            "confidence": scenario.get("confidence", "unknown"),
            "crown_jewel_ids": scenario.get("target_crown_jewels", []) or [],
            "threat_context_ids": scenario.get("threat_context_ids", []) or [],
            "attack_techniques": [
                {"id": technique_id, "label": _attack_label(technique_id, attack_index)}
                for technique_id in technique_ids
            ],
            "telemetry_contract_ids": telemetry_ids,
            "telemetry_status": _status(telemetry_statuses),
            "detection_specification_ids": detection_ids,
            "detection_status": _status(detection_statuses),
            "validation_ids": validation_ids,
            "validation_status": _status(validation_statuses),
            "decision_ids": linked_decisions,
            "gap_ids": linked_gaps,
            "review_date": scenario.get("review_date"),
        })

    rows.sort(key=lambda row: (
        {"P0": 0, "P1": 1, "P2": 2, "P3": 3}.get(row.get("band"), 9),
        -(row.get("score") or 0),
        row["scenario_id"],
    ))

    coverage = coverage_summary(entities)
    techniques = {
        item["id"]
        for row in rows
        for item in row["attack_techniques"]
    }

    dimensions = [
        {"id": "mission", "label": "Mission & Crown Jewels", "count": len(crown_jewels)},
        {"id": "context", "label": "Threat Context", "count": len(contexts)},
        {"id": "behavior", "label": "MITRE ATT&CK Behavior", "count": len(techniques)},
        {"id": "observability", "label": "Observability / Telemetry", "count": len(telemetry)},
        {"id": "detection", "label": "TCEM Detection", "count": len(detections)},
        {"id": "validation", "label": "Validation", "count": len(validations)},
        {"id": "decision", "label": "Decision Trace", "count": len(decisions)},
        {"id": "gaps", "label": "Managed Gaps", "count": len(gaps)},
    ]

    return {
        "name": "TCEM Operational Matrix",
        "discipline": "Threat Context Engineering (TCE)",
        "method": "Threat Context Engineering Method (TCEM)",
        "rows": rows,
        "dimensions": dimensions,
        "coverage": coverage,
        "meta": {
            "scenario_count": len(rows),
            "technique_count": len(techniques),
            "matrix_is_probability_model": False,
            "visibility_model": "TCEM coverage model with DeTT&CT-aligned separation of visibility and detection",
            "review_required": True,
        },
    }
