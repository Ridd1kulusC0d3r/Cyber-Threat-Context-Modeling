from __future__ import annotations

import json
import uuid
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .scoring import score_scenario


def detection_specs(entities: dict[str, dict]) -> list[dict[str, Any]]:
    return [
        wrapped["data"]
        for wrapped in entities.values()
        if wrapped["kind"] == "detection_specification"
    ]


def correlation_patterns() -> list[dict[str, Any]]:
    path = resources.files("tce").joinpath("data/detection-correlation-patterns.yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data.get("patterns", []) or []


def _scenario_specs(entities: dict[str, dict], scenario_id: str) -> list[dict[str, Any]]:
    rows = []
    for spec in detection_specs(entities):
        if scenario_id in (spec.get("scenario_ids") or []):
            rows.append(spec)
    return rows


def compile_backlog(entities: dict[str, dict]) -> list[dict[str, Any]]:
    telemetry = {
        entity_id: wrapped["data"]
        for entity_id, wrapped in entities.items()
        if wrapped["kind"] == "telemetry_contract"
    }
    validations = {
        entity_id: wrapped["data"]
        for entity_id, wrapped in entities.items()
        if wrapped["kind"] == "validation"
    }

    backlog = []
    for entity_id, wrapped in entities.items():
        if wrapped["kind"] != "scenario":
            continue
        scenario = wrapped["data"]
        scored = score_scenario(scenario)
        specs = _scenario_specs(entities, entity_id)
        telemetry_ids = scenario.get("telemetry_requirements", []) or []

        missing_telemetry = [
            ref for ref in telemetry_ids
            if ref not in telemetry or telemetry[ref].get("status") in {"missing", "unknown"}
        ]
        partial_telemetry = [
            ref for ref in telemetry_ids
            if ref in telemetry and telemetry[ref].get("status") == "partial"
        ]

        if not specs:
            backlog.append({
                "scenario_id": entity_id,
                "scenario_title": scenario.get("title"),
                "band": scored["band"],
                "score": scored["score"],
                "work_type": "detection-specification",
                "priority": "highest" if scored["band"] in {"P0", "P1"} else "normal",
                "reason": "No Detection Specification is linked to the scenario.",
                "required_telemetry": telemetry_ids,
            })
            continue

        for spec in specs:
            validation_ids = spec.get("validation_ids", []) or []
            untested = [
                ref for ref in validation_ids
                if ref not in validations or validations[ref].get("status") != "passed"
            ]
            implementation_states = {
                item.get("status", "unknown")
                for item in spec.get("implementations", []) or []
            }
            ready_impl = bool(implementation_states & {"implemented", "validated", "production"})

            reasons = []
            if missing_telemetry:
                reasons.append("missing telemetry")
            if partial_telemetry:
                reasons.append("partial telemetry")
            if not ready_impl:
                reasons.append("no implemented analytic")
            if not validation_ids or untested:
                reasons.append("validation incomplete")

            backlog.append({
                "scenario_id": entity_id,
                "scenario_title": scenario.get("title"),
                "band": scored["band"],
                "score": scored["score"],
                "detection_specification_id": spec.get("id"),
                "title": spec.get("title"),
                "work_type": "detection-engineering",
                "priority": "highest" if scored["band"] in {"P0", "P1"} else "normal",
                "reasons": reasons,
                "telemetry_contract_ids": spec.get("telemetry_contract_ids", []),
                "validation_ids": validation_ids,
                "implementation_states": sorted(implementation_states),
            })

    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    return sorted(
        backlog,
        key=lambda row: (
            order.get(row.get("band"), 9),
            0 if row.get("reasons") or row.get("reason") else 1,
            -float(row.get("score", 0)),
        ),
    )


def sigma_document(spec: dict[str, Any]) -> dict[str, Any]:
    sigma = spec.get("sigma") or {}
    if not sigma:
        raise ValueError(f"{spec.get('id')}: no sigma mapping is defined")

    rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"tce:{spec.get('id')}"))
    return {
        "title": spec.get("title") or spec.get("id"),
        "id": rule_id,
        "status": sigma.get("status", "experimental"),
        "description": (spec.get("analytic_concept") or {}).get("description", ""),
        "references": spec.get("references", []) or [],
        "tags": [
            f"attack.{technique.lower()}"
            for technique in spec.get("attack_techniques", []) or []
        ],
        "logsource": sigma.get("logsource", {}),
        "detection": sigma.get("detection", {}),
        "falsepositives": (spec.get("analytic_concept") or {}).get(
            "benign_alternatives", []
        ),
        "level": spec.get("severity", "medium"),
    }


def write_sigma(spec: dict[str, Any], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(sigma_document(spec), sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return path


def write_backlog(rows: list[dict[str, Any]], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() in {".yaml", ".yml"}:
        path.write_text(
            yaml.safe_dump({"detection_backlog": rows}, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
    else:
        path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
