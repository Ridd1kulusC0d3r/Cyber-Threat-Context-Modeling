from __future__ import annotations

from importlib import resources
from typing import Any

import yaml


def _schema_map() -> dict[str, Any]:
    path = resources.files("tce").joinpath("data/telemetry-schema-map.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def schema_mappings(fields: list[str]) -> dict[str, dict[str, str | None]]:
    concepts = (_schema_map().get("concepts") or {})
    output: dict[str, dict[str, str | None]] = {}
    for field in fields:
        mapped = concepts.get(field, {})
        output[field] = {
            name: mapped.get(name)
            for name in ("ocsf", "ecs", "asim", "cim")
        }
    return output


def _ratio(required: set[str], available: set[str]) -> float:
    if not required:
        return 1.0
    return len(required & available) / len(required)


def evaluate_contract(
    contract: dict[str, Any],
    observed_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    profile = observed_profile or {}
    required = set(contract.get("required_fields", []) or [])
    available = set(
        profile.get("fields")
        or contract.get("available_fields", [])
        or []
    )
    identifiers = set(contract.get("entity_identifiers", []) or [])

    field_ratio = _ratio(required, available)
    identifier_ratio = _ratio(identifiers, available)

    declared_status = profile.get("status") or contract.get("status", "unknown")
    status_values = {
        "ready": 1.0,
        "healthy": 1.0,
        "partial": 0.6,
        "degraded": 0.5,
        "missing": 0.0,
        "unhealthy": 0.0,
        "unknown": 0.25,
    }
    source_health = status_values.get(str(declared_status).lower(), 0.25)
    normalization = 1.0 if contract.get("normalization") else 0.5
    integrity = 1.0 if (contract.get("integrity_requirements") or []) else 0.5

    score = round(
        100
        * (
            field_ratio * 0.45
            + identifier_ratio * 0.20
            + source_health * 0.15
            + normalization * 0.10
            + integrity * 0.10
        ),
        1,
    )

    if score >= 90 and field_ratio == 1 and identifier_ratio == 1:
        health = "ready"
    elif score >= 60:
        health = "partial"
    else:
        health = "insufficient"

    return {
        "id": contract.get("id"),
        "title": contract.get("title"),
        "health_score": score,
        "health": health,
        "required_fields": sorted(required),
        "available_fields": sorted(available),
        "missing_fields": sorted(required - available),
        "missing_entity_identifiers": sorted(identifiers - available),
        "declared_status": declared_status,
        "latency_target": contract.get("latency_target"),
        "normalization": contract.get("normalization"),
        "schema_mappings": schema_mappings(sorted(required | identifiers)),
    }


def evaluate_case_telemetry(
    entities: dict[str, dict],
    profiles: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    profiles = profiles or {}
    rows = []
    for wrapped in entities.values():
        if wrapped["kind"] != "telemetry_contract":
            continue
        contract = wrapped["data"]
        rows.append(evaluate_contract(contract, profiles.get(contract.get("id"), {})))

    average = (
        round(sum(row["health_score"] for row in rows) / len(rows), 1)
        if rows
        else None
    )
    return {
        "contracts": rows,
        "average_health": average,
        "ready": sum(1 for row in rows if row["health"] == "ready"),
        "partial": sum(1 for row in rows if row["health"] == "partial"),
        "insufficient": sum(1 for row in rows if row["health"] == "insufficient"),
    }
