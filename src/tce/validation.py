from __future__ import annotations

import re
from typing import Any

from .graph import REFERENCE_FIELDS

PREFIX_BY_KIND = {
    "case": "CASE-",
    "intelligence_requirement": "IR-",
    "crown_jewel": "CJ-",
    "architecture": "ARCH-",
    "evidence": "EV-",
    "hypothesis": "TH-",
    "scenario": "TS-",
    "telemetry_contract": "TC-",
    "detection_use_case": "DU-",
    "intelligence_gap": "GAP-",
    "decision": "DEC-",
    "validation": "VAL-",
    "threat_context": "CTX-",
}

REQUIRED = {
    "case": ["id", "name", "mission"],
    "intelligence_requirement": ["id", "question", "decision_supported"],
    "crown_jewel": ["id", "name", "rationale"],
    "architecture": ["id", "name", "nodes"],
    "evidence": ["id", "claim", "evidence_state"],
    "hypothesis": ["id", "statement", "confidence", "status"],
    "scenario": ["id", "title", "objective", "priority"],
    "telemetry_contract": ["id", "behavior", "observable", "status"],
    "detection_use_case": ["id", "title", "coverage"],
    "intelligence_gap": ["id", "question", "priority", "status"],
    "decision": ["id", "title", "statement", "status"],
    "validation": ["id", "method", "status"],
    "threat_context": ["id", "name", "lens_id", "relevance", "status"],
}


def _refs(value: Any, field: str | None = None):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _refs(child, key)
    elif isinstance(value, list):
        if field in REFERENCE_FIELDS:
            for child in value:
                if isinstance(child, str):
                    yield child
        else:
            for child in value:
                yield from _refs(child, field)


def validate_entities(entities: dict[str, dict]) -> list[str]:
    errors: list[str] = []
    known = set(entities)

    for entity_id, wrapped in entities.items():
        kind = wrapped["kind"]
        data = wrapped["data"]
        expected = PREFIX_BY_KIND.get(kind)
        if expected and not entity_id.startswith(expected):
            errors.append(f"{entity_id}: expected prefix {expected} for kind {kind}")

        for field in REQUIRED.get(kind, []):
            value = data.get(field)
            if value is None or value == "" or value == []:
                errors.append(f"{entity_id}: required field '{field}' is empty")

        for ref in _refs(data):
            if re.match(r"^(CASE|IR|CJ|ARCH|EV|TH|TS|TC|DU|GAP|DEC|VAL|CTX)-", ref) and ref not in known:
                errors.append(f"{entity_id}: broken reference {ref}")

        if kind == "scenario":
            priority = data.get("priority") or {}
            for field in (
                "crown_jewel_criticality",
                "threat_relevance",
                "attack_path_feasibility",
                "exposure",
                "control_weakness",
                "detection_gap",
            ):
                value = priority.get(field, 0)
                if not isinstance(value, (int, float)) or not 0 <= value <= 5:
                    errors.append(f"{entity_id}: priority.{field} must be 0..5")

    return errors
