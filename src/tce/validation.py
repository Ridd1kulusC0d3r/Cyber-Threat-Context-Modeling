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
    "detection_specification": "DSP-",
    "intelligence_gap": "GAP-",
    "decision": "DEC-",
    "validation": "VAL-",
    "threat_context": "CTX-",
    "environment_state": "ENV-",
    "preemptive_action": "PA-",
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
    "detection_specification": ["id", "title", "scenario_ids", "telemetry_contract_ids", "analytic_concept", "validation_logic", "implementations", "status"],
    "intelligence_gap": ["id", "question", "priority", "status"],
    "decision": ["id", "title", "statement", "status"],
    "validation": ["id", "method", "status"],
    "threat_context": ["id", "name", "lens_id", "relevance", "status"],
    "environment_state": ["id", "name", "snapshot_at", "assets", "relationships"],
    "preemptive_action": ["id", "name", "action_class", "status", "review_required"],
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
            if re.match(r"^(CASE|IR|CJ|ARCH|EV|TH|TS|TC|DU|DSP|GAP|DEC|VAL|CTX|ENV|PA)-", ref) and ref not in known:
                errors.append(f"{entity_id}: broken reference {ref}")

        if kind == "environment_state":
            nodes = {}
            for item in (data.get("assets", []) or []) + (data.get("identities", []) or []):
                node_id = item.get("id")
                if not node_id:
                    errors.append(f"{entity_id}: environment node has no id")
                    continue
                if node_id in nodes:
                    errors.append(f"{entity_id}: duplicate environment node {node_id}")
                nodes[node_id] = item

                for crown_id in item.get("crown_jewel_ids", []) or []:
                    if crown_id not in known:
                        errors.append(f"{entity_id}: environment node {node_id} references unknown crown jewel {crown_id}")

            control_ids = set()
            for control in data.get("controls", []) or []:
                control_id = control.get("id")
                if not control_id:
                    errors.append(f"{entity_id}: control has no id")
                    continue
                control_ids.add(control_id)
                value = control.get("effectiveness", 0)
                if not isinstance(value, (int, float)) or not 0 <= value <= 1:
                    errors.append(f"{entity_id}: control {control_id} effectiveness must be 0..1")

            relationship_ids = set()
            for rel in data.get("relationships", []) or []:
                rel_id = rel.get("id")
                if not rel_id:
                    errors.append(f"{entity_id}: relationship has no id")
                else:
                    if rel_id in relationship_ids:
                        errors.append(f"{entity_id}: duplicate relationship {rel_id}")
                    relationship_ids.add(rel_id)

                source = rel.get("from")
                target = rel.get("to")
                if source not in nodes:
                    errors.append(f"{entity_id}: relationship {rel_id} has unknown source {source}")
                if target not in nodes:
                    errors.append(f"{entity_id}: relationship {rel_id} has unknown target {target}")
                for control_id in rel.get("control_ids", []) or []:
                    if control_id not in control_ids:
                        errors.append(f"{entity_id}: relationship {rel_id} references unknown control {control_id}")

            for item in nodes.values():
                for control_id in item.get("control_ids", []) or []:
                    if control_id not in control_ids:
                        errors.append(f"{entity_id}: node {item.get('id')} references unknown control {control_id}")

            telemetry_ids = set()
            for source in data.get("telemetry_sources", []) or []:
                telemetry_id = source.get("id")
                if not telemetry_id:
                    errors.append(f"{entity_id}: telemetry source has no id")
                elif telemetry_id in telemetry_ids:
                    errors.append(f"{entity_id}: duplicate telemetry source {telemetry_id}")
                else:
                    telemetry_ids.add(telemetry_id)

            for signal in data.get("vulnerability_signals", []) or []:
                target_id = signal.get("target_id")
                if target_id not in nodes:
                    errors.append(f"{entity_id}: vulnerability signal references unknown target {target_id}")
                epss = signal.get("epss")
                if epss is not None and (not isinstance(epss, (int, float)) or not 0 <= epss <= 1):
                    errors.append(f"{entity_id}: vulnerability signal EPSS must be 0..1")

        if kind == "preemptive_action":
            if data.get("review_required") is not True:
                errors.append(f"{entity_id}: preemptive actions must remain review_required")

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
