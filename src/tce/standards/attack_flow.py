from __future__ import annotations

import json
import re
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import yaml

EXTENSION_ID = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"
CONFIDENCE = {"high": 85, "medium": 60, "low": 30, "unknown": 15}


def _id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, 'tce:' + seed)}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _confidence_label(value: int | None) -> str:
    value = int(value or 0)
    if value >= 75:
        return "high"
    if value >= 45:
        return "medium"
    if value > 0:
        return "low"
    return "unknown"


def scenario_to_attack_flow(scenario: dict, attack_index=None) -> dict:
    steps = ((scenario.get("attack_path") or {}).get("steps") or [])
    if not steps:
        raise ValueError("Scenario has no attack-path steps")

    timestamp = _now()
    creator_id = _id("identity", "creator")
    action_ids = [
        _id("attack-action", f"{scenario['id']}:{index}")
        for index in range(len(steps))
    ]
    objects = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": creator_id,
        "created": timestamp,
        "modified": timestamp,
        "name": "Threat Context Engineering",
        "identity_class": "organization",
    }]

    for index, step in enumerate(steps):
        technique_ids = step.get("attack_techniques") or []
        technique_id = technique_ids[0] if technique_ids else None
        technique_obj = attack_index.get(technique_id) if attack_index and technique_id else None
        action = {
            "type": "attack-action",
            "spec_version": "2.1",
            "id": action_ids[index],
            "created_by_ref": creator_id,
            "created": timestamp,
            "modified": timestamp,
            "name": (technique_obj or {}).get("name") or step.get("behavior") or f"Step {index + 1}",
            "description": step.get("behavior", ""),
            "confidence": CONFIDENCE.get(scenario.get("confidence", "unknown"), 15),
            "extensions": {EXTENSION_ID: {"extension_type": "new-sdo"}},
        }
        if technique_id:
            action["technique_id"] = technique_id
            if attack_index:
                ref = attack_index.stix_ref(technique_id)
                if ref:
                    action["technique_ref"] = ref
        if index + 1 < len(action_ids):
            action["effect_refs"] = [action_ids[index + 1]]
        objects.append(action)

    objects.append({
        "type": "attack-flow",
        "spec_version": "2.1",
        "id": _id("attack-flow", scenario["id"]),
        "created_by_ref": creator_id,
        "created": timestamp,
        "modified": timestamp,
        "name": scenario.get("title") or scenario["id"],
        "description": scenario.get("objective", ""),
        "scope": "attack-tree",
        "start_refs": [action_ids[0]],
        "confidence": CONFIDENCE.get(scenario.get("confidence", "unknown"), 15),
        "extensions": {EXTENSION_ID: {"extension_type": "new-sdo"}},
    })
    return {
        "type": "bundle",
        "id": _id("bundle", f"attack-flow:{scenario['id']}"),
        "objects": objects,
    }


def attack_flow_to_scenario(bundle: dict, attack_index=None) -> dict:
    objects = {obj.get("id"): obj for obj in bundle.get("objects", []) if obj.get("id")}
    flows = [obj for obj in objects.values() if obj.get("type") == "attack-flow"]
    if not flows:
        raise ValueError("Bundle contains no attack-flow object")

    flow = flows[0]
    queue = deque((ref, None) for ref in flow.get("start_refs", []) or [])
    seen = set()
    ordered = []

    while queue:
        ref, parent = queue.popleft()
        if ref in seen:
            continue
        seen.add(ref)
        action = objects.get(ref)
        if not action or action.get("type") != "attack-action":
            continue
        ordered.append((action, parent))
        for child in action.get("effect_refs", []) or []:
            queue.append((child, ref))

    steps = []
    for index, (action, parent) in enumerate(ordered, start=1):
        technique_id = action.get("technique_id")
        if not technique_id and attack_index and action.get("technique_ref"):
            technique_obj = attack_index.by_stix_id.get(action["technique_ref"])
            if technique_obj:
                for ext_id, obj in attack_index.by_external_id.items():
                    if obj.get("id") == technique_obj.get("id") and ext_id.startswith("T"):
                        technique_id = ext_id
                        break

        step = {
            "order": index,
            "behavior": action.get("description") or action.get("name") or f"Imported action {index}",
            "attack_techniques": [technique_id] if technique_id else [],
            "architecture_node_id": "",
            "trust_boundary_crossed": "",
            "required_privilege": "",
            "dependencies": [],
            "expected_observable": "",
        }
        if parent:
            step["x_tce_attack_flow_parent_ref"] = parent
        step["x_tce_attack_flow_action_ref"] = action.get("id")
        steps.append(step)

    flow_id = flow.get("id", "attack-flow--unknown").split("--")[-1][:8]
    return {
        "version": "0.3",
        "scenario": {
            "id": f"TS-IMPORT-{flow_id}",
            "title": flow.get("name") or "Imported Attack Flow",
            "objective": flow.get("description") or "",
            "hypothesis_ids": [],
            "target_crown_jewels": [],
            "initial_conditions": [],
            "preconditions": [],
            "threat_context": {
                "actors": [],
                "campaigns": [],
                "sector_relevance": "",
                "evidence_ids": [],
                "theory_rationale": "Imported from Attack Flow; analyst review required.",
                "freshness": "unknown",
            },
            "attack_path": {
                "id": f"AP-IMPORT-{flow_id}",
                "entry_vector": "",
                "steps": steps,
            },
            "impact": {"business": "", "technical": ""},
            "priority": {
                "crown_jewel_criticality": 0,
                "threat_relevance": 0,
                "attack_path_feasibility": 0,
                "exposure": 0,
                "control_weakness": 0,
                "detection_gap": 0,
                "calculated_score": None,
                "band": "",
                "rationale": "",
            },
            "confidence": _confidence_label(flow.get("confidence")),
            "defensive_design": {
                "prevent": [],
                "constrain": [],
                "detect": [],
                "disrupt": [],
                "recover": [],
                "d3fend_refs": [],
                "nist_refs": [],
            },
            "telemetry_requirements": [],
            "detection_use_cases": [],
            "validation_ids": [],
            "residual_risk": "",
            "assumptions": [],
            "owner": "",
            "review_date": "",
            "x_tce_import": {
                "source": "Attack Flow",
                "flow_id": flow.get("id"),
                "review_required": True,
                "auto_merge": False,
            },
        },
    }


def write_attack_flow(bundle: dict, output: str | Path):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return path


def write_imported_scenario(data: dict, output: str | Path):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path
