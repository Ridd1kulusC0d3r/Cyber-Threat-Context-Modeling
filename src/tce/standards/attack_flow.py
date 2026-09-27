from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

EXTENSION_ID = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"
CONFIDENCE = {"high": 85, "medium": 60, "low": 30, "unknown": 15}


def _id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, 'tce:' + seed)}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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


def write_attack_flow(bundle: dict, output: str | Path):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return path
