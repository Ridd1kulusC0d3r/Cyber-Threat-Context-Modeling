from __future__ import annotations

import json
from pathlib import Path


def export_navigator_layer(entities: dict[str, dict], name: str = "TCE ATT&CK Layer") -> dict:
    seen = {}
    for wrapped in entities.values():
        if wrapped["kind"] != "scenario":
            continue
        scenario = wrapped["data"]
        for step in ((scenario.get("attack_path") or {}).get("steps") or []):
            for technique_id in step.get("attack_techniques", []) or []:
                seen.setdefault(technique_id, []).append(scenario.get("id"))
    return {
        "name": name,
        "domain": "enterprise-attack",
        "description": "Generated from Threat Context Engineering scenarios.",
        "techniques": [
            {
                "techniqueID": tid,
                "comment": "Scenarios: " + ", ".join(sorted(set(sids))),
                "enabled": True,
            }
            for tid, sids in sorted(seen.items())
        ],
    }


def write_navigator(layer: dict, output: str | Path):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    return path
