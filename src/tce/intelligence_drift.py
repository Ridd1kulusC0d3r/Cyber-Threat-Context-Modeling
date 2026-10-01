from __future__ import annotations

import json
from pathlib import Path
from typing import Any


COLLECTIONS = (
    "adversaries",
    "campaigns",
    "detections",
    "validation_references",
    "ai_security_surfaces",
)


def _item_id(item: dict[str, Any]) -> str:
    return str(
        item.get("id")
        or item.get("attack_id")
        or item.get("name")
        or json.dumps(item, sort_keys=True)
    )


def _flatten(snapshot: dict[str, Any]) -> dict[str, dict[str, set[str]]]:
    output: dict[str, dict[str, set[str]]] = {}
    for context in snapshot.get("contexts", []) or []:
        context_id = context.get("context_id") or "unknown"
        buckets = {name: set() for name in COLLECTIONS}
        for pack in context.get("domain_packs", []) or []:
            for name in COLLECTIONS:
                for item in pack.get(name, []) or []:
                    if isinstance(item, dict):
                        buckets[name].add(_item_id(item))
        output[context_id] = buckets
    return output


def diff_context_intelligence(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    old = _flatten(before)
    new = _flatten(after)
    contexts = sorted(set(old) | set(new))
    changes = []

    for context_id in contexts:
        old_buckets = old.get(context_id, {name: set() for name in COLLECTIONS})
        new_buckets = new.get(context_id, {name: set() for name in COLLECTIONS})
        delta = {}
        for name in COLLECTIONS:
            added = sorted(new_buckets.get(name, set()) - old_buckets.get(name, set()))
            removed = sorted(old_buckets.get(name, set()) - new_buckets.get(name, set()))
            if added or removed:
                delta[name] = {"added": added, "removed": removed}
        if delta:
            changes.append({
                "context_id": context_id,
                "changes": delta,
                "review_required": True,
            })

    return {
        "changed_contexts": len(changes),
        "changes": changes,
        "policy": {
            "review_required": True,
            "auto_change_scenario_priority": False,
            "auto_promote_external_intelligence": False,
        },
    }


def diff_files(before: str | Path, after: str | Path) -> dict[str, Any]:
    return diff_context_intelligence(
        json.loads(Path(before).read_text(encoding="utf-8")),
        json.loads(Path(after).read_text(encoding="utf-8")),
    )
