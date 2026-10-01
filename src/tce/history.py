from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analysis import coverage_summary, scored_scenarios
from .context import assess_contexts
from .telemetry import evaluate_case_telemetry


def _fingerprint(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_snapshot(entities: dict[str, dict]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    fingerprints = {}
    validation_status = {}

    for entity_id, wrapped in entities.items():
        kind = wrapped["kind"]
        counts[kind] = counts.get(kind, 0) + 1
        fingerprints[entity_id] = {
            "kind": kind,
            "sha256": _fingerprint(wrapped["data"]),
        }
        if kind == "validation":
            validation_status[entity_id] = wrapped["data"].get("status", "unknown")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "coverage": coverage_summary(entities),
        "telemetry": evaluate_case_telemetry(entities),
        "scenarios": {
            row["id"]: {
                "score": row["score"],
                "band": row["band"],
                "confidence": row["confidence"],
            }
            for row in scored_scenarios(entities)
        },
        "contexts": assess_contexts(entities),
        "validations": validation_status,
        "entities": fingerprints,
    }


def write_snapshot(snapshot: dict[str, Any], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_snapshot(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def diff_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_entities = before.get("entities", {})
    after_entities = after.get("entities", {})
    added = sorted(set(after_entities) - set(before_entities))
    removed = sorted(set(before_entities) - set(after_entities))
    changed = sorted(
        entity_id
        for entity_id in set(before_entities) & set(after_entities)
        if before_entities[entity_id].get("sha256") != after_entities[entity_id].get("sha256")
    )

    coverage_delta = {}
    for dim in set(before.get("coverage", {})) | set(after.get("coverage", {})):
        old = before.get("coverage", {}).get(dim)
        new = after.get("coverage", {}).get(dim)
        coverage_delta[dim] = {
            "before": old,
            "after": new,
            "delta": None if old is None or new is None else round(new - old, 1),
        }

    band_changes = []
    before_scenarios = before.get("scenarios", {})
    after_scenarios = after.get("scenarios", {})
    for sid in sorted(set(before_scenarios) & set(after_scenarios)):
        old = before_scenarios[sid]
        new = after_scenarios[sid]
        if old.get("band") != new.get("band") or old.get("score") != new.get("score"):
            band_changes.append({
                "scenario_id": sid,
                "before": old,
                "after": new,
            })

    before_tc = {
        row["id"]: row
        for row in before.get("telemetry", {}).get("contracts", []) or []
    }
    after_tc = {
        row["id"]: row
        for row in after.get("telemetry", {}).get("contracts", []) or []
    }
    telemetry_changes = []
    for tid in sorted(set(before_tc) & set(after_tc)):
        old = before_tc[tid].get("health_score")
        new = after_tc[tid].get("health_score")
        if old != new:
            telemetry_changes.append({
                "telemetry_contract_id": tid,
                "before": old,
                "after": new,
                "delta": round(new - old, 1),
                "direction": "improved" if new > old else "regressed",
            })

    return {
        "before": before.get("generated_at"),
        "after": after.get("generated_at"),
        "entities": {"added": added, "removed": removed, "changed": changed},
        "coverage": coverage_delta,
        "scenario_changes": band_changes,
        "telemetry_changes": telemetry_changes,
        "validation_changes": {
            key: {
                "before": before.get("validations", {}).get(key),
                "after": after.get("validations", {}).get(key),
            }
            for key in sorted(
                set(before.get("validations", {})) | set(after.get("validations", {}))
            )
            if before.get("validations", {}).get(key)
            != after.get("validations", {}).get(key)
        },
    }
