from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _value(event: dict[str, Any], field: str):
    if field in event:
        return event[field]
    current: Any = event
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _predicate(event: dict[str, Any], clause: dict[str, Any]) -> bool:
    field = clause.get("field")
    op = clause.get("op", "eq")
    actual = _value(event, field)

    if op == "exists":
        return actual is not None
    if op == "eq":
        return actual == clause.get("value")
    if op == "neq":
        return actual != clause.get("value")
    if op == "in":
        return actual in (clause.get("values") or [])
    if op == "contains":
        needle = clause.get("value")
        if isinstance(actual, (list, tuple, set)):
            return needle in actual
        if isinstance(actual, str):
            return str(needle) in actual
        return False
    raise ValueError(f"Unsupported validation operator: {op}")


def _matches_stage(event: dict[str, Any], stage: dict[str, Any]) -> bool:
    return all(_predicate(event, clause) for clause in stage.get("all", []) or [])


def _group_value(event: dict[str, Any], fields: list[str]) -> tuple:
    return tuple(_value(event, field) for field in fields)


def evaluate_logic(logic: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    pattern = logic.get("pattern", "single-event")
    stages = logic.get("stages", []) or []
    group_by = logic.get("group_by", []) or []

    if not stages:
        return {"matches": 0, "matched_event_indexes": [], "groups": []}

    if pattern == "single-event":
        indexes = [
            index
            for index, event in enumerate(events)
            if _matches_stage(event, stages[0])
        ]
        return {
            "matches": len(indexes),
            "matched_event_indexes": indexes,
            "groups": [],
        }

    if pattern == "threshold":
        threshold = int(logic.get("threshold", 1))
        groups: dict[tuple, list[int]] = {}
        for index, event in enumerate(events):
            if not _matches_stage(event, stages[0]):
                continue
            key = _group_value(event, group_by)
            groups.setdefault(key, []).append(index)
        matched = [
            {"group": list(key), "event_indexes": indexes}
            for key, indexes in groups.items()
            if len(indexes) >= threshold
        ]
        return {
            "matches": len(matched),
            "matched_event_indexes": sorted(
                {i for row in matched for i in row["event_indexes"]}
            ),
            "groups": matched,
        }

    if pattern == "ordered-sequence":
        matches = []
        used_indexes: set[int] = set()
        for start, event in enumerate(events):
            if not _matches_stage(event, stages[0]):
                continue
            key = _group_value(event, group_by)
            indexes = [start]
            cursor = start + 1
            ok = True
            for stage in stages[1:]:
                found = None
                while cursor < len(events):
                    candidate = events[cursor]
                    if (
                        _group_value(candidate, group_by) == key
                        and _matches_stage(candidate, stage)
                    ):
                        found = cursor
                        cursor += 1
                        break
                    cursor += 1
                if found is None:
                    ok = False
                    break
                indexes.append(found)
            if ok:
                matches.append({"group": list(key), "event_indexes": indexes})
                used_indexes.update(indexes)
        return {
            "matches": len(matches),
            "matched_event_indexes": sorted(used_indexes),
            "groups": matches,
        }

    raise ValueError(f"Unsupported validation pattern: {pattern}")


def load_events(path: str | Path) -> list[dict[str, Any]]:
    file = Path(path)
    if file.suffix.lower() == ".jsonl":
        return [
            json.loads(line)
            for line in file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    data = json.loads(file.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    return data.get("events", []) or []


def run_validation(
    entities: dict[str, dict],
    validation_id: str,
    case_dir: str | Path,
) -> dict[str, Any]:
    wrapped = entities.get(validation_id)
    if not wrapped or wrapped["kind"] != "validation":
        raise KeyError(f"Unknown validation: {validation_id}")
    validation = wrapped["data"]

    spec_ids = validation.get("detection_specification_ids", []) or []
    if not spec_ids:
        raise ValueError(f"{validation_id}: no detection_specification_ids")

    fixture = validation.get("fixture")
    if not fixture:
        raise ValueError(f"{validation_id}: no fixture configured")
    fixture_path = Path(case_dir) / fixture
    events = load_events(fixture_path)

    results = []
    for spec_id in spec_ids:
        spec_wrapped = entities.get(spec_id)
        if not spec_wrapped or spec_wrapped["kind"] != "detection_specification":
            raise ValueError(f"{validation_id}: missing Detection Specification {spec_id}")
        spec = spec_wrapped["data"]
        logic = spec.get("validation_logic") or {}
        result = evaluate_logic(logic, events)
        expected = validation.get("expected") or {}
        minimum = int(expected.get("min_matches", 1))
        maximum = expected.get("max_matches")
        passed = result["matches"] >= minimum and (
            maximum is None or result["matches"] <= int(maximum)
        )
        results.append({
            "detection_specification_id": spec_id,
            "passed": passed,
            "expected": expected,
            **result,
        })

    passed = all(row["passed"] for row in results)
    return {
        "validation_id": validation_id,
        "method": validation.get("method"),
        "fixture": str(fixture_path),
        "events": len(events),
        "passed": passed,
        "status": "passed" if passed else "failed",
        "results": results,
    }
