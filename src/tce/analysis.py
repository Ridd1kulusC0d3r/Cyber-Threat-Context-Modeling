from __future__ import annotations

from collections import Counter, defaultdict, deque

from .graph import build_graph
from .scoring import score_scenario

STATUS_VALUE = {"covered": 100, "partial": 50, "missing": 0, "unknown": None}


def _by_kind(entities, kind):
    return [w["data"] for w in entities.values() if w["kind"] == kind]


def scenarios(entities):
    return _by_kind(entities, "scenario")


def detections(entities):
    return _by_kind(entities, "detection_use_case")


def telemetry_contracts(entities):
    return _by_kind(entities, "telemetry_contract")


def explicit_gaps(entities):
    return _by_kind(entities, "intelligence_gap")


def scored_scenarios(entities):
    return sorted((score_scenario(s) for s in scenarios(entities)), key=lambda x: x["score"], reverse=True)


def coverage_summary(entities):
    dims = ["telemetry", "analytic", "correlation", "validation", "response"]
    values = defaultdict(list)
    for detection in detections(entities):
        coverage = detection.get("coverage") or {}
        for dim in dims:
            value = STATUS_VALUE.get(coverage.get(dim, "unknown"))
            if value is not None:
                values[dim].append(value)
    return {
        dim: round(sum(values[dim]) / len(values[dim]), 1) if values[dim] else None
        for dim in dims
    }


def find_gaps(entities):
    output = []
    for gap in explicit_gaps(entities):
        if gap.get("status") not in {"answered", "accepted"}:
            output.append({
                "type": "intelligence",
                "id": gap.get("id"),
                "priority": gap.get("priority", "unknown"),
                "description": gap.get("question", ""),
            })

    detection_ids = {d.get("id") for d in detections(entities)}
    telemetry_ids = {t.get("id") for t in telemetry_contracts(entities)}

    for scenario in scenarios(entities):
        sid = scenario.get("id")
        refs = scenario.get("detection_use_cases") or []
        if not refs:
            output.append({"type": "detection", "id": sid, "priority": "high", "description": "Scenario has no detection use case"})
        for ref in refs:
            if ref not in detection_ids:
                output.append({"type": "detection", "id": sid, "priority": "high", "description": f"Missing detection object {ref}"})

        trefs = scenario.get("telemetry_requirements") or []
        if not trefs:
            output.append({"type": "telemetry", "id": sid, "priority": "high", "description": "Scenario has no telemetry contract"})
        for ref in trefs:
            if ref not in telemetry_ids:
                output.append({"type": "telemetry", "id": sid, "priority": "high", "description": f"Missing telemetry object {ref}"})

    for contract in telemetry_contracts(entities):
        status = contract.get("status", "unknown")
        if status in {"partial", "missing", "unknown"}:
            output.append({
                "type": "telemetry",
                "id": contract.get("id"),
                "priority": "high" if status == "missing" else "medium",
                "description": f"Telemetry status is {status}",
            })

    for detection in detections(entities):
        coverage = detection.get("coverage") or {}
        for dim in ("telemetry", "analytic", "correlation", "validation", "response"):
            status = coverage.get(dim, "unknown")
            if status in {"missing", "unknown"}:
                output.append({
                    "type": f"detection-{dim}",
                    "id": detection.get("id"),
                    "priority": "medium",
                    "description": f"{dim} coverage is {status}",
                })
    return output


def choke_points(entities):
    counts = Counter()
    for scenario in scenarios(entities):
        scored = score_scenario(scenario)
        if scored["band"] not in {"P0", "P1"}:
            continue
        seen = set()
        for step in ((scenario.get("attack_path") or {}).get("steps") or []):
            node = step.get("architecture_node_id")
            if node:
                seen.add(node)
        for node in seen:
            counts[node] += 1
    return [{"node": node, "critical_paths": count} for node, count in counts.most_common()]


def decision_trace(entities, entity_id):
    if entity_id not in entities:
        raise KeyError(f"Unknown entity: {entity_id}")
    graph = build_graph(entities)
    incoming = defaultdict(list)
    for edge in graph["edges"]:
        incoming[edge["to"]].append(edge)

    visited = set()
    queue = deque([(entity_id, 0)])
    rows = []
    while queue:
        current, depth = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        wrapped = entities.get(current)
        if wrapped:
            data = wrapped["data"]
            rows.append({
                "depth": depth,
                "id": current,
                "kind": wrapped["kind"],
                "label": data.get("title") or data.get("name") or data.get("question") or current,
            })
        for edge in incoming.get(current, []):
            queue.append((edge["from"], depth + 1))
    return rows
