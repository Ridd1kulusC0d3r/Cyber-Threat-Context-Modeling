from __future__ import annotations

from typing import Any

REFERENCE_FIELDS = {
    "linked_crown_jewels",
    "information_gap_ids",
    "intelligence_requirement_ids",
    "target_crown_jewels",
    "supporting_evidence",
    "contradicting_evidence",
    "attack_path_ids",
    "hypothesis_ids",
    "evidence_ids",
    "telemetry_requirements",
    "detection_use_cases",
    "telemetry_contract_ids",
    "validation_ids",
    "scenario_ids",
    "detection_use_case_ids",
    "affected_requirement_ids",
    "affected_hypothesis_ids",
    "affected_scenario_ids",
    "crown_jewel_ids",
}


def _walk_refs(value: Any, field: str | None = None):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_refs(child, key)
    elif isinstance(value, list):
        if field in REFERENCE_FIELDS:
            for child in value:
                if isinstance(child, str):
                    yield child, field
        else:
            for child in value:
                yield from _walk_refs(child, field)


def build_graph(entities: dict[str, dict]) -> dict:
    nodes = []
    edges = []
    known = set(entities)

    for entity_id, wrapped in entities.items():
        label = wrapped["data"].get("title") or wrapped["data"].get("name") or wrapped["data"].get("question") or entity_id
        nodes.append({"id": entity_id, "kind": wrapped["kind"], "label": label})

        for ref, relation in _walk_refs(wrapped["data"]):
            if ref in known:
                edges.append({"from": ref, "to": entity_id, "relation": relation})

        if wrapped["kind"] == "evidence":
            for target in wrapped["data"].get("supports", []) or []:
                if target in known:
                    edges.append({"from": entity_id, "to": target, "relation": "supports"})
            for target in wrapped["data"].get("contradicts", []) or []:
                if target in known:
                    edges.append({"from": entity_id, "to": target, "relation": "contradicts"})

        if wrapped["kind"] == "architecture":
            architecture_id = entity_id
            for node in wrapped["data"].get("nodes", []) or []:
                node_id = node.get("id")
                if node_id:
                    nodes.append({"id": node_id, "kind": "architecture_node", "label": node.get("name", node_id)})
                    edges.append({"from": architecture_id, "to": node_id, "relation": "contains"})
            for rel in wrapped["data"].get("relationships", []) or []:
                if isinstance(rel, dict) and rel.get("from") and rel.get("to"):
                    edges.append({"from": rel["from"], "to": rel["to"], "relation": rel.get("type", "related")})

    return {"nodes": nodes, "edges": edges}


def to_mermaid(graph: dict) -> str:
    lines = ["flowchart LR"]
    ids = {node["id"] for node in graph["nodes"]}
    for node in graph["nodes"]:
        safe = node["id"].replace("-", "_").replace(".", "_")
        label = str(node["label"]).replace('"', "'")
        lines.append(f'    {safe}["{node["id"]}: {label}"]')
    for edge in graph["edges"]:
        if edge["from"] in ids and edge["to"] in ids:
            src = edge["from"].replace("-", "_").replace(".", "_")
            dst = edge["to"].replace("-", "_").replace(".", "_")
            relation = edge["relation"].replace('"', "'")
            lines.append(f"    {src} -->|{relation}| {dst}")
    return "\n".join(lines)
