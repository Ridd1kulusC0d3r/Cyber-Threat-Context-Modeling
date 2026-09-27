from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from tce.graph import build_graph


def _id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, 'tce:' + seed)}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_relation(value: str) -> str:
    value = re.sub(r"[^a-z0-9-]+", "-", value.lower().replace("_", "-")).strip("-")
    return value or "related-to"


def export_case_stix(entities: dict[str, dict]) -> dict:
    graph = build_graph(entities)
    timestamp = _now()
    creator = _id("identity", "creator")
    objects = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": creator,
        "created": timestamp,
        "modified": timestamp,
        "name": "Threat Context Engineering",
        "identity_class": "organization",
    }]

    node_ids = {}
    for node in graph["nodes"]:
        sid = _id("note", node["id"])
        node_ids[node["id"]] = sid
        objects.append({
            "type": "note",
            "spec_version": "2.1",
            "id": sid,
            "created_by_ref": creator,
            "created": timestamp,
            "modified": timestamp,
            "content": f"{node['id']} | {node.get('label', '')}",
            "object_refs": [creator],
            "labels": [f"tce:{node.get('kind', 'entity')}"],
            "x_tce_id": node["id"],
            "x_tce_kind": node.get("kind", "entity"),
        })

    for index, edge in enumerate(graph["edges"]):
        if edge["from"] not in node_ids or edge["to"] not in node_ids:
            continue
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": _id("relationship", f"{index}:{edge['from']}:{edge['relation']}:{edge['to']}"),
            "created_by_ref": creator,
            "created": timestamp,
            "modified": timestamp,
            "relationship_type": _safe_relation(edge["relation"]),
            "source_ref": node_ids[edge["from"]],
            "target_ref": node_ids[edge["to"]],
        })

    return {"type": "bundle", "id": _id("bundle", "case"), "objects": objects}


def write_stix(bundle: dict, output: str | Path):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return path
