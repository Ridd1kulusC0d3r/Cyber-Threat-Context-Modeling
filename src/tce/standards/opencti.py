from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

DEFAULT_TYPES = (
    "intrusion-set",
    "campaign",
    "malware",
    "report",
    "threat-actor-group",
    "vulnerability",
)

HELPERS = {
    "intrusion-set": ("intrusion_set",),
    "campaign": ("campaign",),
    "malware": ("malware",),
    "report": ("report",),
    "threat-actor-group": ("threat_actor_group", "threat_actor"),
    "vulnerability": ("vulnerability",),
}


def _client(url: str | None = None, token: str | None = None):
    url = url or os.getenv("OPENCTI_URL")
    token = token or os.getenv("OPENCTI_TOKEN")
    if not url or not token:
        raise RuntimeError("OPENCTI_URL and OPENCTI_TOKEN are required")
    try:
        from pycti import OpenCTIApiClient
    except ImportError as exc:
        raise RuntimeError("Install OpenCTI support with pip install -e '.[opencti]'") from exc
    return OpenCTIApiClient(url, token)


def _helper(client, entity_type: str):
    candidates = HELPERS.get(entity_type, (entity_type.replace("-", "_"),))
    for name in candidates:
        value = getattr(client, name, None)
        if value is not None and hasattr(value, "list"):
            return value
    raise RuntimeError(f"PyCTI helper not available for {entity_type}")


def _normalize_external_refs(entity: dict) -> list[dict]:
    refs = entity.get("externalReferences") or entity.get("external_references") or []
    if isinstance(refs, dict) and "edges" in refs:
        refs = [edge.get("node", {}) for edge in refs.get("edges", [])]
    output = []
    for ref in refs or []:
        if not isinstance(ref, dict):
            continue
        output.append({
            "source_name": ref.get("source_name") or ref.get("sourceName"),
            "external_id": ref.get("external_id") or ref.get("externalId"),
            "url": ref.get("url"),
            "description": ref.get("description"),
        })
    return output


def normalize_entity(entity_type: str, entity: dict) -> dict:
    aliases = entity.get("aliases") or entity.get("x_opencti_aliases") or []
    if isinstance(aliases, str):
        aliases = [aliases]
    return {
        "id": entity.get("id"),
        "standard_id": entity.get("standard_id") or entity.get("standardId"),
        "entity_type": entity.get("entity_type") or entity.get("entityType") or entity_type,
        "name": entity.get("name") or entity.get("value") or entity.get("title"),
        "description": entity.get("description") or "",
        "aliases": aliases,
        "created_at": entity.get("created_at") or entity.get("createdAt"),
        "updated_at": entity.get("updated_at") or entity.get("updatedAt"),
        "external_references": _normalize_external_refs(entity),
        "labels": entity.get("objectLabel") or entity.get("labels") or [],
    }


def normalize_relationship(rel: dict) -> dict:
    source = rel.get("from") or rel.get("from_") or rel.get("source") or {}
    target = rel.get("to") or rel.get("target") or {}
    if isinstance(source, str):
        source = {"id": source}
    if isinstance(target, str):
        target = {"id": target}
    return {
        "id": rel.get("id"),
        "standard_id": rel.get("standard_id") or rel.get("standardId"),
        "relationship_type": rel.get("relationship_type") or rel.get("relationshipType"),
        "from": {
            "id": source.get("id"),
            "standard_id": source.get("standard_id") or source.get("standardId"),
            "name": source.get("name") or source.get("value"),
            "entity_type": source.get("entity_type") or source.get("entityType"),
        },
        "to": {
            "id": target.get("id"),
            "standard_id": target.get("standard_id") or target.get("standardId"),
            "name": target.get("name") or target.get("value"),
            "entity_type": target.get("entity_type") or target.get("entityType"),
        },
    }


def pull_snapshot(
    types: list[str] | tuple[str, ...] = DEFAULT_TYPES,
    limit: int = 100,
    search: str | None = None,
    include_relationships: bool = True,
    url: str | None = None,
    token: str | None = None,
) -> dict:
    client = _client(url=url, token=token)
    entities = []

    for entity_type in types:
        helper = _helper(client, entity_type)
        kwargs: dict[str, Any] = {"first": limit}
        if search:
            kwargs["search"] = search
        rows = helper.list(**kwargs) or []
        entities.extend(normalize_entity(entity_type, row) for row in rows)

    relationships = []
    if include_relationships:
        helper = getattr(client, "stix_core_relationship", None)
        if helper is not None and hasattr(helper, "list"):
            try:
                rows = helper.list(first=limit) or []
                relationships = [normalize_relationship(row) for row in rows]
            except Exception as exc:
                relationships = [{"warning": f"relationship pull unavailable: {exc}"}]

    return {
        "source": "OpenCTI",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "entity_types": list(types),
        "entities": entities,
        "relationships": relationships,
        "review_required": True,
    }


def write_snapshot(snapshot: dict, output: str | Path):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def snapshot_to_evidence(snapshot: dict) -> dict:
    items = []
    for entity in snapshot.get("entities", []) or []:
        stable = entity.get("standard_id") or entity.get("id") or json.dumps(entity, sort_keys=True)
        digest = hashlib.sha256(str(stable).encode("utf-8")).hexdigest()[:16]
        name = entity.get("name") or "unnamed entity"
        entity_type = entity.get("entity_type") or "entity"
        description = (entity.get("description") or "").strip()
        claim = f"OpenCTI contains {entity_type} '{name}'."
        if description:
            claim += f" Source description: {description}"

        refs = entity.get("external_references") or []
        reference = entity.get("standard_id") or entity.get("id") or ""
        if refs and refs[0].get("url"):
            reference = refs[0]["url"]

        items.append({
            "id": f"EV-OPENCTI-{digest}",
            "title": f"OpenCTI: {name}",
            "source_type": "secondary-external",
            "source": "OpenCTI",
            "reference": reference,
            "publication_date": entity.get("created_at") or "",
            "collected_at": snapshot.get("collected_at") or "",
            "claim": claim,
            "evidence_state": "observed",
            "source_reliability": "unknown",
            "information_credibility": "unknown",
            "temporal_relevance": "current",
            "supports": [],
            "contradicts": [],
            "analyst_notes": "Imported as a candidate from OpenCTI. Review before linking to a hypothesis.",
            "x_tce_external_entity": entity,
        })
    return {
        "version": "0.3",
        "evidence_items": items,
        "import_metadata": {
            "source": "OpenCTI",
            "review_required": True,
            "auto_merge": False,
        },
    }


def write_evidence_candidates(data: dict, output: str | Path):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def bundle_summary(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    kinds = {}
    for obj in data.get("objects", []):
        kind = obj.get("type", "unknown")
        kinds[kind] = kinds.get(kind, 0) + 1
    return {
        "bundle_id": data.get("id"),
        "objects": len(data.get("objects", [])),
        "types": kinds,
    }


def push_bundle(
    path: str | Path,
    url: str | None = None,
    token: str | None = None,
    update: bool = False,
):
    client = _client(url=url, token=token)
    content = Path(path).read_text(encoding="utf-8")
    return client.stix2.import_bundle_from_json(content, update=update)
