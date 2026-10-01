from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

import yaml

SINGULAR_KEYS = {
    "case": "case",
    "intelligence_requirement": "intelligence_requirement",
    "crown_jewel": "crown_jewel",
    "architecture": "architecture",
    "evidence": "evidence",
    "hypothesis": "hypothesis",
    "scenario": "scenario",
    "telemetry_contract": "telemetry_contract",
    "detection_use_case": "detection_use_case",
    "detection_specification": "detection_specification",
    "intelligence_gap": "intelligence_gap",
    "decision": "decision",
    "validation": "validation",
    "threat_context": "threat_context",
}

PLURAL_KEYS = {
    "cases": "case",
    "intelligence_requirements": "intelligence_requirement",
    "crown_jewels": "crown_jewel",
    "architectures": "architecture",
    "evidence_items": "evidence",
    "hypotheses": "hypothesis",
    "scenarios": "scenario",
    "telemetry_contracts": "telemetry_contract",
    "detection_use_cases": "detection_use_case",
    "detection_specifications": "detection_specification",
    "intelligence_gaps": "intelligence_gap",
    "decisions": "decision",
    "validations": "validation",
    "threat_contexts": "threat_context",
}


def _load_path(path: Path) -> list[Any]:
    if path.suffix.lower() == ".json":
        return [json.loads(path.read_text(encoding="utf-8"))]
    with path.open("r", encoding="utf-8") as handle:
        return [doc for doc in yaml.safe_load_all(handle) if doc is not None]


def _iter_files(case_dir: Path) -> Iterable[Path]:
    for path in sorted(case_dir.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".yaml", ".yml", ".json"}:
            if "reports" not in path.parts:
                yield path


def _extract_entities(document: Any) -> Iterable[tuple[str, dict[str, Any]]]:
    if not isinstance(document, dict):
        return
    for key, kind in SINGULAR_KEYS.items():
        value = document.get(key)
        if isinstance(value, dict):
            yield kind, value
    for key, kind in PLURAL_KEYS.items():
        value = document.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield kind, item


def load_case(case_dir: str | Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    root = Path(case_dir)
    if not root.exists():
        raise FileNotFoundError(f"Case directory not found: {root}")

    entities: dict[str, dict[str, Any]] = {}
    errors: list[str] = []

    for path in _iter_files(root):
        try:
            documents = _load_path(path)
        except Exception as exc:
            errors.append(f"{path}: parse error: {exc}")
            continue

        for document in documents:
            for kind, data in _extract_entities(document):
                entity_id = data.get("id")
                if not entity_id:
                    errors.append(f"{path}: {kind} has no id")
                    continue
                if entity_id in entities:
                    errors.append(
                        f"{path}: duplicate id {entity_id}; first seen in {entities[entity_id]['source']}"
                    )
                    continue
                entities[entity_id] = {"kind": kind, "data": data, "source": str(path)}

    return entities, errors
