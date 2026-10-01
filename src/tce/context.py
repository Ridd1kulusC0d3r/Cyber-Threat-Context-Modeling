from __future__ import annotations

from collections import defaultdict
from importlib import resources
from typing import Any

import yaml


def load_context_catalog() -> dict[str, dict[str, Any]]:
    path = resources.files("tce").joinpath("data/threat-context-lenses.yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {item["id"]: item for item in data.get("lenses", [])}


def context_entities(entities: dict[str, dict]) -> list[dict]:
    return [
        wrapped["data"]
        for wrapped in entities.values()
        if wrapped["kind"] == "threat_context"
    ]


def _text_corpus(entities: dict[str, dict]) -> str:
    chunks: list[str] = []
    for wrapped in entities.values():
        data = wrapped["data"]
        for key in ("name", "title", "mission", "decision_context", "objective", "rationale"):
            value = data.get(key)
            if isinstance(value, str):
                chunks.append(value)
        for key in ("scope", "themes", "assumptions"):
            value = data.get(key)
            if isinstance(value, list):
                chunks.extend(str(item) for item in value)
        if wrapped["kind"] == "architecture":
            for node in data.get("nodes", []) or []:
                chunks.extend(str(node.get(k, "")) for k in ("name", "type", "trust_zone"))
    return " ".join(chunks).lower()


def suggest_context_lenses(
    entities: dict[str, dict],
    catalog: dict[str, dict[str, Any]] | None = None,
    limit: int = 12,
) -> list[dict[str, Any]]:
    catalog = catalog or load_context_catalog()
    corpus = _text_corpus(entities)
    modeled_lens_ids = {
        ctx.get("lens_id")
        for ctx in context_entities(entities)
        if ctx.get("lens_id")
    }
    suggestions = []

    for lens_id, lens in catalog.items():
        hits = sorted({
            signal
            for signal in lens.get("signals", []) or []
            if signal.lower() in corpus
        })
        if not hits:
            continue
        suggestions.append({
            "lens_id": lens_id,
            "name": lens.get("name"),
            "class": lens.get("class"),
            "score": len(hits),
            "matched_signals": hits,
            "modeled": lens_id in modeled_lens_ids,
            "redframeworks_domain_pack": lens.get("redframeworks_domain_pack"),
        })

    return sorted(
        suggestions,
        key=lambda item: (item["modeled"], -item["score"], item["name"]),
    )[:limit]


def assess_contexts(
    entities: dict[str, dict],
    catalog: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    catalog = catalog or load_context_catalog()
    contexts = context_entities(entities)
    crown_jewel_links = defaultdict(set)

    for ctx in contexts:
        for crown_id in ctx.get("crown_jewel_ids", []) or []:
            crown_jewel_links[crown_id].add(ctx.get("id"))

    gaps = []
    for wrapped in entities.values():
        data = wrapped["data"]
        if wrapped["kind"] == "scenario" and not (data.get("threat_context_ids") or []):
            gaps.append({
                "type": "scenario-context",
                "id": data.get("id"),
                "description": "Scenario is not linked to a threat-context lens.",
            })
        elif wrapped["kind"] == "crown_jewel" and data.get("id") not in crown_jewel_links:
            gaps.append({
                "type": "crown-jewel-context",
                "id": data.get("id"),
                "description": "Crown jewel is not linked to a threat-context lens.",
            })

    for ctx in contexts:
        if ctx.get("lens_id") not in catalog:
            gaps.append({
                "type": "unknown-lens",
                "id": ctx.get("id"),
                "description": f"Unknown context lens: {ctx.get('lens_id')}",
            })

    return {
        "modeled_contexts": len(contexts),
        "modeled_context_ids": sorted(ctx["id"] for ctx in contexts if ctx.get("id")),
        "catalog_lenses": len(catalog),
        "suggestions": suggest_context_lenses(entities, catalog=catalog),
        "gaps": gaps,
    }
