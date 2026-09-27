from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher


def canonical_name(value: str) -> str:
    value = unicodedata.normalize("NFKD", value or "")
    value = "".join(ch for ch in value if not unicodedata.combining(ch))
    value = re.sub(r"[^a-zA-Z0-9]+", " ", value).strip().lower()
    return re.sub(r"\s+", " ", value)


def entity_names(entity: dict) -> set[str]:
    values = set()
    for key in ("name", "value", "title"):
        if entity.get(key):
            values.add(canonical_name(str(entity[key])))
    for alias in entity.get("aliases", []) or []:
        if alias:
            values.add(canonical_name(str(alias)))
    return {value for value in values if value}


def similarity(left: dict, right: dict) -> float:
    a = entity_names(left)
    b = entity_names(right)
    if not a or not b:
        return 0.0
    if a & b:
        return 1.0
    return max(SequenceMatcher(None, x, y).ratio() for x in a for y in b)


def resolve_entities(incoming: list[dict], existing: list[dict], threshold: float = 0.90) -> list[dict]:
    decisions = []
    for source in incoming:
        scored = [
            (similarity(source, target), target)
            for target in existing
        ]
        scored.sort(key=lambda row: row[0], reverse=True)
        best_score, best = scored[0] if scored else (0.0, None)
        decisions.append({
            "incoming": source,
            "match": best if best_score >= threshold else None,
            "score": round(best_score, 3),
            "status": "matched" if best_score >= threshold else "new_candidate",
            "analyst_review_required": best_score < 1.0,
        })
    return decisions
