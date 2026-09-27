from __future__ import annotations

import json
import re
from difflib import SequenceMatcher
from pathlib import Path

import requests

ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CACHE_DIR = Path.home() / ".cache" / "tce" / "standards"
ATTACK_CACHE = CACHE_DIR / "enterprise-attack.json"
ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def sync_attack(url: str = ATTACK_STIX_URL, cache: Path = ATTACK_CACHE) -> Path:
    cache.parent.mkdir(parents=True, exist_ok=True)
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    json.loads(response.text)
    cache.write_text(response.text, encoding="utf-8")
    return cache


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


class AttackIndex:
    def __init__(self, data: dict):
        self.data = data
        self.by_external_id: dict[str, dict] = {}
        self.by_stix_id: dict[str, dict] = {}
        self.techniques: list[dict] = []
        self.detection_strategies: list[dict] = []
        self.analytics: list[dict] = []
        self.data_components: list[dict] = []
        self.relationships: list[dict] = []

        for obj in data.get("objects", []):
            oid = obj.get("id")
            if oid:
                self.by_stix_id[oid] = obj
            external_id = _external_id(obj)
            if external_id:
                self.by_external_id[external_id] = obj

            kind = obj.get("type")
            if kind == "attack-pattern" and external_id and ATTACK_ID_RE.match(external_id):
                self.techniques.append(obj)
            elif kind == "x-mitre-detection-strategy":
                self.detection_strategies.append(obj)
            elif kind == "x-mitre-analytic":
                self.analytics.append(obj)
            elif kind == "x-mitre-data-component":
                self.data_components.append(obj)
            elif kind == "relationship":
                self.relationships.append(obj)

        self._rels_to: dict[str, list[dict]] = {}
        self._rels_from: dict[str, list[dict]] = {}
        for rel in self.relationships:
            self._rels_to.setdefault(rel.get("target_ref", ""), []).append(rel)
            self._rels_from.setdefault(rel.get("source_ref", ""), []).append(rel)

    @classmethod
    def load(cls, cache: Path = ATTACK_CACHE, sync_if_missing: bool = True):
        if not cache.exists():
            if not sync_if_missing:
                raise FileNotFoundError(cache)
            sync_attack(cache=cache)
        return cls(json.loads(cache.read_text(encoding="utf-8")))

    def get(self, external_id: str):
        return self.by_external_id.get(external_id)

    def stix_ref(self, external_id: str):
        obj = self.get(external_id)
        return obj.get("id") if obj else None

    def validate_ids(self, ids: list[str]) -> dict:
        valid, invalid = [], []
        for value in ids:
            (valid if value in self.by_external_id else invalid).append(value)
        return {"valid": sorted(set(valid)), "invalid": sorted(set(invalid))}

    def search(self, query: str, limit: int = 10) -> list[dict]:
        q = query.lower().strip()
        scored = []
        for obj in self.techniques:
            name = obj.get("name", "")
            desc = obj.get("description", "")
            score = max(
                SequenceMatcher(None, q, name.lower()).ratio(),
                1.0 if q and q in name.lower() else 0.0,
                0.65 if q and q in desc.lower() else 0.0,
            )
            if score > 0.25:
                scored.append({
                    "id": _external_id(obj),
                    "name": name,
                    "score": round(score, 3),
                    "stix_id": obj.get("id"),
                })
        return sorted(scored, key=lambda row: row["score"], reverse=True)[:limit]

    def detection_strategies_for_technique(self, technique_id: str) -> list[dict]:
        technique_ref = self.stix_ref(technique_id)
        if not technique_ref:
            return []

        rows = []
        for rel in self._rels_to.get(technique_ref, []):
            if rel.get("relationship_type") != "detects":
                continue
            strategy = self.by_stix_id.get(rel.get("source_ref"))
            if not strategy or strategy.get("type") != "x-mitre-detection-strategy":
                continue
            rows.append(self._normalize_detection_strategy(strategy))
        return rows

    def _normalize_detection_strategy(self, strategy: dict) -> dict:
        analytics = []
        data_components: dict[str, dict] = {}

        for analytic_ref in strategy.get("x_mitre_analytic_refs", []) or []:
            analytic = self.by_stix_id.get(analytic_ref)
            if not analytic:
                continue

            log_sources = []
            for log_ref in analytic.get("x_mitre_log_source_references", []) or []:
                component_ref = log_ref.get("x_mitre_data_component_ref")
                component = self.by_stix_id.get(component_ref) or {}
                component_id = _external_id(component)
                if component_ref:
                    data_components[component_ref] = {
                        "id": component_id,
                        "stix_id": component_ref,
                        "name": component.get("name"),
                        "description": component.get("description"),
                        "log_sources": component.get("x_mitre_log_sources", []) or [],
                    }
                log_sources.append({
                    "data_component_id": component_id,
                    "data_component_ref": component_ref,
                    "data_component_name": component.get("name"),
                    "name": log_ref.get("name"),
                    "channel": log_ref.get("channel"),
                })

            analytics.append({
                "id": _external_id(analytic),
                "stix_id": analytic.get("id"),
                "name": analytic.get("name"),
                "description": analytic.get("description"),
                "platforms": analytic.get("x_mitre_platforms", []) or [],
                "log_sources": log_sources,
                "mutable_elements": analytic.get("x_mitre_mutable_elements", []) or [],
            })

        return {
            "id": _external_id(strategy),
            "stix_id": strategy.get("id"),
            "name": strategy.get("name"),
            "description": strategy.get("description"),
            "domains": strategy.get("x_mitre_domains", []) or [],
            "analytics": analytics,
            "data_components": list(data_components.values()),
        }

    def detection_profile(self, technique_id: str) -> dict:
        technique = self.get(technique_id)
        return {
            "technique": {
                "id": technique_id,
                "stix_id": technique.get("id") if technique else None,
                "name": technique.get("name") if technique else None,
            },
            "detection_strategies": self.detection_strategies_for_technique(technique_id),
        }
