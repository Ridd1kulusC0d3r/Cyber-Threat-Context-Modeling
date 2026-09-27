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


class AttackIndex:
    def __init__(self, data: dict):
        self.data = data
        self.by_external_id = {}
        self.by_stix_id = {}
        self.techniques = []
        for obj in data.get("objects", []):
            oid = obj.get("id")
            if oid:
                self.by_stix_id[oid] = obj
            external_id = None
            for ref in obj.get("external_references", []) or []:
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    external_id = ref["external_id"]
                    break
            if external_id:
                self.by_external_id[external_id] = obj
            if obj.get("type") == "attack-pattern" and external_id and ATTACK_ID_RE.match(external_id):
                self.techniques.append(obj)

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
                ext = next(
                    (
                        ref.get("external_id")
                        for ref in obj.get("external_references", [])
                        if ref.get("source_name") == "mitre-attack"
                    ),
                    None,
                )
                scored.append({
                    "id": ext,
                    "name": name,
                    "score": round(score, 3),
                    "stix_id": obj.get("id"),
                })
        return sorted(scored, key=lambda row: row["score"], reverse=True)[:limit]
