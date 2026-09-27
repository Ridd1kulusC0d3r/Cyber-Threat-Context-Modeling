from __future__ import annotations

import json
from pathlib import Path

import requests

D3FEND_MAPPINGS_URL = "https://next.d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"
CACHE_DIR = Path.home() / ".cache" / "tce" / "standards"
D3FEND_CACHE = CACHE_DIR / "d3fend-full-mappings.json"


def sync_d3fend(url: str = D3FEND_MAPPINGS_URL, cache: Path = D3FEND_CACHE) -> Path:
    cache.parent.mkdir(parents=True, exist_ok=True)
    response = requests.get(url, timeout=120)
    response.raise_for_status()
    json.loads(response.text)
    cache.write_text(response.text, encoding="utf-8")
    return cache


class D3FENDIndex:
    def __init__(self, data: dict):
        self.data = data
        self.bindings = ((data.get("results") or {}).get("bindings") or [])

    @classmethod
    def load(cls, cache: Path = D3FEND_CACHE, sync_if_missing: bool = True):
        if not cache.exists():
            if not sync_if_missing:
                raise FileNotFoundError(cache)
            sync_d3fend(cache=cache)
        return cls(json.loads(cache.read_text(encoding="utf-8")))

    def lookup_attack(self, technique_id: str, limit: int = 50) -> list[dict]:
        matches = []
        for binding in self.bindings:
            values = [
                str(cell.get("value", ""))
                for cell in binding.values()
                if isinstance(cell, dict)
            ]
            if any(technique_id in value for value in values):
                matches.append(binding)
                if len(matches) >= limit:
                    break
        return matches
