from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests

BASE_URL = "https://ridd1kulusc0d3r.github.io/RedFrameworks/api/v4"
CACHE_DIR = Path.home() / ".cache" / "tce" / "redframeworks" / "v4"

ENDPOINTS = {
    "index": "index.json",
    "adversaries": "adversaries.json",
    "campaigns": "campaigns.json",
    "detections": "detections.json",
    "domain_packs": "domain-packs.json",
    "ai_security_surface": "ai-security-surface.json",
    "emulation_plans": "emulation-plans.json",
    "intelligence_sources": "intelligence-sources.json",
    "verification_v2": "verification-v2.json",
}


def sync_redframeworks(
    base_url: str = BASE_URL,
    cache_dir: Path = CACHE_DIR,
) -> dict[str, str]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    written = {}
    for name, filename in ENDPOINTS.items():
        response = requests.get(f"{base_url.rstrip('/')}/{filename}", timeout=60)
        response.raise_for_status()
        json.loads(response.text)
        path = cache_dir / filename
        path.write_text(response.text, encoding="utf-8")
        written[name] = str(path)
    return written


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class RedFrameworksIndex:
    def __init__(self, datasets: dict[str, dict[str, Any]]):
        self.datasets = datasets
        self.index = datasets.get("index", {})
        self.adversaries = {
            item["id"]: item
            for item in datasets.get("adversaries", {}).get("adversaries", [])
        }
        self.campaigns = {
            item["id"]: item
            for item in datasets.get("campaigns", {}).get("campaigns", [])
        }
        self.detections = {
            item["id"]: item
            for item in datasets.get("detections", {}).get("detections", [])
        }
        self.domain_packs = {
            item["id"]: item
            for item in datasets.get("domain_packs", {}).get("packs", [])
        }
        self.ai_surfaces = {
            item["id"]: item
            for item in datasets.get("ai_security_surface", {}).get("surfaces", [])
        }
        self.emulation_plans = {
            item["id"]: item
            for item in datasets.get("emulation_plans", {}).get("plans", [])
        }
        sources = datasets.get("intelligence_sources", {})
        self.intelligence_sources = sources.get(
            "sources",
            sources.get("intelligence_sources", []),
        )

    @classmethod
    def load(
        cls,
        cache_dir: Path = CACHE_DIR,
        sync_if_missing: bool = True,
    ):
        missing = [
            filename
            for filename in ENDPOINTS.values()
            if not (cache_dir / filename).exists()
        ]
        if missing:
            if not sync_if_missing:
                raise FileNotFoundError(
                    f"RedFrameworks cache missing: {', '.join(missing)}"
                )
            sync_redframeworks(cache_dir=cache_dir)

        return cls({
            name: _load_json(cache_dir / filename)
            for name, filename in ENDPOINTS.items()
        })

    def enrich_domain_pack(self, pack_id: str) -> dict[str, Any]:
        pack = self.domain_packs.get(pack_id)
        if not pack:
            return {
                "domain_pack_id": pack_id,
                "found": False,
                "review_required": True,
            }

        actor_ids = pack.get("adversaries", []) or []
        adversaries = [
            self.adversaries[item_id]
            for item_id in actor_ids
            if item_id in self.adversaries
        ]
        attack_group_ids = {
            item.get("attack_id")
            for item in adversaries
            if item.get("attack_id")
        }
        campaigns = [
            item
            for item in self.campaigns.values()
            if set(item.get("actor_ids", []) or []) & set(actor_ids)
        ]
        detections = [
            self.detections[item_id]
            for item_id in pack.get("detections", []) or []
            if item_id in self.detections
        ]
        plans = [
            item
            for item in self.emulation_plans.values()
            if item.get("attack_group_id") in attack_group_ids
        ]

        return {
            "domain_pack_id": pack_id,
            "found": True,
            "pack": pack,
            "adversaries": adversaries,
            "campaigns": campaigns,
            "detections": detections,
            "validation_references": plans,
            "ai_security_surfaces": (
                list(self.ai_surfaces.values())
                if pack_id == "ai-genai"
                else []
            ),
            "intelligence_sources": self.intelligence_sources,
            "source": {
                "provider": "RedFrameworks",
                "api": "v4",
                "updated": self.index.get("updated"),
                "counts": self.index.get("counts", {}),
            },
            "policy": {
                "review_required": True,
                "auto_promote_to_evidence": False,
                "actor_relevance_requires_case_evidence": True,
                "validation_metadata_only": True,
            },
        }

    def enrich_context(self, context: dict[str, Any]) -> dict[str, Any]:
        config = context.get("redframeworks") or {}
        pack_ids = config.get("domain_pack_ids") or []
        return {
            "context_id": context.get("id"),
            "context_name": context.get("name"),
            "domain_packs": [
                self.enrich_domain_pack(pack_id)
                for pack_id in pack_ids
            ],
            "review_required": True,
            "auto_merge": False,
        }


def enrich_case_contexts(
    entities: dict[str, dict],
    index: RedFrameworksIndex,
) -> dict[str, Any]:
    contexts = [
        wrapped["data"]
        for wrapped in entities.values()
        if wrapped["kind"] == "threat_context"
    ]
    return {
        "provider": "RedFrameworks",
        "api": "v4",
        "contexts": [index.enrich_context(context) for context in contexts],
        "review_required": True,
        "auto_merge": False,
    }
