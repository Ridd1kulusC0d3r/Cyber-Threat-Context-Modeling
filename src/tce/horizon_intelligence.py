from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml


def _signal_id(context_id: str, pack_id: str) -> str:
    digest = hashlib.sha256(f"{context_id}|{pack_id}".encode("utf-8")).hexdigest()[:10].upper()
    return f"SIG-RF-{digest}"


def _environment_nodes_for_crowns(
    entities: dict[str, dict],
    crown_ids: set[str],
) -> list[str]:
    output = []
    for wrapped in entities.values():
        if wrapped["kind"] != "environment_state":
            continue
        environment = wrapped["data"]
        for item in (environment.get("assets", []) or []) + (environment.get("identities", []) or []):
            if set(item.get("crown_jewel_ids", []) or []) & crown_ids:
                output.append(item.get("id"))
    return sorted({item for item in output if item})


def redframeworks_signal_candidates(
    entities: dict[str, dict],
    enrichment: dict[str, Any],
) -> list[dict[str, Any]]:
    contexts = {
        wrapped["data"]["id"]: wrapped["data"]
        for wrapped in entities.values()
        if wrapped["kind"] == "threat_context"
    }
    candidates = []

    for context_row in enrichment.get("contexts", []) or []:
        context_id = context_row.get("context_id")
        context = contexts.get(context_id)
        if not context:
            continue

        crown_ids = set(context.get("crown_jewel_ids", []) or [])
        target_ids = _environment_nodes_for_crowns(entities, crown_ids)
        techniques = sorted(set(context.get("attack_techniques", []) or []))

        for pack in context_row.get("domain_packs", []) or []:
            if not pack.get("found"):
                continue
            pack_id = pack.get("domain_pack_id") or (pack.get("pack") or {}).get("id") or "unknown"
            adversaries = pack.get("adversaries", []) or []
            campaigns = pack.get("campaigns", []) or []
            source_tiers = {
                str(item.get("source_tier", "")).upper()
                for item in [*adversaries, *campaigns]
                if item.get("source_tier")
            }
            reliability = "A" if source_tiers and source_tiers <= {"A"} else "C"

            candidates.append({
                "id": _signal_id(str(context_id), str(pack_id)),
                "kind": "redframeworks-context",
                "status": "candidate",
                "scope": "context",
                "context_id": context_id,
                "domain_pack_id": pack_id,
                "target_ids": target_ids,
                "crown_jewel_ids": sorted(crown_ids),
                "technique_ids": techniques,
                "adversary_ids": sorted(
                    item.get("id") for item in adversaries if item.get("id")
                ),
                "campaign_ids": sorted(
                    item.get("id") for item in campaigns if item.get("id")
                ),
                "severity": "medium",
                "confidence": "medium",
                "source_reliability": reliability,
                "information_credibility": 0.7,
                "relevance": 0.5,
                "direction": "increase",
                "observed_at": (pack.get("source") or {}).get("updated"),
                "half_life_days": 30,
                "source_ref": f"RedFrameworks v4 domain pack {pack_id}",
                "rationale": (
                    "Candidate enterprise context derived from a review-gated RedFrameworks "
                    "domain-pack enrichment. Actor or campaign presence does not establish "
                    "organization-specific targeting."
                ),
                "review_required": True,
            })

    return candidates


def write_redframeworks_signal_candidates(
    entities: dict[str, dict],
    enrichment: dict[str, Any],
    output: str | Path,
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": "0.5",
        "provider": "RedFrameworks",
        "review_required": True,
        "auto_accept": False,
        "intelligence_signal_candidates": redframeworks_signal_candidates(
            entities,
            enrichment,
        ),
    }
    path.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return path


def load_enrichment(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
