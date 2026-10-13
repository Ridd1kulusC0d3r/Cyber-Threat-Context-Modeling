from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from importlib import resources
from itertools import islice
from pathlib import Path
from typing import Any

import networkx as nx
import yaml


EXPOSURE = {"none": 0.05, "indirect": 0.45, "direct": 1.0, "unknown": 0.5}
RELATION_PRESSURE = {
    "administers": 0.90,
    "authenticates_to": 0.80,
    "federates_with": 0.85,
    "trusts": 0.85,
    "remote_access": 0.90,
    "controls": 0.95,
    "depends_on": 0.55,
    "connects_to": 0.60,
    "third_party": 0.80,
    "stores": 0.50,
    "syncs": 0.55,
    "recovers": 0.50,
    "logs_to": 0.20,
    "other": 0.50,
}

RELATION_TECHNIQUE_HINTS = {
    "administers": ["T1078", "T1098"],
    "authenticates_to": ["T1078"],
    "federates_with": ["T1078"],
    "remote_access": ["T1133", "T1021"],
    "third_party": ["T1078"],
}

CONFIDENCE = {"low": 0.4, "medium": 0.65, "high": 0.85, "confirmed": 1.0}
SOURCE_RELIABILITY = {"a": 1.0, "b": 0.85, "c": 0.70, "d": 0.50, "e": 0.30, "f": 0.15}


def environments(entities: dict[str, dict]) -> list[dict[str, Any]]:
    return [
        wrapped["data"]
        for wrapped in entities.values()
        if wrapped["kind"] == "environment_state"
    ]


def preemptive_actions(entities: dict[str, dict]) -> list[dict[str, Any]]:
    return [
        wrapped["data"]
        for wrapped in entities.values()
        if wrapped["kind"] == "preemptive_action"
    ]


def _control_catalog() -> list[dict[str, Any]]:
    path = resources.files("tce").joinpath("data/horizon-control-catalog.yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data.get("actions", []) or []


def derive_environment_from_architecture(entities: dict[str, dict]) -> dict[str, Any] | None:
    architectures = [
        wrapped["data"]
        for wrapped in entities.values()
        if wrapped["kind"] == "architecture"
    ]
    if not architectures:
        return None

    assets: dict[str, dict[str, Any]] = {}
    relationships = []
    for architecture in architectures:
        for node in architecture.get("nodes", []) or []:
            node_id = node.get("id")
            if not node_id:
                continue
            current = assets.setdefault(node_id, dict(node))
            current.setdefault("entry_point", str(current.get("internet_exposure", "")).lower() == "direct")
            current.setdefault("control_ids", [])
            current.setdefault("telemetry_requirements", [])
        for index, rel in enumerate(architecture.get("relationships", []) or [], start=1):
            if not rel.get("from") or not rel.get("to"):
                continue
            row = dict(rel)
            row.setdefault("id", f"REL-DERIVED-{architecture.get('id', 'ARCH')}-{index}")
            row.setdefault("technique_ids", [])
            row.setdefault("control_ids", [])
            row.setdefault("required_telemetry", [])
            relationships.append(row)

    for wrapped in entities.values():
        if wrapped["kind"] != "crown_jewel":
            continue
        crown = wrapped["data"]
        for node_id in crown.get("architecture_node_ids", []) or []:
            if node_id in assets:
                values = set(assets[node_id].get("crown_jewel_ids", []) or [])
                values.add(crown["id"])
                assets[node_id]["crown_jewel_ids"] = sorted(values)

    return {
        "id": "ENV-DERIVED",
        "name": "Environment derived from TCE architecture",
        "snapshot_at": datetime.now(timezone.utc).isoformat(),
        "scope": "derived",
        "assets": list(assets.values()),
        "identities": [],
        "relationships": relationships,
        "controls": [],
        "telemetry_sources": [],
        "vulnerability_signals": [],
        "intelligence_signals": [],
        "accepted_forecasts": {},
        "derived": True,
    }


def _asset_index(environment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = {}
    for item in (environment.get("assets", []) or []) + (environment.get("identities", []) or []):
        if item.get("id"):
            rows[item["id"]] = item
    return rows


def _relationship_index(environment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["id"]: item
        for item in environment.get("relationships", []) or []
        if item.get("id")
    }


def _merge_edge(existing: dict[str, Any] | None, rel: dict[str, Any]) -> dict[str, Any]:
    if not existing:
        row = dict(rel)
        row["relationship_id"] = rel.get("id")
        row["relationship_ids"] = [rel.get("id")] if rel.get("id") else []
        return row

    row = dict(existing)
    current_type = str(row.get("type", "other")).lower()
    new_type = str(rel.get("type", "other")).lower()
    if RELATION_PRESSURE.get(new_type, 0.5) > RELATION_PRESSURE.get(current_type, 0.5):
        row["type"] = rel.get("type")
        row["relationship_id"] = rel.get("id")

    row["relationship_ids"] = sorted({
        *(row.get("relationship_ids", []) or []),
        *([rel.get("id")] if rel.get("id") else []),
    })
    for field in ("technique_ids", "control_ids", "required_telemetry"):
        row[field] = sorted({
            *(row.get(field, []) or []),
            *(rel.get(field, []) or []),
        })
    row["parallel_relationships_merged"] = True
    return row


def _add_graph_edge(graph: nx.DiGraph, rel: dict[str, Any]) -> None:
    source, target = rel.get("from"), rel.get("to")
    if not source or not target or source not in graph or target not in graph:
        return
    if rel.get("enabled", True) is False:
        return
    existing = graph.get_edge_data(source, target)
    graph.add_edge(source, target, **_merge_edge(existing, rel))


def _graph(environment: dict[str, Any]) -> nx.DiGraph:
    graph = nx.DiGraph()
    for node_id, item in _asset_index(environment).items():
        graph.add_node(node_id, **item)
    for rel in environment.get("relationships", []) or []:
        _add_graph_edge(graph, rel)
        if rel.get("bidirectional"):
            reverse = dict(rel)
            reverse["from"], reverse["to"] = rel.get("to"), rel.get("from")
            _add_graph_edge(graph, reverse)
    return graph


def _entry_nodes(environment: dict[str, Any]) -> list[str]:
    output = []
    for node_id, item in _asset_index(environment).items():
        exposure = str(item.get("internet_exposure", "unknown")).lower()
        if item.get("entry_point") or exposure == "direct" or item.get("external") is True:
            output.append(node_id)
    return sorted(set(output))


def _target_nodes(environment: dict[str, Any]) -> list[str]:
    return sorted(
        node_id
        for node_id, item in _asset_index(environment).items()
        if item.get("crown_jewel_ids")
    )


def _path_id(nodes: list[str]) -> str:
    digest = hashlib.sha256("->".join(nodes).encode("utf-8")).hexdigest()[:10].upper()
    return f"HZN-PATH-{digest}"


def _severity_value(value: Any) -> float:
    if isinstance(value, (int, float)):
        return min(max(float(value), 0.0), 1.0)
    return {
        "low": 0.25,
        "medium": 0.50,
        "high": 0.75,
        "critical": 1.0,
    }.get(str(value).lower(), 0.5)


def _reliability_value(value: Any) -> float:
    if isinstance(value, (int, float)):
        return min(max(float(value), 0.0), 1.0)
    if value is None:
        return 0.70
    return SOURCE_RELIABILITY.get(str(value).strip().lower(), 0.70)


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _intelligence_pressure(
    environment: dict[str, Any],
    nodes: list[str],
    techniques: set[str],
    now: datetime,
) -> tuple[float, list[dict[str, Any]]]:
    contributions = []
    total = 0.0
    for signal in environment.get("intelligence_signals", []) or []:
        if str(signal.get("status", "candidate")).lower() not in {"accepted", "active", "validated", "confirmed"}:
            continue
        targets = set(signal.get("target_ids", []) or [])
        signal_techniques = set(signal.get("technique_ids", []) or [])
        relevant = bool(targets & set(nodes) or signal_techniques & techniques or signal.get("scope") in {"global", "sector"})
        if not relevant:
            continue

        expires = _parse_time(signal.get("expires_at"))
        if expires and now > expires:
            continue

        severity = _severity_value(signal.get("severity", 0.5))
        confidence = CONFIDENCE.get(str(signal.get("confidence", "medium")).lower(), 0.65)
        reliability = _reliability_value(signal.get("source_reliability"))
        credibility = _severity_value(signal.get("information_credibility", 1.0))
        relevance = _severity_value(signal.get("relevance", 1.0))
        observed = _parse_time(signal.get("observed_at"))
        half_life = max(float(signal.get("half_life_days", 30) or 30), 1.0)
        age_days = max((now - observed).total_seconds() / 86400.0, 0.0) if observed else 0.0
        decay = 0.5 ** (age_days / half_life)
        direction = -1.0 if str(signal.get("direction", "increase")).lower() in {"decrease", "negative"} else 1.0
        value = severity * confidence * reliability * credibility * relevance * decay * direction
        total += value
        contributions.append({
            "id": signal.get("id"),
            "kind": signal.get("kind"),
            "value": round(value, 4),
            "decay": round(decay, 4),
            "confidence": signal.get("confidence", "medium"),
            "source_reliability": signal.get("source_reliability", "C"),
            "information_credibility": signal.get("information_credibility", 1.0),
            "relevance": signal.get("relevance", 1.0),
            "source_ref": signal.get("source_ref"),
        })
    return min(max(total, 0.0), 1.0), contributions


def _vulnerability_pressure(environment: dict[str, Any], nodes: list[str]) -> tuple[float, list[dict[str, Any]]]:
    rows = []
    values = []
    for signal in environment.get("vulnerability_signals", []) or []:
        if signal.get("target_id") not in nodes:
            continue
        epss = signal.get("epss")
        base = float(epss) if isinstance(epss, (int, float)) else _severity_value(signal.get("severity"))
        if signal.get("kev") is True:
            base = max(base, 0.95)
        base = min(max(base, 0.0), 1.0)
        values.append(base)
        rows.append({
            "id": signal.get("id") or signal.get("cve"),
            "target_id": signal.get("target_id"),
            "cve": signal.get("cve"),
            "kev": bool(signal.get("kev")),
            "epss": signal.get("epss"),
            "pressure": round(base, 4),
        })
    return (max(values) if values else 0.0), rows


def _controls(environment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["id"]: item
        for item in environment.get("controls", []) or []
        if item.get("id")
    }


def _control_weakness(environment: dict[str, Any], nodes: list[str], relationships: list[dict[str, Any]]) -> tuple[float, list[str]]:
    control_index = _controls(environment)
    ids = set()
    assets = _asset_index(environment)
    for node in nodes:
        ids.update(assets.get(node, {}).get("control_ids", []) or [])
    for rel in relationships:
        ids.update(rel.get("control_ids", []) or [])

    residual = 1.0
    applied = []
    for control_id in sorted(ids):
        control = control_index.get(control_id)
        if not control or str(control.get("status", "active")).lower() not in {"active", "implemented", "validated"}:
            continue
        effectiveness = min(max(float(control.get("effectiveness", 0.0) or 0.0), 0.0), 1.0)
        residual *= 1.0 - effectiveness
        applied.append(control_id)
    return round(residual, 4), applied


def _techniques(relationships: list[dict[str, Any]]) -> set[str]:
    output: set[str] = set()
    for rel in relationships:
        explicit = rel.get("technique_ids", []) or []
        output.update(explicit)
        if not explicit:
            output.update(RELATION_TECHNIQUE_HINTS.get(str(rel.get("type", "")).lower(), []))
    return output


def _attack_data_components(attack_index: Any, techniques: set[str]) -> set[str]:
    if attack_index is None:
        return set()
    output: set[str] = set()
    for technique_id in techniques:
        try:
            profile = attack_index.detection_profile(technique_id)
        except Exception:
            continue
        for strategy in profile.get("detection_strategies", []) or []:
            for analytic in strategy.get("analytics", []) or []:
                for source in analytic.get("log_sources", []) or []:
                    name = source.get("data_component_name") or source.get("data_component_id")
                    if name:
                        output.add(str(name))
    return output


def _d3fend_refs(d3fend_index: Any, techniques: set[str], limit: int = 30) -> list[str]:
    if d3fend_index is None:
        return []
    refs = set()
    for technique_id in sorted(techniques):
        try:
            rows = d3fend_index.lookup_attack(technique_id, limit=20)
        except Exception:
            continue
        for row in rows:
            for cell in row.values():
                if not isinstance(cell, dict):
                    continue
                value = str(cell.get("value", ""))
                if "d3fend" in value.lower() or "d3f:" in value.lower():
                    refs.add(value)
                    if len(refs) >= limit:
                        return sorted(refs)
    return sorted(refs)


def _telemetry_state(
    environment: dict[str, Any],
    nodes: list[str],
    relationships: list[dict[str, Any]],
    techniques: set[str],
    attack_index: Any = None,
) -> dict[str, Any]:
    requirements = set()
    for node in nodes:
        requirements.update(_asset_index(environment).get(node, {}).get("telemetry_requirements", []) or [])
    for rel in relationships:
        requirements.update(rel.get("required_telemetry", []) or [])

    data_components = _attack_data_components(attack_index, techniques)
    available_capabilities = set()
    available_components = set()
    sources = []
    for source in environment.get("telemetry_sources", []) or []:
        if str(source.get("status", "unknown")).lower() not in {"ready", "healthy", "active", "partial"}:
            continue
        scopes = set(source.get("target_ids", []) or [])
        rel_scopes = set(source.get("relationship_ids", []) or [])
        relationship_scope = {r.get("id") for r in relationships}
        if scopes or rel_scopes:
            if not scopes.intersection(nodes) and not rel_scopes.intersection(relationship_scope):
                continue
        available_capabilities.update(source.get("capabilities", []) or [])
        available_components.update(source.get("data_components", []) or [])
        sources.append(source.get("id"))

    missing = sorted(requirements - available_capabilities)
    missing_components = sorted(data_components - available_components)
    denominator = len(requirements) + len(data_components)
    covered = denominator - len(missing) - len(missing_components)
    ratio = (covered / denominator) if denominator else 1.0
    return {
        "requirements": sorted(requirements),
        "available_capabilities": sorted(available_capabilities),
        "missing": missing,
        "attack_data_components": sorted(data_components),
        "available_data_components": sorted(available_components),
        "missing_data_components": missing_components,
        "coverage": round(ratio, 4),
        "gap": round(1.0 - ratio, 4),
        "sources": sorted(source for source in sources if source),
    }


def _crown_jewel_impact(entities: dict[str, dict], crown_ids: set[str]) -> float:
    values = []
    for crown_id in crown_ids:
        wrapped = entities.get(crown_id)
        if not wrapped or wrapped["kind"] != "crown_jewel":
            continue
        impact = wrapped["data"].get("impact") or {}
        numeric = [float(v) for v in impact.values() if isinstance(v, (int, float))]
        if numeric:
            values.append(max(numeric) / 5.0)
    return max(values) if values else 0.6


def _band(score: float) -> str:
    if score >= 80:
        return "H0"
    if score >= 65:
        return "H1"
    if score >= 45:
        return "H2"
    return "H3"


def generate_candidate_paths(
    entities: dict[str, dict],
    environment: dict[str, Any],
    max_hops: int = 5,
    limit: int = 50,
    attack_index: Any = None,
    now: datetime | None = None,
    max_source_target_pairs: int = 2000,
) -> list[dict[str, Any]]:
    graph = _graph(environment)
    rel_index = _relationship_index(environment)
    assets = _asset_index(environment)
    now = now or datetime.now(timezone.utc)
    accepted = environment.get("accepted_forecasts", {}) or {}
    candidates = []

    considered_pairs = 0
    stop_search = False
    for source in _entry_nodes(environment):
        if stop_search:
            break
        for target in _target_nodes(environment):
            if source == target:
                continue
            considered_pairs += 1
            if considered_pairs > max_source_target_pairs:
                stop_search = True
                break
            try:
                paths = nx.all_simple_paths(graph, source=source, target=target, cutoff=max_hops)
                per_pair_cap = max(25, min(250, limit * 3))
                for nodes in islice(paths, per_pair_cap):
                    relationships = []
                    relation_ids = []
                    for left, right in zip(nodes, nodes[1:]):
                        edge = dict(graph.get_edge_data(left, right) or {})
                        rel_id = edge.get("relationship_id")
                        relationships.append(edge)
                        if rel_id:
                            relation_ids.append(rel_id)

                    techniques = _techniques(relationships)
                    crown_ids = set(assets.get(target, {}).get("crown_jewel_ids", []) or [])
                    impact = _crown_jewel_impact(entities, crown_ids)
                    entry_exposure = EXPOSURE.get(
                        str(assets.get(source, {}).get("internet_exposure", "unknown")).lower(), 0.5
                    )
                    relation_pressure = max(
                        [RELATION_PRESSURE.get(str(r.get("type", "other")).lower(), 0.5) for r in relationships] or [0.0]
                    )
                    vulnerability, vulnerability_rows = _vulnerability_pressure(environment, nodes)
                    intelligence, intelligence_rows = _intelligence_pressure(environment, nodes, techniques, now)
                    weakness, applied_controls = _control_weakness(environment, nodes, relationships)
                    telemetry = _telemetry_state(environment, nodes, relationships, techniques, attack_index=attack_index)

                    score = round(
                        100.0 * (
                            impact * 0.25
                            + entry_exposure * 0.15
                            + relation_pressure * 0.15
                            + vulnerability * 0.15
                            + intelligence * 0.15
                            + weakness * 0.10
                            + telemetry["gap"] * 0.05
                        ),
                        1,
                    )
                    path_id = _path_id(nodes)
                    candidates.append({
                        "id": path_id,
                        "source": source,
                        "target": target,
                        "nodes": nodes,
                        "relationship_ids": relation_ids,
                        "relationship_types": [r.get("type", "other") for r in relationships],
                        "technique_ids": sorted(techniques),
                        "crown_jewel_ids": sorted(crown_ids),
                        "forecast": {
                            "proposed_score": score,
                            "accepted_score": accepted.get(path_id),
                            "band": _band(score),
                            "review_required": True,
                            "components": {
                                "crown_jewel_impact": round(impact, 4),
                                "entry_exposure": round(entry_exposure, 4),
                                "relationship_pressure": round(relation_pressure, 4),
                                "vulnerability_pressure": round(vulnerability, 4),
                                "intelligence_pressure": round(intelligence, 4),
                                "control_weakness": round(weakness, 4),
                                "telemetry_gap": telemetry["gap"],
                            },
                        },
                        "controls": {"applied": applied_controls},
                        "telemetry": telemetry,
                        "vulnerability_signals": vulnerability_rows,
                        "intelligence_signals": intelligence_rows,
                    })
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

    candidates.sort(key=lambda row: row["forecast"]["proposed_score"], reverse=True)
    return candidates[:limit]


def weighted_choke_points(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    risk = defaultdict(float)
    leverage = defaultdict(float)
    count = defaultdict(int)
    transit = defaultdict(int)
    entry = defaultdict(int)
    target = defaultdict(int)
    crowns = defaultdict(set)
    total = sum(float(p["forecast"]["proposed_score"]) for p in paths) or 1.0

    for path in paths:
        weight = float(path["forecast"]["proposed_score"])
        nodes = path.get("nodes", []) or []
        for index, node in enumerate(nodes):
            risk[node] += weight
            count[node] += 1
            crowns[node].update(path.get("crown_jewel_ids", []) or [])
            if index == 0:
                entry[node] += 1
                leverage[node] += weight * 0.50
            elif index == len(nodes) - 1:
                target[node] += 1
                leverage[node] += weight * 0.35
            else:
                transit[node] += 1
                leverage[node] += weight

    output = []
    for node, value in risk.items():
        output.append({
            "node_id": node,
            "weighted_risk": round(value, 1),
            "defensive_leverage": round(leverage[node], 1),
            "risk_share": round(value / total, 4),
            "candidate_paths": count[node],
            "transit_paths": transit[node],
            "entry_paths": entry[node],
            "target_paths": target[node],
            "crown_jewel_ids": sorted(crowns[node]),
        })
    return sorted(
        output,
        key=lambda row: (row["defensive_leverage"], row["transit_paths"], row["weighted_risk"]),
        reverse=True,
    )


def detection_by_absence(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    gaps = []
    for path in paths:
        telemetry = path.get("telemetry") or {}
        missing = telemetry.get("missing", []) or []
        missing_components = telemetry.get("missing_data_components", []) or []
        if not missing and not missing_components:
            continue
        gaps.append({
            "path_id": path.get("id"),
            "band": (path.get("forecast") or {}).get("band"),
            "proposed_score": (path.get("forecast") or {}).get("proposed_score"),
            "crown_jewel_ids": path.get("crown_jewel_ids", []),
            "technique_ids": path.get("technique_ids", []),
            "missing_telemetry": missing,
            "missing_attack_data_components": missing_components,
            "coverage": telemetry.get("coverage"),
            "review_required": True,
        })
    return gaps


def _action_applies(
    action: dict[str, Any],
    path: dict[str, Any],
    assets: dict[str, dict[str, Any]],
) -> tuple[bool, list[str], list[str]]:
    triggers = action.get("triggers") or {}
    nodes = path.get("nodes", []) or []
    relation_types = set(path.get("relationship_types", []) or [])
    target_nodes = []
    target_relationships = []

    expected_exposure = set(triggers.get("exposure", []) or [])
    if expected_exposure:
        for node in nodes:
            if assets.get(node, {}).get("internet_exposure") in expected_exposure:
                target_nodes.append(node)

    expected_types = set(triggers.get("node_types", []) or [])
    if expected_types:
        for node in nodes:
            if assets.get(node, {}).get("type") in expected_types:
                target_nodes.append(node)

    relation_triggers = set(triggers.get("relationship_types", []) or [])
    if relation_triggers & relation_types:
        for rel_id, rel_type in zip(path.get("relationship_ids", []), path.get("relationship_types", [])):
            if rel_type in relation_triggers:
                target_relationships.append(rel_id)

    if triggers.get("telemetry_gap") and (path.get("telemetry") or {}).get("gap", 0) > 0:
        target_nodes.extend(nodes)

    if triggers.get("vulnerability_signal") and path.get("vulnerability_signals"):
        target_nodes.extend(row.get("target_id") for row in path["vulnerability_signals"] if row.get("target_id"))

    applies = bool(target_nodes or target_relationships)
    return applies, sorted(set(target_nodes)), sorted(set(target_relationships))


def propose_preemptive_actions(
    environment: dict[str, Any],
    paths: list[dict[str, Any]],
    budget: float | None = None,
    d3fend_index: Any = None,
) -> dict[str, Any]:
    assets = _asset_index(environment)
    candidates: dict[tuple[str, tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}

    for path in paths:
        path_score = float(path["forecast"]["proposed_score"])
        for action in _control_catalog():
            applies, target_nodes, target_relationships = _action_applies(action, path, assets)
            if not applies:
                continue
            key = (action["id"], tuple(target_nodes), tuple(target_relationships))
            row = candidates.setdefault(key, {
                "catalog_id": action["id"],
                "name": action["name"],
                "action_class": action["action_class"],
                "target_ids": target_nodes,
                "relationship_ids": target_relationships,
                "path_ids": [],
                "crown_jewel_ids": set(),
                "estimated_risk_reduction": 0.0,
                "cost": float(action.get("cost", 1)),
                "effectiveness": float(action.get("effectiveness", 0.0)),
                "defensive_terms": action.get("defensive_terms", []),
                "technique_ids": set(),
                "status": "proposed",
                "review_required": True,
            })
            row["path_ids"].append(path["id"])
            row["crown_jewel_ids"].update(path.get("crown_jewel_ids", []) or [])
            row["technique_ids"].update(path.get("technique_ids", []) or [])
            row["estimated_risk_reduction"] += path_score * row["effectiveness"]

    normalized = []
    for row in candidates.values():
        row["crown_jewel_ids"] = sorted(row["crown_jewel_ids"])
        row["path_ids"] = sorted(set(row["path_ids"]))
        technique_ids = set(row["technique_ids"])
        row["technique_ids"] = sorted(technique_ids)
        row["d3fend_refs"] = _d3fend_refs(d3fend_index, technique_ids)
        row["estimated_risk_reduction"] = round(row["estimated_risk_reduction"], 1)
        row["benefit_cost"] = round(row["estimated_risk_reduction"] / max(row["cost"], 0.1), 2)
        normalized.append(row)

    normalized.sort(key=lambda row: (row["benefit_cost"], row["estimated_risk_reduction"]), reverse=True)

    selected = []
    spent = 0.0
    portfolio_reduction = None
    if budget is not None:
        residual = {
            path["id"]: float(path["forecast"]["proposed_score"])
            for path in paths
        }
        remaining = [dict(row) for row in normalized]

        while remaining:
            affordable = [row for row in remaining if spent + row["cost"] <= budget]
            if not affordable:
                break

            ranked = []
            for row in affordable:
                marginal = sum(
                    residual.get(path_id, 0.0) * row["effectiveness"]
                    for path_id in row.get("path_ids", [])
                )
                ranked.append((
                    marginal / max(row["cost"], 0.1),
                    marginal,
                    row,
                ))
            ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
            ratio, marginal, chosen = ranked[0]
            if marginal <= 0:
                break

            chosen = dict(chosen)
            chosen["marginal_risk_reduction"] = round(marginal, 1)
            chosen["marginal_benefit_cost"] = round(ratio, 2)
            selected.append(chosen)
            spent += chosen["cost"]

            for path_id in chosen.get("path_ids", []):
                if path_id in residual:
                    residual[path_id] *= 1.0 - chosen["effectiveness"]

            remaining = [
                row for row in remaining
                if not (
                    row["catalog_id"] == chosen["catalog_id"]
                    and row.get("target_ids") == chosen.get("target_ids")
                    and row.get("relationship_ids") == chosen.get("relationship_ids")
                )
            ]

        initial = sum(float(path["forecast"]["proposed_score"]) for path in paths)
        portfolio_reduction = round(initial - sum(residual.values()), 1)

    return {
        "candidates": normalized,
        "selected": selected if budget is not None else normalized,
        "budget": budget,
        "spent": round(spent, 2) if budget is not None else None,
        "estimated_portfolio_risk_reduction": portfolio_reduction,
        "policy": {
            "review_required": True,
            "automatic_control_change": False,
            "score_is_forecast_pressure_not_probability": True,
            "optimizer_uses_marginal_path_coverage": True,
        },
    }


def _scenario_priority_from_path(path: dict[str, Any]) -> dict[str, Any]:
    components = path["forecast"]["components"]
    to5 = lambda value: round(min(max(float(value), 0.0), 1.0) * 5, 2)
    return {
        "crown_jewel_criticality": to5(components["crown_jewel_impact"]),
        "threat_relevance": to5(components["intelligence_pressure"]),
        "attack_path_feasibility": to5(components["relationship_pressure"]),
        "exposure": to5(components["entry_exposure"]),
        "control_weakness": to5(components["control_weakness"]),
        "detection_gap": to5(components["telemetry_gap"]),
        "calculated_score": None,
        "band": "",
        "rationale": "Candidate values generated by TCE Horizon and require analyst review.",
    }


def candidate_scenarios(paths: list[dict[str, Any]], environment: dict[str, Any]) -> list[dict[str, Any]]:
    rel_index = _relationship_index(environment)
    assets = _asset_index(environment)
    output = []
    for path in paths:
        steps = []
        for order, (left, right, rel_id) in enumerate(
            zip(path["nodes"], path["nodes"][1:], path["relationship_ids"]),
            start=1,
        ):
            rel = rel_index.get(rel_id, {})
            steps.append({
                "order": order,
                "behavior": f"{rel.get('type', 'relationship')} across modeled trust/dependency",
                "architecture_node_id": right,
                "attack_techniques": rel.get("technique_ids", []) or RELATION_TECHNIQUE_HINTS.get(
                    str(rel.get("type", "")).lower(), []
                ),
                "relationship_id": rel_id,
            })

        digest = path["id"].split("-")[-1]
        output.append({
            "id": f"TS-HZN-{digest}",
            "title": f"Candidate enterprise exposure path: {assets.get(path['source'], {}).get('name', path['source'])} -> {assets.get(path['target'], {}).get('name', path['target'])}",
            "objective": "Assess whether the modeled trust and dependency chain could create material exposure to a crown jewel.",
            "status": "candidate",
            "review_required": True,
            "generated_by": "TCE Horizon",
            "source_horizon_path_id": path["id"],
            "target_crown_jewels": path.get("crown_jewel_ids", []),
            "attack_path": {
                "id": f"AP-HZN-{digest}",
                "entry_vector": "modeled enterprise exposure/trust entry point",
                "steps": steps,
            },
            "priority": _scenario_priority_from_path(path),
            "confidence": "low",
            "telemetry_requirements": [],
            "detection_use_cases": [],
            "detection_specification_ids": [],
            "validation_ids": [],
            "forecast": path["forecast"],
        })
    return output


def horizon_assessment(
    entities: dict[str, dict],
    environment_id: str | None = None,
    max_hops: int = 5,
    limit: int = 50,
    attack_index: Any = None,
    d3fend_index: Any = None,
    budget: float | None = None,
    max_source_target_pairs: int = 2000,
) -> dict[str, Any]:
    envs = environments(entities)
    if not envs:
        derived = derive_environment_from_architecture(entities)
        if derived:
            envs = [derived]
        else:
            raise ValueError("No environment_state or architecture object found in the case")
    if environment_id:
        matches = [item for item in envs if item.get("id") == environment_id]
        if not matches:
            raise KeyError(f"Unknown environment: {environment_id}")
        environment = matches[0]
    else:
        environment = envs[0]

    paths = generate_candidate_paths(
        entities,
        environment,
        max_hops=max_hops,
        limit=limit,
        attack_index=attack_index,
        max_source_target_pairs=max_source_target_pairs,
    )
    reached_targets = sorted({path.get("target") for path in paths if path.get("target")})
    target_nodes = _target_nodes(environment)
    source_target_pairs = len(_entry_nodes(environment)) * len(target_nodes)
    band_counts = {band: sum(1 for path in paths if path["forecast"]["band"] == band) for band in ("H0", "H1", "H2", "H3")}
    return {
        "environment_id": environment.get("id"),
        "snapshot_at": environment.get("snapshot_at"),
        "derived_environment": bool(environment.get("derived")),
        "summary": {
            "assets_and_identities": len(_asset_index(environment)),
            "relationships": len(environment.get("relationships", []) or []),
            "entry_nodes": len(_entry_nodes(environment)),
            "crown_jewel_nodes": len(target_nodes),
            "candidate_paths": len(paths),
            "source_target_pairs": source_target_pairs,
            "search_truncated_by_pair_cap": source_target_pairs > max_source_target_pairs,
            "bands": band_counts,
        },
        "entry_nodes": _entry_nodes(environment),
        "crown_jewel_nodes": target_nodes,
        "reached_crown_jewel_nodes": reached_targets,
        "unreached_crown_jewel_nodes": sorted(set(target_nodes) - set(reached_targets)),
        "candidate_paths": paths,
        "choke_points": weighted_choke_points(paths),
        "detection_by_absence": detection_by_absence(paths),
        "preemptive_actions": propose_preemptive_actions(
            environment,
            paths,
            budget=budget,
            d3fend_index=d3fend_index,
        ),
        "policy": {
            "candidate_paths_only": True,
            "analyst_review_required": True,
            "automatic_exploitation": False,
            "accepted_score_is_separate": True,
            "bounded_search": True,
            "max_source_target_pairs": max_source_target_pairs,
        },
    }


def write_candidate_scenarios(
    assessment: dict[str, Any],
    environment: dict[str, Any],
    output: str | Path,
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "version": "0.5",
        "generated_by": "TCE Horizon",
        "review_required": True,
        "scenarios": candidate_scenarios(assessment.get("candidate_paths", []), environment),
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def write_assessment(assessment: dict[str, Any], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(assessment, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _preemptive_action_id(row: dict[str, Any]) -> str:
    payload = "|".join([
        str(row.get("catalog_id", "")),
        ",".join(row.get("target_ids", []) or []),
        ",".join(row.get("relationship_ids", []) or []),
    ])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:10].upper()
    return f"PA-HZN-{digest}"


def write_preemptive_actions(
    assessment: dict[str, Any],
    output: str | Path,
    selected_only: bool = True,
) -> Path:
    source = assessment.get("preemptive_actions", {})
    rows = source.get("selected" if selected_only else "candidates", []) or []
    actions = []
    for row in rows:
        item = dict(row)
        item["id"] = _preemptive_action_id(row)
        item["rationale"] = (
            "Review-gated Horizon proposal based on risk-weighted enterprise path coverage; "
            "estimated reduction is a prioritization aid, not a guaranteed outcome."
        )
        actions.append(item)

    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": "0.5",
        "generated_by": "TCE Horizon",
        "review_required": True,
        "preemptive_actions": actions,
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def horizon_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    old = {row["id"]: row for row in before.get("candidate_paths", []) or []}
    new = {row["id"]: row for row in after.get("candidate_paths", []) or []}
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = []
    for path_id in sorted(set(old) & set(new)):
        old_score = float((old[path_id].get("forecast") or {}).get("proposed_score", 0))
        new_score = float((new[path_id].get("forecast") or {}).get("proposed_score", 0))
        old_components = (old[path_id].get("forecast") or {}).get("components", {}) or {}
        new_components = (new[path_id].get("forecast") or {}).get("components", {}) or {}
        component_delta = {}
        for key in sorted(set(old_components) | set(new_components)):
            before_value = float(old_components.get(key, 0) or 0)
            after_value = float(new_components.get(key, 0) or 0)
            delta = round(after_value - before_value, 4)
            if delta:
                component_delta[key] = delta

        if old_score != new_score or component_delta:
            changed.append({
                "path_id": path_id,
                "before": old_score,
                "after": new_score,
                "delta": round(new_score - old_score, 1),
                "direction": "increased" if new_score > old_score else ("decreased" if new_score < old_score else "component-change"),
                "component_delta": component_delta,
                "drivers": [
                    key
                    for key, value in sorted(component_delta.items(), key=lambda item: abs(item[1]), reverse=True)
                    if abs(value) >= 0.01
                ][:4],
            })

    old_absence = {row["path_id"] for row in before.get("detection_by_absence", []) or []}
    new_absence = {row["path_id"] for row in after.get("detection_by_absence", []) or []}

    return {
        "environment_before": before.get("environment_id"),
        "environment_after": after.get("environment_id"),
        "paths": {
            "added": added,
            "removed": removed,
            "score_changes": changed,
        },
        "detection_by_absence": {
            "new_blind_paths": sorted(new_absence - old_absence),
            "resolved_blind_paths": sorted(old_absence - new_absence),
        },
        "summary_delta": {
            "candidate_paths": (after.get("summary", {}).get("candidate_paths", 0) - before.get("summary", {}).get("candidate_paths", 0)),
            "h0_h1": (
                after.get("summary", {}).get("bands", {}).get("H0", 0)
                + after.get("summary", {}).get("bands", {}).get("H1", 0)
                - before.get("summary", {}).get("bands", {}).get("H0", 0)
                - before.get("summary", {}).get("bands", {}).get("H1", 0)
            ),
        },
        "review_required": True,
    }


def diff_horizon_files(before: str | Path, after: str | Path) -> dict[str, Any]:
    return horizon_diff(
        json.loads(Path(before).read_text(encoding="utf-8")),
        json.loads(Path(after).read_text(encoding="utf-8")),
    )
