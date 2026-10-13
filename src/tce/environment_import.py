from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


LIST_FIELDS = {
    "crown_jewel_ids",
    "control_ids",
    "telemetry_requirements",
    "technology_tags",
    "technique_ids",
    "required_telemetry",
    "target_ids",
    "relationship_ids",
    "capabilities",
    "data_components",
}


def _bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _list(value: str | None) -> list[str]:
    if not value:
        return []
    raw = str(value).replace(";", ",")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _rows(path: str | Path | None) -> list[dict[str, str]]:
    if not path:
        return []
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _clean(row: dict[str, str]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in row.items():
        if value is None or str(value).strip() == "":
            continue
        if key in LIST_FIELDS:
            output[key] = _list(value)
        elif key in {"entry_point", "external", "bidirectional", "kev"}:
            output[key] = _bool(value)
        elif key in {"effectiveness", "epss", "information_credibility", "relevance", "half_life_days"}:
            output[key] = float(value)
        else:
            output[key] = str(value).strip()
    return output


def environment_from_csv(
    assets_csv: str | Path,
    relationships_csv: str | Path,
    output: str | Path,
    *,
    environment_id: str = "ENV-IMPORTED",
    name: str = "Imported enterprise environment",
    snapshot_at: str = "",
    controls_csv: str | Path | None = None,
    telemetry_csv: str | Path | None = None,
    vulnerabilities_csv: str | Path | None = None,
    intelligence_csv: str | Path | None = None,
) -> Path:
    assets = []
    identities = []
    for raw in _rows(assets_csv):
        row = _clean(raw)
        record_kind = row.pop("record_kind", "asset")
        if record_kind == "identity":
            identities.append(row)
        else:
            assets.append(row)

    relationships = [_clean(row) for row in _rows(relationships_csv)]
    controls = [_clean(row) for row in _rows(controls_csv)]
    telemetry = [_clean(row) for row in _rows(telemetry_csv)]
    vulnerabilities = [_clean(row) for row in _rows(vulnerabilities_csv)]
    intelligence = [_clean(row) for row in _rows(intelligence_csv)]

    snapshot_at = snapshot_at or datetime.now(timezone.utc).isoformat()

    payload = {
        "version": "0.5",
        "environment_state": {
            "id": environment_id,
            "name": name,
            "snapshot_at": snapshot_at,
            "scope": "enterprise",
            "assets": assets,
            "identities": identities,
            "relationships": relationships,
            "controls": controls,
            "telemetry_sources": telemetry,
            "vulnerability_signals": vulnerabilities,
            "intelligence_signals": intelligence,
            "accepted_forecasts": {},
        },
    }

    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return path
