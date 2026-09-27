from __future__ import annotations

import json
import os
from pathlib import Path


def bundle_summary(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    kinds = {}
    for obj in data.get("objects", []):
        kind = obj.get("type", "unknown")
        kinds[kind] = kinds.get(kind, 0) + 1
    return {
        "bundle_id": data.get("id"),
        "objects": len(data.get("objects", [])),
        "types": kinds,
    }


def push_bundle(
    path: str | Path,
    url: str | None = None,
    token: str | None = None,
    update: bool = False,
):
    url = url or os.getenv("OPENCTI_URL")
    token = token or os.getenv("OPENCTI_TOKEN")
    if not url or not token:
        raise RuntimeError("OPENCTI_URL and OPENCTI_TOKEN are required")
    try:
        from pycti import OpenCTIApiClient
    except ImportError as exc:
        raise RuntimeError("Install OpenCTI support with pip install -e '.[opencti]'") from exc
    client = OpenCTIApiClient(url, token)
    content = Path(path).read_text(encoding="utf-8")
    return client.stix2.import_bundle_from_json(content, update=update)
