from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from urllib.parse import urlencode

import requests

TAXII_ACCEPT = "application/taxii+json;version=2.1"


def pull_collection(
    collection_url: str,
    output: str | Path | None = None,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    added_after: str | None = None,
    limit: int = 100,
    max_pages: int = 20,
) -> dict:
    base = collection_url.rstrip("/")
    objects_url = base if base.endswith("/objects") else base + "/objects"

    headers = {"Accept": TAXII_ACCEPT}
    token = token or os.getenv("TAXII_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    auth = None
    username = username or os.getenv("TAXII_USERNAME")
    password = password or os.getenv("TAXII_PASSWORD")
    if username:
        auth = (username, password or "")

    objects = []
    next_value = None
    pages = 0

    while pages < max_pages:
        params = {"limit": limit}
        if added_after:
            params["added_after"] = added_after
        if next_value:
            params["next"] = next_value

        response = requests.get(
            objects_url,
            headers=headers,
            auth=auth,
            params=params,
            timeout=120,
        )
        response.raise_for_status()
        envelope = response.json()
        objects.extend(envelope.get("objects", []) or [])
        pages += 1

        if not envelope.get("more"):
            break
        next_value = envelope.get("next")
        if not next_value:
            break

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
        "x_tce_taxii_source": collection_url,
        "x_tce_pages": pages,
    }
    if output:
        write_bundle(bundle, output)
    return bundle


def write_bundle(bundle: dict, output: str | Path):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return path
