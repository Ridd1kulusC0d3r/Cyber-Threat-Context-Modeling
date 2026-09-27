from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EvidencePacket:
    packet_id: str
    evidence: tuple[dict[str, Any], ...]
    context: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_text(cls, text: str, source_id: str = "SOURCE-001", **context: str):
        evidence = ({
            "id": source_id,
            "evidence_state": "observed",
            "content": text,
        },)
        canonical = json.dumps(
            {"evidence": evidence, "context": sorted(context.items())},
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        return cls(
            packet_id=f"sha256:{digest}",
            evidence=evidence,
            context=tuple(sorted(context.items())),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "evidence": [dict(item) for item in self.evidence],
            "context": dict(self.context),
        }
