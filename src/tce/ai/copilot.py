from __future__ import annotations

from .config import AIConfig
from .evidence_packet import EvidencePacket
from .gliner_engine import GLiNEREngine
from .qwen_engine import QwenEngine


class TCECopilot:
    def __init__(self, config: AIConfig | None = None):
        self.config = config or AIConfig()
        self.gliner = GLiNEREngine(self.config)
        self.qwen = QwenEngine(self.config)

    def analyze_text(self, text: str, source_id: str = "SOURCE-001", **context):
        packet = EvidencePacket.from_text(text, source_id=source_id, **context)
        entities = self.gliner.extract(text) if self.config.gliner_enabled else []
        reasoning = (
            self.qwen.analyze(packet.as_dict(), entities)
            if self.config.qwen_enabled
            else {"status": "disabled"}
        )
        return {
            "evidence_packet": packet.as_dict(),
            "entity_candidates": entities,
            "reasoning_candidates": reasoning,
            "integrity": {
                "evidence_mutated": False,
                "auto_merge_into_case": False,
                "analyst_review_required": True,
            },
        }
