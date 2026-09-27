from __future__ import annotations

from .config import AIConfig

DEFAULT_LABELS = [
    "threat actor",
    "campaign",
    "malware",
    "tool",
    "vulnerability",
    "organization",
    "sector",
    "technology",
    "cloud service",
    "identity",
    "asset",
    "security control",
    "attack technique",
    "data source",
]


class GLiNEREngine:
    def __init__(self, config: AIConfig | None = None):
        self.config = config or AIConfig()
        self._model = None

    def load(self):
        if not self.config.gliner_enabled:
            return None
        if self._model is None:
            try:
                from gliner import GLiNER
            except ImportError as exc:
                raise RuntimeError("Install AI support with pip install -e '.[ai]'") from exc
            self._model = GLiNER.from_pretrained(self.config.gliner_model)
        return self._model

    def extract(self, text: str, labels: list[str] | None = None) -> list[dict]:
        if not self.config.gliner_enabled:
            return []
        rows = self.load().predict_entities(
            text,
            labels or DEFAULT_LABELS,
            threshold=self.config.gliner_threshold,
        )
        return [
            {
                "text": row.get("text"),
                "label": row.get("label"),
                "score": float(row.get("score", 0.0)),
                "start": row.get("start"),
                "end": row.get("end"),
                "status": "candidate",
                "provenance": "GLiNER",
            }
            for row in rows
        ]
