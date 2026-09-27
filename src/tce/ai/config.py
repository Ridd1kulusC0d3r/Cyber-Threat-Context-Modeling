from __future__ import annotations

import os
from dataclasses import dataclass


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def choose_qwen_model() -> str:
    configured = os.getenv("TCE_QWEN_MODEL", "auto").strip()
    if configured and configured.lower() != "auto":
        return configured
    try:
        import torch
        if torch.cuda.is_available():
            gb = torch.cuda.get_device_properties(0).total_memory / (1024 ** 3)
            if gb >= 13:
                return "Qwen/Qwen3-4B"
            if gb >= 7:
                return "Qwen/Qwen3-1.7B"
    except Exception:
        pass
    return "Qwen/Qwen3-0.6B"


@dataclass(frozen=True)
class AIConfig:
    gliner_enabled: bool = _bool_env("TCE_AI_GLINER", True)
    qwen_enabled: bool = _bool_env("TCE_AI_QWEN", True)
    gliner_model: str = os.getenv("TCE_GLINER_MODEL", "urchade/gliner_medium-v2.1")
    qwen_model: str = choose_qwen_model()
    gliner_threshold: float = float(os.getenv("TCE_GLINER_THRESHOLD", "0.45"))
    qwen_max_new_tokens: int = int(os.getenv("TCE_QWEN_MAX_NEW_TOKENS", "1200"))
    qwen_4bit: bool = _bool_env("TCE_QWEN_4BIT", True)
