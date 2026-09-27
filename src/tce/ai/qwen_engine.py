from __future__ import annotations

import json
import re

from .config import AIConfig

SYSTEM_PROMPT = """You are the TCE defensive intelligence copilot.
Work only from the supplied immutable Evidence Packet and entity candidates.

Rules:
1. Never rewrite, delete, or silently correct evidence.
2. Separate observation from inference.
3. Every suggestion must cite one or more evidence IDs.
4. ATT&CK technique IDs are candidates until deterministically validated.
5. Include contradicting evidence or alternative explanations when present.
6. Do not invent actors, campaigns, vulnerabilities, techniques, or facts absent from evidence.
7. Output JSON only.
8. The output is a review queue, never an automatic case modification.

Return: summary, entity_links, hypothesis_candidates, attack_technique_candidates,
intelligence_gaps, alternative_explanations, confidence_notes.
"""


def _extract_json(text: str) -> dict:
    text = text.strip()
    fenced = re.search(r"\x60\x60\x60(?:json)?\s*(\{.*\})\s*\x60\x60\x60", text, re.S)
    if fenced:
        text = fenced.group(1)
    else:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            text = text[start:end + 1]
    return json.loads(text)


class QwenEngine:
    def __init__(self, config: AIConfig | None = None):
        self.config = config or AIConfig()
        self._tokenizer = None
        self._model = None

    def load(self):
        if not self.config.qwen_enabled:
            return None
        if self._model is not None:
            return self._tokenizer, self._model

        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        except ImportError as exc:
            raise RuntimeError("Install AI support with pip install -e '.[ai]'") from exc

        kwargs = {"device_map": "auto", "low_cpu_mem_usage": True}
        if torch.cuda.is_available() and self.config.qwen_4bit:
            kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.float16,
            )
        elif torch.cuda.is_available():
            kwargs["torch_dtype"] = torch.float16

        self._tokenizer = AutoTokenizer.from_pretrained(self.config.qwen_model)
        self._model = AutoModelForCausalLM.from_pretrained(self.config.qwen_model, **kwargs)
        return self._tokenizer, self._model

    def analyze(self, packet: dict, entities: list[dict]) -> dict:
        if not self.config.qwen_enabled:
            return {"status": "disabled"}

        tokenizer, model = self.load()
        payload = json.dumps(
            {"evidence_packet": packet, "entity_candidates": entities},
            ensure_ascii=False,
        )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": payload},
        ]
        try:
            inputs = tokenizer.apply_chat_template(
                messages,
                add_generation_prompt=True,
                enable_thinking=False,
                tokenize=True,
                return_dict=True,
                return_tensors="pt",
            )
        except TypeError:
            inputs = tokenizer.apply_chat_template(
                messages,
                add_generation_prompt=True,
                tokenize=True,
                return_dict=True,
                return_tensors="pt",
            )
        inputs = {key: value.to(model.device) for key, value in inputs.items()}
        output = model.generate(
            **inputs,
            max_new_tokens=self.config.qwen_max_new_tokens,
            do_sample=False,
        )
        generated = output[0][inputs["input_ids"].shape[-1]:]
        result = _extract_json(tokenizer.decode(generated, skip_special_tokens=True))
        result["_ai_metadata"] = {
            "model": self.config.qwen_model,
            "status": "candidate",
            "evidence_packet_id": packet["packet_id"],
        }
        return result
