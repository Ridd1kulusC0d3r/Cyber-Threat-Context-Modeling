from __future__ import annotations

WEIGHTS = {
    "crown_jewel_criticality": 0.25,
    "threat_relevance": 0.20,
    "attack_path_feasibility": 0.15,
    "exposure": 0.15,
    "control_weakness": 0.10,
    "detection_gap": 0.15,
}


def priority_score(priority: dict) -> float:
    score = 0.0
    for field, weight in WEIGHTS.items():
        value = float(priority.get(field, 0) or 0)
        if not 0 <= value <= 5:
            raise ValueError(f"{field} must be between 0 and 5")
        score += value * weight
    return round(score, 2)


def priority_band(score: float) -> str:
    if score >= 4.25:
        return "P0"
    if score >= 3.50:
        return "P1"
    if score >= 2.50:
        return "P2"
    return "P3"


def score_scenario(scenario: dict) -> dict:
    priority = scenario.get("priority") or {}
    score = priority_score(priority)
    return {
        "id": scenario.get("id"),
        "title": scenario.get("title", ""),
        "score": score,
        "band": priority_band(score),
        "confidence": scenario.get("confidence", "unknown"),
    }
