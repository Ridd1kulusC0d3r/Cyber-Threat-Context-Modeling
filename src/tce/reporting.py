from __future__ import annotations

from datetime import datetime, timezone

from .analysis import choke_points, coverage_summary, find_gaps, scored_scenarios


def markdown_report(entities: dict[str, dict]) -> str:
    counts = {}
    for wrapped in entities.values():
        counts[wrapped["kind"]] = counts.get(wrapped["kind"], 0) + 1

    scores = scored_scenarios(entities)
    gaps = find_gaps(entities)
    coverage = coverage_summary(entities)
    choke = choke_points(entities)

    lines = [
        "# TCE Case Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Inventory",
        "",
        "| Entity | Count |",
        "|---|---:|",
    ]
    for kind, count in sorted(counts.items()):
        lines.append(f"| {kind} | {count} |")

    lines += ["", "## Prioritized scenarios", "", "| ID | Score | Band | Confidence | Title |", "|---|---:|---|---|---|"]
    for item in scores:
        lines.append(f"| {item['id']} | {item['score']:.2f} | {item['band']} | {item['confidence']} | {item['title']} |")

    lines += ["", "## Coverage", "", "| Dimension | Coverage |", "|---|---:|"]
    for dim, value in coverage.items():
        rendered = "unknown" if value is None else f"{value}%"
        lines.append(f"| {dim} | {rendered} |")

    lines += ["", "## Defensive choke points", "", "| Architecture node | P0/P1 paths |", "|---|---:|"]
    for item in choke[:10]:
        lines.append(f"| {item['node']} | {item['critical_paths']} |")

    lines += ["", "## Open gaps", "", "| Type | ID | Priority | Description |", "|---|---|---|---|"]
    for gap in gaps:
        lines.append(f"| {gap['type']} | {gap['id']} | {gap['priority']} | {gap['description']} |")

    lines += [
        "",
        "## Interpretation",
        "",
        "This report is a decision aid. Scores and percentages must be reviewed with architecture, business impact, evidence quality, and validation results.",
        "",
    ]
    return "\n".join(lines)
