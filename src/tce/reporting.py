from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from .analysis import choke_points, coverage_summary, find_gaps, scored_scenarios


def _counts(entities):
    result = {}
    for wrapped in entities.values():
        result[wrapped["kind"]] = result.get(wrapped["kind"], 0) + 1
    return result


def _hypotheses(entities):
    return [w["data"] for w in entities.values() if w["kind"] == "hypothesis"]


def _decisions(entities):
    return [w["data"] for w in entities.values() if w["kind"] == "decision"]


def _contexts(entities):
    return [w["data"] for w in entities.values() if w["kind"] == "threat_context"]


def _horizon(entities):
    if not any(w["kind"] == "environment_state" for w in entities.values()):
        return None
    try:
        from .horizon import horizon_assessment

        return horizon_assessment(
            entities,
            max_hops=5,
            limit=25,
            attack_index=None,
            budget=8,
        )
    except (ValueError, KeyError):
        return None


def markdown_report(entities: dict[str, dict], audience: str = "all") -> str:
    counts = _counts(entities)
    scores = scored_scenarios(entities)
    gaps = find_gaps(entities)
    coverage = coverage_summary(entities)
    choke = choke_points(entities)
    hypotheses = _hypotheses(entities)
    decisions = _decisions(entities)
    contexts = _contexts(entities)
    horizon = _horizon(entities)

    lines = [
        f"# TCEM {audience.title()} Report" if audience != "all" else "# TCEM Case Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
    ]

    if audience in {"all", "executive"}:
        lines += [
            "## Executive attention",
            "",
            f"- Crown jewels: {counts.get('crown_jewel', 0)}",
            f"- Threat contexts: {counts.get('threat_context', 0)}",
            f"- Threat hypotheses: {counts.get('hypothesis', 0)}",
            f"- Threat scenarios: {counts.get('scenario', 0)}",
            f"- Open gaps: {len(gaps)}",
            f"- Decisions: {counts.get('decision', 0)}",
            "",
            "### Prioritized scenarios",
            "",
            "| ID | Score | Band | Confidence | Title |",
            "|---|---:|---|---|---|",
        ]
        for item in scores:
            lines.append(
                f"| {item['id']} | {item['score']:.2f} | {item['band']} | "
                f"{item['confidence']} | {item['title']} |"
            )

        if horizon:
            summary = horizon.get("summary", {})
            bands = summary.get("bands", {})
            lines += [
                "",
                "### Horizon enterprise forecast",
                "",
                f"- Environment: {horizon.get('environment_id')}",
                f"- Candidate paths: {summary.get('candidate_paths', 0)}",
                f"- H0/H1 paths: {bands.get('H0', 0) + bands.get('H1', 0)}",
                f"- Detection-by-Absence paths: {len(horizon.get('detection_by_absence', []) or [])}",
                f"- Unreached crown-jewel nodes: {len(horizon.get('unreached_crown_jewel_nodes', []) or [])}",
                "",
                "| Horizon path | Score | Band | Crown jewels |",
                "|---|---:|---|---|",
            ]
            for path in (horizon.get("candidate_paths", []) or [])[:10]:
                lines.append(
                    f"| {path.get('id')} | {path.get('forecast', {}).get('proposed_score')} | "
                    f"{path.get('forecast', {}).get('band')} | "
                    f"{', '.join(path.get('crown_jewel_ids', []))} |"
                )

        lines += ["", "### Decisions", ""]
        for decision in decisions:
            lines.append(
                f"- **{decision.get('id')}** {decision.get('title', '')}: "
                f"{decision.get('status', 'unknown')}"
            )

    if audience in {"all", "cti"}:
        lines += [
            "",
            "## Intelligence",
            "",
            "### Hypotheses",
            "",
            "| ID | Confidence | Status | Statement |",
            "|---|---|---|---|",
        ]
        for hyp in hypotheses:
            lines.append(
                f"| {hyp.get('id')} | {hyp.get('confidence', 'unknown')} | "
                f"{hyp.get('status', 'unknown')} | {hyp.get('statement', '')} |"
            )

        if horizon:
            lines += ["", "### Accepted Horizon intelligence contributions", ""]
            seen = set()
            for path in (horizon.get("candidate_paths", []) or []):
                for signal in path.get("intelligence_signals", []) or []:
                    signal_id = signal.get("id")
                    if not signal_id or signal_id in seen:
                        continue
                    seen.add(signal_id)
                    lines.append(
                        f"- **{signal_id}**: value={signal.get('value')} "
                        f"confidence={signal.get('confidence')} "
                        f"source_reliability={signal.get('source_reliability')}"
                    )

        lines += ["", "### Intelligence gaps", ""]
        for gap in gaps:
            if gap["type"] == "intelligence":
                lines.append(
                    f"- **{gap['id']}** [{gap['priority']}]: {gap['description']}"
                )

    if audience in {"all", "architecture"}:
        lines += [
            "",
            "## Architecture and choke points",
            "",
            "### Threat contexts",
            "",
            "| ID | Lens | Confidence | Relevance |",
            "|---|---|---|---|",
        ]
        for context in contexts:
            lines.append(
                f"| {context.get('id')} | {context.get('lens_id', '')} | "
                f"{context.get('confidence', 'unknown')} | "
                f"{context.get('relevance', '')} |"
            )

        lines += [
            "",
            "### Accepted-scenario defensive choke points",
            "",
            "| Architecture node | P0/P1 paths |",
            "|---|---:|",
        ]
        for item in choke[:15]:
            lines.append(f"| {item['node']} | {item['critical_paths']} |")

        if horizon:
            lines += [
                "",
                "### Horizon risk-weighted choke points",
                "",
                "| Node | Defensive leverage | Candidate paths | Transit paths |",
                "|---|---:|---:|---:|",
            ]
            for item in (horizon.get("choke_points", []) or [])[:15]:
                lines.append(
                    f"| {item.get('node_id')} | {item.get('defensive_leverage')} | "
                    f"{item.get('candidate_paths')} | {item.get('transit_paths')} |"
                )

    if audience in {"all", "soc"}:
        lines += [
            "",
            "## Detection coverage",
            "",
            "| Dimension | Coverage |",
            "|---|---:|",
        ]
        for dim, value in coverage.items():
            rendered = "unknown" if value is None else f"{value}%"
            lines.append(f"| {dim} | {rendered} |")

        lines += ["", "### Telemetry / detection / validation gaps", ""]
        for gap in gaps:
            if gap["type"] != "intelligence":
                lines.append(
                    f"- **{gap['id']}** [{gap['type']}]: {gap['description']}"
                )

        if horizon:
            lines += ["", "### Horizon Detection by Absence", ""]
            for gap in (horizon.get("detection_by_absence", []) or [])[:15]:
                missing = [
                    *(gap.get("missing_telemetry", []) or []),
                    *(gap.get("missing_attack_data_components", []) or []),
                ]
                lines.append(
                    f"- **{gap.get('path_id')}** [{gap.get('band')}]: "
                    f"{', '.join(missing) if missing else 'no missing requirement'}"
                )

    if audience == "all":
        lines += ["", "## Inventory", "", "| Entity | Count |", "|---|---:|"]
        for kind, count in sorted(counts.items()):
            lines.append(f"| {kind} | {count} |")

    lines += [
        "",
        "## Interpretation",
        "",
        "This report is a decision aid. Scores and percentages must be reviewed with "
        "architecture, business impact, evidence quality, intelligence freshness, and "
        "validation results. Horizon forecast pressure is not attack probability.",
        "",
    ]
    return "\n".join(lines)


def dashboard_html(entities: dict[str, dict]) -> str:
    counts = _counts(entities)
    scores = scored_scenarios(entities)
    gaps = find_gaps(entities)
    coverage = coverage_summary(entities)
    choke = choke_points(entities)
    decisions = _decisions(entities)
    contexts = _contexts(entities)
    horizon = _horizon(entities)

    band_counts = {
        band: sum(1 for item in scores if item["band"] == band)
        for band in ("P0", "P1", "P2", "P3")
    }
    gap_counts = {}
    for gap in gaps:
        gap_counts[gap["type"]] = gap_counts.get(gap["type"], 0) + 1

    def card(label, value):
        return (
            f'<div class="card"><div class="label">{escape(label)}</div>'
            f'<div class="value">{escape(str(value))}</div></div>'
        )

    scenario_rows = "".join(
        f"<tr><td>{escape(str(s['id']))}</td><td>{s['score']:.2f}</td>"
        f"<td>{s['band']}</td><td>{escape(str(s['confidence']))}</td>"
        f"<td>{escape(str(s['title']))}</td></tr>"
        for s in scores[:15]
    )
    choke_rows = "".join(
        f"<tr><td>{escape(str(item['node']))}</td><td>{item['critical_paths']}</td></tr>"
        for item in choke[:10]
    )
    context_rows = "".join(
        f"<tr><td>{escape(str(x.get('id')))}</td>"
        f"<td>{escape(str(x.get('lens_id', '')))}</td>"
        f"<td>{escape(str(x.get('confidence', 'unknown')))}</td>"
        f"<td>{escape(str(x.get('relevance', '')))}</td></tr>"
        for x in contexts
    )
    decision_rows = "".join(
        f"<tr><td>{escape(str(d.get('id')))}</td>"
        f"<td>{escape(str(d.get('status', 'unknown')))}</td>"
        f"<td>{escape(str(d.get('title', '')))}</td></tr>"
        for d in decisions
    )
    coverage_rows = "".join(
        f"<tr><td>{escape(dim)}</td>"
        f"<td>{'unknown' if value is None else str(value) + '%'}</td></tr>"
        for dim, value in coverage.items()
    )

    horizon_cards = []
    horizon_section = ""
    if horizon:
        summary = horizon.get("summary", {})
        bands = summary.get("bands", {})
        horizon_cards = [
            card("Horizon Paths", summary.get("candidate_paths", 0)),
            card("H0 / H1", bands.get("H0", 0) + bands.get("H1", 0)),
            card("Blind Paths", len(horizon.get("detection_by_absence", []) or [])),
        ]
        path_rows = "".join(
            f"<tr><td>{escape(str(x.get('id')))}</td>"
            f"<td>{escape(str(x.get('forecast', {}).get('proposed_score')))}</td>"
            f"<td>{escape(str(x.get('forecast', {}).get('band')))}</td>"
            f"<td>{escape(' → '.join(x.get('nodes', [])))}</td></tr>"
            for x in (horizon.get("candidate_paths", []) or [])[:15]
        )
        horizon_choke_rows = "".join(
            f"<tr><td>{escape(str(x.get('node_id')))}</td>"
            f"<td>{escape(str(x.get('defensive_leverage')))}</td>"
            f"<td>{escape(str(x.get('candidate_paths')))}</td></tr>"
            for x in (horizon.get("choke_points", []) or [])[:10]
        )
        horizon_section = (
            "<section><h2>Horizon candidate paths</h2><table><thead><tr>"
            "<th>ID</th><th>Score</th><th>Band</th><th>Path</th>"
            f"</tr></thead><tbody>{path_rows}</tbody></table></section>"
            "<section><h2>Horizon choke points</h2><table><thead><tr>"
            "<th>Node</th><th>Defensive leverage</th><th>Paths</th>"
            f"</tr></thead><tbody>{horizon_choke_rows}</tbody></table></section>"
        )

    cards = "".join([
        card("Crown Jewels", counts.get("crown_jewel", 0)),
        card("Threat Contexts", counts.get("threat_context", 0)),
        card("Hypotheses", counts.get("hypothesis", 0)),
        card("Scenarios", counts.get("scenario", 0)),
        card("P0 / P1", band_counts["P0"] + band_counts["P1"]),
        card("Open Gaps", len(gaps)),
        card("Decisions", counts.get("decision", 0)),
        *horizon_cards,
    ])

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TCEM Analyst Dashboard</title>
<style>
body {{ font-family: Inter, system-ui, sans-serif; margin:0; background:#f5f7f8; color:#172024; }}
main {{ max-width:1200px; margin:auto; padding:32px; }}
h1 {{ margin-bottom:4px; }}
.sub {{ color:#617076; margin-top:0; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:24px 0; }}
.card {{ background:white; border:1px solid #dce4e6; border-radius:12px; padding:18px; }}
.label {{ color:#607177; font-size:13px; text-transform:uppercase; }}
.value {{ font-size:32px; font-weight:700; margin-top:6px; }}
section {{ background:white; border:1px solid #dce4e6; border-radius:12px; padding:20px; margin:16px 0; overflow:auto; }}
table {{ width:100%; border-collapse:collapse; }}
th, td {{ padding:10px; border-bottom:1px solid #e8edef; text-align:left; }}
th {{ color:#53656b; font-size:13px; }}
.tag {{ display:inline-block; padding:3px 8px; background:#e8f6f4; border-radius:999px; }}
</style>
</head>
<body>
<main>
<h1>TCEM — Threat Context Engineering Method</h1>
<p class="sub">Analyst attention dashboard generated from the TCEM case model.</p>
<div class="grid">{cards}</div>
{horizon_section}
<section><h2>Threat contexts</h2><table><thead><tr><th>ID</th><th>Lens</th><th>Confidence</th><th>Relevance</th></tr></thead><tbody>{context_rows}</tbody></table></section>
<section><h2>Prioritized scenarios</h2><table><thead><tr><th>ID</th><th>Score</th><th>Band</th><th>Confidence</th><th>Title</th></tr></thead><tbody>{scenario_rows}</tbody></table></section>
<section><h2>Detection coverage</h2><table><thead><tr><th>Dimension</th><th>Coverage</th></tr></thead><tbody>{coverage_rows}</tbody></table></section>
<section><h2>Accepted-scenario defensive choke points</h2><table><thead><tr><th>Architecture node</th><th>P0/P1 paths</th></tr></thead><tbody>{choke_rows}</tbody></table></section>
<section><h2>Open gap types</h2><p>{escape(str(gap_counts))}</p></section>
<section><h2>Decisions</h2><table><thead><tr><th>ID</th><th>Status</th><th>Decision</th></tr></thead><tbody>{decision_rows}</tbody></table></section>
</main>
</body>
</html>"""
