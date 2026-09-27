from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analysis import choke_points, coverage_summary, decision_trace, find_gaps, scored_scenarios
from .graph import build_graph, to_mermaid
from .io import load_case
from .reporting import dashboard_html, markdown_report
from .validation import validate_entities


def _load(path):
    return load_case(path)


def _fail_parse(errors):
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        raise SystemExit(1)


def cmd_validate(args):
    entities, errors = _load(args.case_dir)
    errors.extend(validate_entities(entities))
    _fail_parse(errors)
    print(f"OK: {len(entities)} entities validated")


def cmd_score(args):
    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    print(json.dumps(scored_scenarios(entities), indent=2))


def cmd_graph(args):
    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    graph = build_graph(entities)
    print(json.dumps(graph, indent=2) if args.format == "json" else to_mermaid(graph))


def cmd_gaps(args):
    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    print(json.dumps(find_gaps(entities), indent=2))


def cmd_coverage(args):
    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    print(json.dumps(coverage_summary(entities), indent=2))


def cmd_chokepoints(args):
    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    print(json.dumps(choke_points(entities), indent=2))


def cmd_trace(args):
    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    rows = decision_trace(entities, args.entity_id)
    for row in rows:
        indent = "  " * row["depth"]
        print(f"{indent}{row['id']} [{row['kind']}] {row['label']}")


def cmd_report(args):
    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    content = markdown_report(entities, audience=args.audience)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        print(str(output))
    else:
        print(content)


def cmd_dashboard(args):
    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    content = dashboard_html(entities)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    print(str(output))


def build_parser():
    parser = argparse.ArgumentParser(prog="tce", description="Threat Context Engineering analyst toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="Validate case structure and references")
    p.add_argument("case_dir")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("score", help="Calculate TCE priority scores")
    p.add_argument("case_dir")
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("graph", help="Generate a case graph")
    p.add_argument("case_dir")
    p.add_argument("--format", choices=["mermaid", "json"], default="mermaid")
    p.set_defaults(func=cmd_graph)

    p = sub.add_parser("gaps", help="List intelligence, telemetry and detection gaps")
    p.add_argument("case_dir")
    p.set_defaults(func=cmd_gaps)

    p = sub.add_parser("coverage", help="Summarize detection coverage")
    p.add_argument("case_dir")
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("chokepoints", help="Find architecture nodes shared by P0/P1 paths")
    p.add_argument("case_dir")
    p.set_defaults(func=cmd_chokepoints)

    p = sub.add_parser("trace", help="Trace evidence and analysis supporting an entity")
    p.add_argument("case_dir")
    p.add_argument("entity_id")
    p.set_defaults(func=cmd_trace)

    p = sub.add_parser("report", help="Generate a Markdown case report")
    p.add_argument("case_dir")
    p.add_argument("--audience", choices=["all", "executive", "cti", "architecture", "soc"], default="all")
    p.add_argument("--output")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("dashboard", help="Generate a self-contained HTML analyst dashboard")
    p.add_argument("case_dir")
    p.add_argument("--output", default="tce-dashboard.html")
    p.set_defaults(func=cmd_dashboard)

    return parser


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
