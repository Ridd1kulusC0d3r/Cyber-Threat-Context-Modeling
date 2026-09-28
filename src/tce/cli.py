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


def _case_technique_ids(entities):
    ids = []
    for wrapped in entities.values():
        if wrapped["kind"] != "scenario":
            continue
        for step in ((wrapped["data"].get("attack_path") or {}).get("steps") or []):
            ids.extend(step.get("attack_techniques", []) or [])
    return sorted(set(ids))


def _entity_rows(entities):
    rows = []
    for entity_id, wrapped in entities.items():
        data = wrapped["data"]
        rows.append({
            "id": entity_id,
            "name": data.get("name") or data.get("title") or data.get("question") or entity_id,
            "aliases": data.get("aliases", []) or [],
            "kind": wrapped["kind"],
        })
    return rows


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


def cmd_standards_sync(args):
    from .standards.attack import sync_attack
    from .standards.d3fend import sync_d3fend

    output = {}
    if not args.d3fend_only:
        output["attack"] = str(sync_attack())
    if not args.attack_only:
        output["d3fend"] = str(sync_d3fend())
    print(json.dumps(output, indent=2))


def cmd_attack_validate(args):
    from .standards.attack import AttackIndex

    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    index = AttackIndex.load()
    result = index.validate_ids(_case_technique_ids(entities))
    print(json.dumps(result, indent=2))
    if result["invalid"]:
        raise SystemExit(2)


def cmd_attack_search(args):
    from .standards.attack import AttackIndex

    index = AttackIndex.load()
    print(json.dumps(index.search(args.query, limit=args.limit), indent=2))


def cmd_attack_detect(args):
    from .standards.attack import AttackIndex

    index = AttackIndex.load()
    print(json.dumps(index.detection_profile(args.technique_id), indent=2))


def cmd_d3fend(args):
    from .standards.d3fend import D3FENDIndex

    index = D3FENDIndex.load()
    print(json.dumps(index.lookup_attack(args.technique_id, limit=args.limit), indent=2))


def cmd_kg(args):
    from .knowledge_graph import build_operational_graph, graph_summary, write_graph
    from .standards.attack import AttackIndex
    from .standards.d3fend import D3FENDIndex

    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    attack = AttackIndex.load(sync_if_missing=not args.offline)
    d3fend = None if args.no_d3fend else D3FENDIndex.load(sync_if_missing=not args.offline)
    graph = build_operational_graph(entities, attack_index=attack, d3fend_index=d3fend)
    write_graph(graph, args.output, fmt=args.format)
    print(json.dumps(graph_summary(graph), indent=2))


def cmd_export_attack_flow(args):
    from .standards.attack import AttackIndex
    from .standards.attack_flow import scenario_to_attack_flow, write_attack_flow

    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    wrapped = entities.get(args.scenario_id)
    if not wrapped or wrapped["kind"] != "scenario":
        raise SystemExit(f"Unknown scenario: {args.scenario_id}")
    attack = AttackIndex.load()
    bundle = scenario_to_attack_flow(wrapped["data"], attack_index=attack)
    print(write_attack_flow(bundle, args.output))


def cmd_import_attack_flow(args):
    from .standards.attack import AttackIndex
    from .standards.attack_flow import attack_flow_to_scenario, write_imported_scenario

    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    attack = AttackIndex.load(sync_if_missing=not args.offline)
    draft = attack_flow_to_scenario(bundle, attack_index=attack)
    print(write_imported_scenario(draft, args.output))


def cmd_export_stix(args):
    from .standards.stix_export import export_case_stix, write_stix

    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    print(write_stix(export_case_stix(entities), args.output))


def cmd_export_navigator(args):
    from .standards.navigator import export_navigator_layer, write_navigator

    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    print(write_navigator(export_navigator_layer(entities, name=args.name), args.output))


def cmd_opencti_push(args):
    from .standards.opencti import bundle_summary, push_bundle

    summary = bundle_summary(args.bundle)
    if not args.commit:
        summary["mode"] = "dry-run"
        summary["message"] = "No data was sent. Add --commit to import the bundle."
        print(json.dumps(summary, indent=2))
        return
    result = push_bundle(args.bundle, url=args.url, update=args.update)
    print(json.dumps({"mode": "commit", "result": str(result)}, indent=2))


def cmd_opencti_pull(args):
    from .standards.opencti import pull_snapshot, write_snapshot

    types = [value.strip() for value in args.types.split(",") if value.strip()]
    snapshot = pull_snapshot(
        types=types,
        limit=args.limit,
        search=args.search,
        include_relationships=not args.no_relationships,
        url=args.url,
    )
    print(write_snapshot(snapshot, args.output))


def cmd_opencti_to_tce(args):
    from .standards.opencti import snapshot_to_evidence, write_evidence_candidates

    snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    candidates = snapshot_to_evidence(snapshot)
    print(write_evidence_candidates(candidates, args.output))


def cmd_opencti_resolve(args):
    from .entity_resolution import resolve_entities

    snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    entities, errors = _load(args.case_dir)
    _fail_parse(errors)
    decisions = resolve_entities(
        snapshot.get("entities", []) or [],
        _entity_rows(entities),
        threshold=args.threshold,
    )
    rendered = json.dumps(decisions, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(args.output)
    else:
        print(rendered)


def cmd_taxii_pull(args):
    from .standards.taxii import pull_collection

    bundle = pull_collection(
        args.collection_url,
        output=args.output,
        added_after=args.added_after,
        limit=args.limit,
        max_pages=args.max_pages,
    )
    print(json.dumps({
        "output": args.output,
        "objects": len(bundle.get("objects", [])),
        "pages": bundle.get("x_tce_pages"),
    }, indent=2))


def cmd_ui(args):
    import os

    try:
        import uvicorn
    except ImportError as exc:
        raise SystemExit("Install the web extra: pip install -e '.[web]'") from exc

    os.environ["TCE_CASE_DIR"] = str(Path(args.case_dir).resolve())
    uvicorn.run("tce.webapp:app", host=args.host, port=args.port, reload=False)


def cmd_ai(args):
    from .ai.copilot import TCECopilot

    text = Path(args.input).read_text(encoding="utf-8")
    result = TCECopilot().analyze_text(
        text,
        source_id=args.source_id,
        case_id=args.case_id or "",
    )
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(args.output)
    else:
        print(rendered)


def build_parser():
    parser = argparse.ArgumentParser(prog="tce", description="Threat Context Engineering analyst toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="Validate case structure and references")
    p.add_argument("case_dir")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("score", help="Calculate TCE priority scores")
    p.add_argument("case_dir")
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("graph", help="Generate the native TCE case graph")
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

    p = sub.add_parser("standards-sync", help="Cache current ATT&CK STIX and D3FEND mappings")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--attack-only", action="store_true")
    mode.add_argument("--d3fend-only", action="store_true")
    p.set_defaults(func=cmd_standards_sync)

    p = sub.add_parser("attack-validate", help="Validate case technique IDs against ATT&CK")
    p.add_argument("case_dir")
    p.set_defaults(func=cmd_attack_validate)

    p = sub.add_parser("attack-search", help="Search ATT&CK techniques")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=10)
    p.set_defaults(func=cmd_attack_search)

    p = sub.add_parser("attack-detect", help="Show ATT&CK Detection Strategies, Analytics and Data Components")
    p.add_argument("technique_id")
    p.set_defaults(func=cmd_attack_detect)

    p = sub.add_parser("d3fend", help="Show D3FEND mappings for an ATT&CK technique")
    p.add_argument("technique_id")
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(func=cmd_d3fend)

    p = sub.add_parser("kg", help="Build the TCE + ATT&CK + D3FEND operational knowledge graph")
    p.add_argument("case_dir")
    p.add_argument("--format", choices=["json", "graphml", "ttl"], default="json")
    p.add_argument("--output", default="tce-knowledge-graph.json")
    p.add_argument("--offline", action="store_true")
    p.add_argument("--no-d3fend", action="store_true")
    p.set_defaults(func=cmd_kg)

    p = sub.add_parser("export-attack-flow", help="Export a scenario as Attack Flow STIX 2.1")
    p.add_argument("case_dir")
    p.add_argument("scenario_id")
    p.add_argument("--output", default="attack-flow.json")
    p.set_defaults(func=cmd_export_attack_flow)

    p = sub.add_parser("import-attack-flow", help="Convert Attack Flow into a review-only TCE scenario draft")
    p.add_argument("bundle")
    p.add_argument("--output", default="imported-scenario.yaml")
    p.add_argument("--offline", action="store_true")
    p.set_defaults(func=cmd_import_attack_flow)

    p = sub.add_parser("export-stix", help="Export the TCE graph as a STIX 2.1 bundle")
    p.add_argument("case_dir")
    p.add_argument("--output", default="tce-case.stix.json")
    p.set_defaults(func=cmd_export_stix)

    p = sub.add_parser("export-navigator", help="Export ATT&CK techniques as a Navigator layer")
    p.add_argument("case_dir")
    p.add_argument("--name", default="TCE ATT&CK Layer")
    p.add_argument("--output", default="tce-navigator.json")
    p.set_defaults(func=cmd_export_navigator)

    p = sub.add_parser("opencti-push", help="Dry-run or import a STIX bundle into OpenCTI")
    p.add_argument("bundle")
    p.add_argument("--url")
    p.add_argument("--update", action="store_true")
    p.add_argument("--commit", action="store_true", help="Actually send data; default is dry-run")
    p.set_defaults(func=cmd_opencti_push)

    p = sub.add_parser("opencti-pull", help="Read selected CTI entities into a local review snapshot")
    p.add_argument("--types", default="intrusion-set,campaign,malware,report,threat-actor-group,vulnerability")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--search")
    p.add_argument("--url")
    p.add_argument("--no-relationships", action="store_true")
    p.add_argument("--output", default="opencti-snapshot.json")
    p.set_defaults(func=cmd_opencti_pull)

    p = sub.add_parser("opencti-to-tce", help="Convert an OpenCTI snapshot into review-only TCE evidence candidates")
    p.add_argument("snapshot")
    p.add_argument("--output", default="opencti-evidence-candidates.yaml")
    p.set_defaults(func=cmd_opencti_to_tce)

    p = sub.add_parser("opencti-resolve", help="Resolve OpenCTI snapshot entities against an existing TCE case")
    p.add_argument("snapshot")
    p.add_argument("case_dir")
    p.add_argument("--threshold", type=float, default=0.90)
    p.add_argument("--output")
    p.set_defaults(func=cmd_opencti_resolve)

    p = sub.add_parser("taxii-pull", help="Read a TAXII 2.1 collection into a local STIX bundle")
    p.add_argument("collection_url")
    p.add_argument("--output", default="taxii-bundle.json")
    p.add_argument("--added-after")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--max-pages", type=int, default=20)
    p.set_defaults(func=cmd_taxii_pull)

    p = sub.add_parser("ui", help="Run the local TCE web workbench")
    p.add_argument("case_dir", nargs="?", default="examples/cases/enterprise-identity")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=3000)
    p.set_defaults(func=cmd_ui)

    p = sub.add_parser("ai", help="Run GLiNER + Qwen over a text Evidence Packet")
    p.add_argument("input")
    p.add_argument("--source-id", default="SOURCE-001")
    p.add_argument("--case-id")
    p.add_argument("--output")
    p.set_defaults(func=cmd_ai)

    return parser


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
