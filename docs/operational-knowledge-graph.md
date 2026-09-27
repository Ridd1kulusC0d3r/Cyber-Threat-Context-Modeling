# Operational Knowledge Graph

TCE v0.3 builds a typed multi-edge graph from the case plus ATT&CK and D3FEND.

Node families include TCE analytical objects, architecture nodes, crown jewels, ATT&CK techniques, D3FEND mappings, telemetry, detections, validation and intelligence gaps.

Example edges include supports, contradicts, targets, uses_behavior, defensive_mapping, telemetry_requirements, validation_ids, administers, controls and depends_on.

## Build

    tce standards-sync
    tce kg examples/cases/enterprise-identity --format json --output tce-kg.json

Other formats:

    tce kg examples/cases/enterprise-identity --format graphml --output tce-kg.graphml
    tce kg examples/cases/enterprise-identity --format ttl --output tce-kg.ttl

JSON supports application development, GraphML supports graph tooling, and Turtle supports RDF and semantic-graph workflows.

ATT&CK and D3FEND enrich the graph. They never replace mission, evidence, architecture or decision provenance.
