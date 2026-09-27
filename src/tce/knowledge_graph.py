from __future__ import annotations

import json
import re
from pathlib import Path

import networkx as nx
from rdflib import Graph, Literal, Namespace, RDF, URIRef

from .graph import build_graph


def build_operational_graph(entities: dict[str, dict], attack_index=None, d3fend_index=None) -> nx.MultiDiGraph:
    raw = build_graph(entities)
    graph = nx.MultiDiGraph()

    for node in raw["nodes"]:
        graph.add_node(
            node["id"],
            kind=node.get("kind", "entity"),
            label=str(node.get("label", node["id"])),
        )
    for edge in raw["edges"]:
        graph.add_edge(
            edge["from"],
            edge["to"],
            relation=edge.get("relation", "related"),
        )

    for wrapped in entities.values():
        if wrapped["kind"] != "scenario":
            continue
        scenario = wrapped["data"]
        sid = scenario["id"]
        for step in ((scenario.get("attack_path") or {}).get("steps") or []):
            for technique_id in step.get("attack_techniques", []) or []:
                attack_node = f"ATTACK::{technique_id}"
                obj = attack_index.get(technique_id) if attack_index else None
                graph.add_node(
                    attack_node,
                    kind="attack_technique",
                    label=(obj or {}).get("name", technique_id),
                    external_id=technique_id,
                )
                graph.add_edge(sid, attack_node, relation="uses_behavior")

                if d3fend_index:
                    for mapping in d3fend_index.lookup_attack(technique_id, limit=20):
                        values = [
                            str(cell.get("value", ""))
                            for cell in mapping.values()
                            if isinstance(cell, dict)
                        ]
                        candidates = [
                            value for value in values
                            if "d3fend" in value.lower() or "d3f:" in value.lower()
                        ]
                        for value in candidates[:4]:
                            defense_node = "D3FEND::" + value
                            label = re.split(r"[/#]", value)[-1] or value
                            graph.add_node(
                                defense_node,
                                kind="d3fend_mapping",
                                label=label,
                            )
                            graph.add_edge(
                                attack_node,
                                defense_node,
                                relation="defensive_mapping",
                            )
    return graph


def graph_summary(graph: nx.MultiDiGraph) -> dict:
    kinds = {}
    for _, attrs in graph.nodes(data=True):
        kind = attrs.get("kind", "unknown")
        kinds[kind] = kinds.get(kind, 0) + 1
    return {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "node_kinds": kinds,
    }


def write_graph(graph: nx.MultiDiGraph, output: str | Path, fmt: str = "json"):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        data = nx.node_link_data(graph, edges="edges")
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    elif fmt == "graphml":
        safe = nx.MultiDiGraph()
        for node, attrs in graph.nodes(data=True):
            safe.add_node(node, **{key: str(value) for key, value in attrs.items()})
        for source, target, key, attrs in graph.edges(keys=True, data=True):
            safe.add_edge(
                source,
                target,
                key=key,
                **{name: str(value) for name, value in attrs.items()},
            )
        nx.write_graphml(safe, path)
    elif fmt == "ttl":
        namespace = Namespace("https://tce.local/id/")
        predicate = Namespace("https://tce.local/relation/")
        rdf = Graph()
        for node, attrs in graph.nodes(data=True):
            subject = URIRef(namespace + str(node))
            rdf.add((subject, RDF.type, URIRef(namespace + str(attrs.get("kind", "entity")))))
            rdf.add((subject, URIRef(predicate + "label"), Literal(str(attrs.get("label", node)))))
        for source, target, attrs in graph.edges(data=True):
            relation = re.sub(r"[^A-Za-z0-9_-]", "_", str(attrs.get("relation", "related")))
            rdf.add((
                URIRef(namespace + str(source)),
                URIRef(predicate + relation),
                URIRef(namespace + str(target)),
            ))
        rdf.serialize(destination=str(path), format="turtle")
    else:
        raise ValueError(f"Unsupported graph format: {fmt}")
    return path
