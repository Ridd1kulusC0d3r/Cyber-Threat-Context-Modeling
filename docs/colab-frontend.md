# Colab Web Workbench

The TCE frontend is deliberately small and runs on the same Google Colab VM as the analyst toolkit.

## Start locally

    pip install -e .[web]
    tce ui examples/cases/enterprise-identity --host 0.0.0.0 --port 3000

The Colab notebook performs this automatically and asks Colab for the proxied URL for port 3000.

## Sections

The current UI contains:

- **Visão geral** — crown jewels, hypotheses, scenarios, P0/P1 counts, gaps, detections, coverage, choke points and decisions.
- **Engenharia** — Telemetry Health, Detection Backlog and deterministic Validation Harness.
- **Cenários** — priority band, weighted score, confidence and open gaps.
- **Inteligência** — threat hypotheses with analytical state and confidence.
- **ATT&CK** — Detection Strategy, Analytic, Data Component and D3FEND lookup, plus standards synchronization.
- **IA** — Evidence Packet analysis using GLiNER and Qwen.
- **Grafo** — nodes and relationships from the TCE Case.
- **Exports** — STIX 2.1, ATT&CK Navigator and Attack Flow.

## Architecture

~~~mermaid
flowchart LR
    B[Browser / Colab Proxy :3000] --> F[FastAPI frontend]
    F --> C[TCE Case YAML/JSON]
    F --> A[ATT&CK / D3FEND cache]
    F --> AI[GLiNER + Qwen]
    F --> G[TCE Graph]
    F --> E[STIX / Navigator / Attack Flow]
~~~

The browser does not maintain a separate database. FastAPI calls the existing TCE modules and case files directly.

## Security boundary

- OpenCTI publication remains explicit and is not exposed as an automatic frontend action.
- AI results remain candidate material.
- The UI never silently mutates source evidence.
- ATT&CK/D3FEND synchronization is explicit from the UI.
- The Colab proxy URL is runtime-specific and should be treated as an analyst workspace, not a production deployment.

For a persistent multi-user deployment, place the API behind normal authentication, authorization and a proper application server rather than treating a notebook VM like a data center.