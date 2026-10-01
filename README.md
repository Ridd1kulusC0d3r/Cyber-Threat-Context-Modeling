# Cyber Threat Context Modeling

> **Threat Context Engineering (TCE)**: from business mission and crown jewels to attack paths, telemetry, detections, validation, and continuous threat intelligence.

[![Method](https://img.shields.io/badge/method-TCE-0ea5a4)](#the-method)
[![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![D3FEND](https://img.shields.io/badge/MITRE-D3FEND-1f6f67)](https://d3fend.mitre.org/)
[![Attack Flow](https://img.shields.io/badge/CTID-Attack%20Flow-334155)](https://center-for-threat-informed-defense.github.io/attack-flow/)
[![Docs](https://img.shields.io/badge/docs-MkDocs-4051b5)](./docs/)
[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Ridd1kulusC0d3r/Cyber-Threat-Context-Modeling/blob/main/colab/TCE_v0_3_AI_Knowledge_Graph.ipynb)

## Why this repository exists

Traditional threat modeling is often trapped at design time. Detection engineering is often trapped after telemetry exists. CTI is often trapped in reports. TCE turns those disconnected activities into one traceable decision system.

This project connects all three.

**Core idea:**

> Model the threat before the first log, decide what must be observable, then engineer detections around attack sequences instead of isolated events.

This is the repository's **Zero-Point Detection** principle.

~~~mermaid
flowchart LR
    A[Mission & Crown Jewels] --> B[Architecture & Trust Boundaries]
    B --> C[Threat Context]
    C --> D[Attack Paths / Attack Flow]
    D --> E[Telemetry Contract]
    E --> F[Detection Hypotheses]
    F --> G[Analytics & Correlation]
    G --> H[Use Cases / Cases]
    H --> I[Validation]
    I --> J[CTI Feedback]
    J --> C
~~~

## The method

The proposed method is called **Threat Context Engineering (TCE)**.

TCE is broader than application threat modeling. It combines:

1. **Mission and decision context** — what must be protected and what decision the analysis must support.
2. **Intelligence Requirements** — the questions that must be answered to support that decision.
3. **Crown-jewel analysis** — the data, identities, systems, processes, and dependencies whose compromise creates unacceptable impact.
4. **Architecture context** — trust boundaries, identities, control planes, dependencies, exposure, data flows, third parties, cloud/SaaS and operational technology.
5. **Evidence and threat hypotheses** — explicit provenance, supporting and contradicting evidence, assumptions, unknowns, and confidence.
6. **Attack-path modeling** — how an adversary could sequence behaviors across the architecture to reach an objective.
7. **Prioritization and choke points** — which scenarios deserve attention and where defensive investment changes several paths at once.
8. **Defensive architecture** — preventive, constraining, detective, disruptive, recovery, and resilience controls.
9. **Telemetry engineering** — what events, fields, entities, context, integrity, and latency must exist for a threat to be observable.
10. **Detection engineering** — hypotheses, analytics, correlations, chains, triage, and response.
11. **Validation and coverage** — evidence that telemetry, detections, controls, and response behave as expected.
12. **Decision Trace and continuous feedback** — every defensive decision remains traceable to requirements, evidence, hypotheses, scenarios, gaps, and validation.

### TCE operating pipeline

| Stage | Main question | Output |
|---|---|---|
| 0. Mission & Decision | What must not fail and what decision is needed? | Mission + decision context |
| 1. Intelligence Requirements | What must we know? | Prioritized IRs |
| 2. Crown Jewels | What creates unacceptable impact if compromised? | Critical asset register |
| 3. Architecture | Where does risk actually live? | Nodes, relationships, trust boundaries |
| 4. Evidence | What do we actually know and from where? | Evidence lineage |
| 5. Hypotheses | What plausible proposition should be tested? | Threat hypotheses + confidence |
| 6. Attack Paths | How could compromise unfold? | Graph / Attack Flow candidates |
| 7. Prioritization | What matters first? | Priority separate from confidence |
| 8. Choke Points | Where do critical paths converge? | Defensive leverage points |
| 9. Defensive Design | What should stop, constrain, expose, or recover? | Control mapping |
| 10. Telemetry | What must be observable? | Telemetry contracts |
| 11. Detection | What behavior and sequence should trigger action? | Detection use cases |
| 12. Validation | Did the control and detection actually work? | Validation evidence |
| 13. Gaps & Decision Trace | What remains unknown and why are we acting? | Backlog + auditable decision chain |

## What makes this different

TCE intentionally joins areas that are usually treated as separate disciplines:

- **Threat Modeling Manifesto** for the four core questions and iterative mindset.
- **MITRE ATT&CK** for adversary behavior vocabulary.
- **CTID Threat Modeling with ATT&CK** for theory + evidence and critical-asset-driven analysis.
- **Attack Flow** for sequencing adversary behavior.
- **MITRE D3FEND** for engineering-oriented defensive countermeasure vocabulary.
- **NIST CSF / SP 800-53** for controls, governance, and risk treatment.
- **STRIDE, PASTA, Attack Trees, DFDs** when they are useful.
- **Detection engineering** as a first-class design output, not an afterthought.
- **CTI** as continuous evidence, not decoration at the end of a risk document.

TCE is **framework-compatible, not framework-dependent**.

## Zero-Point Detection

The detection pipeline starts **before telemetry exists**.

~~~mermaid
flowchart LR
    TM[Threat model] --> LOG[Required telemetry]
    LOG --> CHAIN[Behavior chain]
    CHAIN --> CASE[Detection use case]
    CASE --> TEST[Validation]
~~~

Instead of asking only:

> "What logs do we already have?"

TCE asks:

> "What must we be able to observe if this attack path happens?"

That changes telemetry from a passive data source into an explicit security requirement.

## Prioritization

TCE separates **priority** from **confidence**.

A scenario can be high priority even when evidence is incomplete, and strong evidence does not automatically mean high business impact.

The default model scores each dimension from 0–5:

- Crown-jewel criticality
- Threat relevance
- Attack-path feasibility
- Exposure
- Control weakness
- Detection gap

See [Prioritization Model](docs/prioritization.md).

## Repository structure

    .
    ├── README.md
    ├── docs/
    │   ├── index.md
    │   ├── methodology.md
    │   ├── prioritization.md
    │   └── detection-engineering.md
    ├── awesome/
    │   └── README.md
    ├── templates/
    │   ├── crown-jewels.yaml
    │   ├── threat-scenario.yaml
    │   └── detection-use-case.yaml
    ├── examples/
    │   └── enterprise-ransomware-path.md
    ├── .github/
    │   └── workflows/
    │       └── docs.yml
    ├── mkdocs.yml
    ├── requirements-docs.txt
    ├── CONTRIBUTING.md
    └── SECURITY.md

## Quick start

1. Copy the templates from [templates/](templates/).
2. Define mission and crown jewels.
3. Map architecture, trust boundaries, identities and dependencies.
4. Build threat hypotheses using both **theory** and **evidence**.
5. Convert hypotheses into ATT&CK-linked attack paths.
6. Prioritize scenarios.
7. Define controls and required telemetry.
8. Write detection hypotheses and correlations.
9. Validate safely in an authorized environment.
10. Feed results back into CTI and architecture decisions.


## Analyst toolkit

Install the repository in editable mode and operate directly on a TCE Case:

~~~bash
pip install -e .

tce validate examples/cases/enterprise-identity
tce score examples/cases/enterprise-identity
tce graph examples/cases/enterprise-identity
tce gaps examples/cases/enterprise-identity
tce coverage examples/cases/enterprise-identity
tce chokepoints examples/cases/enterprise-identity
tce trace examples/cases/enterprise-identity DEC-001
tce report examples/cases/enterprise-identity --audience executive --output executive.md
tce dashboard examples/cases/enterprise-identity --output dashboard.html
~~~

The CLI currently provides semantic validation, priority scoring, graph export, intelligence and telemetry gap discovery, multi-dimensional detection coverage, defensive choke-point analysis, Decision Trace, audience-specific Markdown reports, and a self-contained analyst dashboard.

## First-class analytical objects

- **Threat Context** — the lens that connects mission, crown jewels, architecture, external CTI, behavior, exposure, defensive requirements and time.
- **Intelligence Requirement** — the question tied to a decision.
- **Evidence** — observed, assessed, inferred, assumed, or unknown information with provenance.
- **Threat Hypothesis** — a falsifiable proposition with supporting and contradicting evidence.
- **Attack Path** — a behavior sequence tied to architecture nodes and trust boundaries.
- **Telemetry Contract** — what must be observable, including fields and integrity requirements.
- **Detection Use Case** — behavior, correlation, triage, response, and coverage by dimension.
- **Validation** — evidence that a control or detection behaves as expected.
- **Intelligence Gap** — an unknown turned into managed collection work.
- **Decision** — the defensive action connected back to the analytical chain.


## TCE v0.3 — AI + operational knowledge graph

v0.3 adds a Colab-ready intelligence workbench:

- **GLiNER ON by default** for zero-shot entity extraction.
- **Qwen ON by default** for evidence-grounded analytical suggestions.
- immutable Evidence Packets so AI cannot silently rewrite source evidence;
- deterministic ATT&CK STIX validation and technique search;
- D3FEND inferred defensive mappings;
- Attack Flow STIX 2.1 export;
- ATT&CK Navigator layer export;
- TCE STIX 2.1 export and an explicit-review OpenCTI bridge;
- operational knowledge graph export to JSON, GraphML and RDF/Turtle.

~~~bash
tce standards-sync
tce attack-validate examples/cases/enterprise-identity
tce kg examples/cases/enterprise-identity --format ttl --output tce-kg.ttl
tce export-attack-flow examples/cases/enterprise-identity TS-001 --output flow.json
tce export-stix examples/cases/enterprise-identity --output case.stix.json
~~~

OpenCTI is dry-run by default. AI outputs are review candidates by default.


## TCE v0.3.1 — intelligence synchronization

The remaining v0.3 interoperability layer is now operational:

- ATT&CK **Detection Strategies**, **Analytics**, **Data Components**, log sources and mutable elements;
- Attack Flow **import and export**;
- OpenCTI → local snapshot → entity resolution → TCE evidence-candidate workflow;
- reviewed TCE → STIX → OpenCTI publication path;
- read-only TAXII 2.1 collection ingestion;
- deterministic entity resolution before CTI is linked into the case.

~~~bash
tce attack-detect T1078

tce import-attack-flow flow.json --output imported-scenario.yaml

tce opencti-pull --output opencti-snapshot.json
tce opencti-resolve opencti-snapshot.json examples/cases/enterprise-identity
tce opencti-to-tce opencti-snapshot.json --output opencti-evidence-candidates.yaml

tce taxii-pull https://example/taxii/root/collections/COLLECTION-ID \
  --output taxii-bundle.json
~~~

All inbound intelligence remains **candidate material until analyst review**. External CTI is not silently promoted into organizational fact, and AI still cannot rewrite evidence.



## TCE v0.3.2 — Threat Context Matrix

TCE now treats **Threat Context** as a first-class analytical object instead of assuming that every threat model is primarily an application or architecture model.

The new matrix spans:

- mission and business context;
- architecture and trust;
- adversary and campaign relevance;
- behavior and attack-path context;
- exposure and dependency context;
- defensive and telemetry context;
- evidence and confidence;
- resilience and recovery;
- temporal validity.

The built-in catalog contains more than twenty lenses, including Identity, Cloud, AI/GenAI, Web/API, Software Supply Chain, Detection & Validation, ICS/OT, IoT/Embedded, Endpoint, Network, Data, Collaboration, Third-Party/SaaS, Kubernetes, Developer/CI/CD, Cryptography, Recovery, Human/Process, Mobile, Telecommunications and the Security Control Plane.

Eight of those lenses map directly to **RedFrameworks v6 domain packs**. RedFrameworks remains the external catalog; TCE uses it as a review-gated context provider.

~~~bash
tce context-catalog
tce context-assess examples/cases/enterprise-identity
tce redframeworks-sync
tce context-enrich examples/cases/enterprise-identity --output context-intelligence.json
~~~

External actor, campaign, detection and validation metadata remains **candidate context** until local evidence establishes relevance.

## Colab web workbench

TCE now includes a lightweight dark frontend designed to run **inside the same Colab VM** on port `3000`.

~~~bash
pip install -e .[web]
tce ui examples/cases/enterprise-identity --port 3000
~~~

The Colab notebook starts it automatically and prints a proxied `*.prod.colab.dev` link.

The UI provides:

- case health and summary metrics;
- prioritized P0–P3 scenarios;
- detection coverage and defensive choke points;
- hypotheses, gaps and decisions;
- ATT&CK Detection Strategy / Analytic / Data Component lookup;
- D3FEND enrichment;
- GLiNER + Qwen Evidence Packet analysis;
- TCE graph inspection;
- STIX, ATT&CK Navigator and Attack Flow downloads.

The frontend is intentionally thin: it reads the same case files and calls the same TCE Python modules rather than maintaining a second security-data model.

## Awesome knowledge base

The repository has a curated [Awesome Threat Context Engineering](awesome/README.md) section covering:

- Frameworks and methodologies
- ATT&CK / D3FEND / Attack Flow resources
- Threat Modeling as Code
- Tools
- Cloud / Kubernetes / identity / OT
- Detection engineering
- Purple-team validation
- Books, courses, talks, and research

## Design principles

- **Business impact before technique count**
- **Sequences before isolated alerts**
- **Evidence and theory together**
- **Priority and confidence are different things**
- **Telemetry is a security requirement**
- **Detection is designed, not merely written**
- **Every model has an owner and review date**
- **Unknowns are recorded explicitly**
- **CTI must change decisions or it is just reading**
- **The model must produce operational outputs**

## Intended audience

- Cyber Threat Intelligence
- Detection Engineering
- SOC Engineering
- Threat Hunting
- Security Architecture
- Purple Team
- Incident Response
- Cloud Security
- Product / Application Security
- Risk and Resilience teams

## Defensive-use boundary

The project is intended for defensive architecture, threat-informed detection, and authorized security validation. Scenario operationalization should be performed only in systems you own or are explicitly authorized to test.

## Status

**v0.3.2 — Threat Context Matrix + RedFrameworks v6 context integration**

The method now adds an explicit Threat Context layer across mission, architecture, trust, adversary/campaign intelligence, behavior, exposure, telemetry, evidence, resilience and time. RedFrameworks v6 can enrich selected contexts with review-only domain-pack intelligence while organization-specific relevance still requires TCE evidence. The existing ATT&CK, D3FEND, Attack Flow, OpenCTI, TAXII, knowledge-graph, GLiNER and Qwen capabilities remain intact.

## Contributing

Contributions that improve rigor, reproducibility, references, examples, and defensive applicability are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

**Threat Context Engineering:** intelligence across the whole defensive pipeline, from the crown jewel to the detection case.
