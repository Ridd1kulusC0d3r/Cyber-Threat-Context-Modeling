# Cyber Threat Context Modeling

> **Threat Context Engineering (TCE)**: from business mission and crown jewels to attack paths, telemetry, detections, validation, and continuous threat intelligence.

[![Method](https://img.shields.io/badge/method-TCE-0ea5a4)](#the-method)
[![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![D3FEND](https://img.shields.io/badge/MITRE-D3FEND-1f6f67)](https://d3fend.mitre.org/)
[![Attack Flow](https://img.shields.io/badge/CTID-Attack%20Flow-334155)](https://center-for-threat-informed-defense.github.io/attack-flow/)
[![Docs](https://img.shields.io/badge/docs-MkDocs-4051b5)](./docs/)

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

- **Intelligence Requirement** — the question tied to a decision.
- **Evidence** — observed, assessed, inferred, assumed, or unknown information with provenance.
- **Threat Hypothesis** — a falsifiable proposition with supporting and contradicting evidence.
- **Attack Path** — a behavior sequence tied to architecture nodes and trust boundaries.
- **Telemetry Contract** — what must be observable, including fields and integrity requirements.
- **Detection Use Case** — behavior, correlation, triage, response, and coverage by dimension.
- **Validation** — evidence that a control or detection behaves as expected.
- **Intelligence Gap** — an unknown turned into managed collection work.
- **Decision** — the defensive action connected back to the analytical chain.

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

**v0.2 — analyst workflow + executable model**

The method is now executable as structured case data. v0.2 includes Intelligence Requirements, evidence lineage, threat hypotheses, graph-oriented attack paths, defensive choke points, telemetry contracts, multi-dimensional coverage, validation, intelligence gaps, Decision Trace, audience-specific reporting, and a static analyst dashboard. The next layer is standards interoperability and richer automation.

## Contributing

Contributions that improve rigor, reproducibility, references, examples, and defensive applicability are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

**Threat Context Engineering:** intelligence across the whole defensive pipeline, from the crown jewel to the detection case.
