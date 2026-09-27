# Cyber Threat Context Modeling

> **Threat Context Engineering (TCE)**: from business mission and crown jewels to attack paths, telemetry, detections, validation, and continuous threat intelligence.

[![Method](https://img.shields.io/badge/method-TCE-0ea5a4)](#the-method)
[![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![D3FEND](https://img.shields.io/badge/MITRE-D3FEND-1f6f67)](https://d3fend.mitre.org/)
[![Attack Flow](https://img.shields.io/badge/CTID-Attack%20Flow-334155)](https://center-for-threat-informed-defense.github.io/attack-flow/)
[![Docs](https://img.shields.io/badge/docs-MkDocs-4051b5)](./docs/)

## Why this repository exists

Traditional threat modeling is often trapped at design time. Detection engineering is often trapped after telemetry exists. CTI is often trapped in reports.

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

1. **Mission modeling** — what the organization must keep working.
2. **Crown-jewel analysis** — the data, identities, systems, processes, and dependencies whose compromise creates unacceptable impact.
3. **Architecture context** — trust boundaries, identities, control planes, dependencies, exposure, data flows, third parties, cloud/SaaS and operational technology.
4. **Threat context** — relevant actors, campaigns, capabilities, TTPs, targeting patterns, preconditions, and plausible but not-yet-observed attack hypotheses.
5. **Attack-path modeling** — how an adversary could sequence actions to reach an objective.
6. **Defensive architecture** — preventive, detective, disruptive, recovery, and resilience controls.
7. **Telemetry engineering** — what events and context must exist for a threat to be observable.
8. **Detection engineering** — hypotheses, analytics, correlations, chains, and use cases.
9. **Validation** — safe adversary emulation, purple-team testing, control verification, and coverage review in authorized environments.
10. **Continuous intelligence feedback** — new CTI changes the model, which changes telemetry, detections, and priorities.

### TCE operating pipeline

| Stage | Main question | Output |
|---|---|---|
| 0. Mission | What must not fail? | Mission map, critical processes |
| 1. Crown Jewels | What creates unacceptable impact if compromised? | Critical asset register |
| 2. Architecture | Where does risk actually live? | Context map, trust boundaries |
| 3. Threat Context | Who/what is relevant and why? | Threat hypotheses, evidence |
| 4. Attack Paths | How could compromise unfold? | Attack trees / Attack Flows |
| 5. Prioritization | What matters first? | Priority + confidence |
| 6. Defensive Design | What should stop or constrain it? | Control mapping |
| 7. Telemetry | What must be observable? | Telemetry contract |
| 8. Detection | What behavior should trigger analysis? | Detection hypotheses and analytics |
| 9. Chaining | What sequence matters more than a single alert? | Correlation / use case |
| 10. Validation | Did we detect the scenario correctly? | Test evidence, gaps |
| 11. Feedback | What changed? | Updated model and backlog |

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

**v0.1 — method foundation**

The first milestone is to make the method reproducible. The next milestones are machine-readable schemas, coverage matrices, ATT&CK Navigator export, Attack Flow export, and automated report generation.

## Contributing

Contributions that improve rigor, reproducibility, references, examples, and defensive applicability are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

**Threat Context Engineering:** intelligence across the whole defensive pipeline, from the crown jewel to the detection case.
