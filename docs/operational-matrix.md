# TCEM Operational Matrix

The **TCEM Operational Matrix** is the multidimensional visual and operational layer of the Threat Context Engineering Method.

It replaces the idea that a threat model is finished when a diagram is drawn. The matrix keeps context, MITRE behavior, observability, detection, defensive action, validation, Decision Trace and drift visible in one operating view.

## The operating dimensions

| Dimension | Core question | MITRE / operational anchor | Primary output |
|---|---|---|---|
| Mission & Crown Jewels | What must remain trustworthy? | Mission context | Crown-jewel register |
| Threat Landscape & Intelligence | What external conditions materially change our assumptions? | ATT&CK groups/campaigns where relevant, STIX/OpenCTI | Evidence-backed Threat Context |
| Environment & Trust | Where can risk propagate? | Architecture + Environment State | Directed trust/dependency graph |
| Exposure & Attack Paths | How can a plausible sequence reach an objective? | ATT&CK + Attack Flow | Candidate/accepted paths |
| Behavior | What adversary behavior matters here? | MITRE ATT&CK tactics, techniques, sub-techniques | Behavior mapping |
| Observability | What must be visible? What is actually visible? | ATT&CK Detection Strategies, Analytics, Data Components, DeTT&CT-style visibility | Telemetry Contract + Detection by Absence |
| TCEM Detection | What analytic should test the behavior hypothesis? | ATT&CK detection metadata + platform implementations | Detection Specification |
| Defensive Engineering | Where can we prevent, constrain, expose, disrupt or recover? | MITRE D3FEND + enterprise controls | Defensive / preemptive action candidates |
| Validation | Did the control, telemetry and analytic behave as expected? | Safe validation evidence | Validation record |
| Decision & Drift | Why are we acting, and what changed? | Decision Trace + snapshots + CTI drift | Decision, gap, owner, review trigger |

## Visual model

~~~mermaid
flowchart TB
    M["Mission / Crown Jewels"] --> C["Threat Context"]
    L["Threat Landscape / CTI"] --> C
    C --> E["Environment / Trust"]
    E --> P["Exposure & Attack Paths"]
    P --> A["MITRE ATT&CK Behavior"]
    A --> O["Observability"]
    O --> D["TCEM Detection"]
    A --> F["D3FEND / Defensive Engineering"]
    D --> V["Validation"]
    F --> V
    V --> X["Decision Trace"]
    X --> R["Drift / Continuous Operation"]
    R --> C
~~~

## Matrix cell model

Each operationally relevant scenario should be renderable with:

| Field | Meaning |
|---|---|
| Scenario / Path | What sequence is being assessed |
| Crown Jewel | What business-critical outcome is exposed |
| Threat Context | Why the scenario matters here |
| Evidence state | Observed / assessed / inferred / assumed / unknown |
| ATT&CK | Behavior vocabulary |
| Detection Strategy | High-level observability approach |
| Data Components | Evidence concepts required |
| Enterprise telemetry | What is actually available |
| Visibility status | Covered / partial / missing / unknown |
| Detection Specification | Analytic hypothesis and correlation |
| D3FEND / controls | Defensive mechanisms and local implementation |
| Validation | Passed / failed / partial / not tested |
| Decision | What action follows |
| Drift | What changed since last review |
| Owner / review date | Operational accountability |

## Relationship to the former Threat Context Matrix

The original **Threat Context Matrix** is retained as the context-lens layer. It answers *which dimensions of context apply*.

The **TCEM Operational Matrix** is broader. It asks:

> Given this context, behavior, evidence and environment, what can we observe, detect, defend, validate, decide and continuously re-evaluate?

The matrix is not a maturity score, attribution engine, attack-probability calculator or ATT&CK heatmap pretending to be a threat model. Its job is operational traceability.
