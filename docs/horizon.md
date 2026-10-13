# TCE Horizon

**TCE Horizon** is the predictive and preemptive enterprise layer of Threat Context Engineering.

Traditional threat modeling often starts with one application. Horizon starts with the **enterprise environment state**: assets, identities, trust relationships, exposure, crown jewels, controls, telemetry, vulnerability pressure, and accepted intelligence signals.

The goal is not to claim that TCE can predict the next attacker with certainty. The useful goal is to continuously identify which modeled paths toward crown jewels are becoming more defensively urgent, explain why, find where they converge, expose visibility gaps, and propose review-gated actions before an incident forces the decision.

## Operating model

~~~mermaid
flowchart LR
    A[Enterprise Environment State] --> B[Exposure + Trust Graph]
    I[Accepted CTI / OSINT signals] --> C[Forecast Pressure]
    V[Vulnerability / KEV / EPSS signals] --> C
    B --> D[Candidate Exposure Paths]
    C --> D
    D --> E[Risk-weighted Choke Points]
    D --> F[Detection by Absence]
    D --> G[Preemptive Action Candidates]
    E --> G
    F --> G
    G --> H[Analyst Review]
    H --> J[TCE Scenario / Telemetry / Detection / Decision]
    J --> K[Validation + Drift]
    K --> A
~~~

Horizon never promotes a generated path into an organizational fact automatically.

## What Horizon models

The ENV Environment State can represent infrastructure, cloud, IdP/IAM, SaaS, privileged and machine identities, AI agents and connector authority, endpoints, network paths, security tooling, recovery systems, OT/ICS, controls, telemetry sources, vulnerability pressure, and time-bounded intelligence signals.

This is deliberately broader than an application DFD.

## Candidate paths, not exploit recipes

Horizon traverses the directed enterprise trust/dependency graph from modeled exposure points toward nodes linked to crown jewels. A result contains the nodes and relationships involved, ATT&CK behavior hints where explicitly mapped or safely inferred at a high level, telemetry requirements, controls, accepted intelligence contributions, vulnerability signals, and a proposed score.

It does not contain command-level exploitation procedures.

Search is bounded by max hops and result limits. Horizon is an analytical prioritizer, not a claim that every possible adversary path has been enumerated.

## Forecast pressure

Horizon calls its score **forecast pressure**, not attack probability.

| Dimension | Weight |
|---|---:|
| Crown-jewel impact | 25% |
| Entry exposure | 15% |
| Relationship pressure | 15% |
| Vulnerability pressure | 15% |
| Accepted intelligence pressure | 15% |
| Residual control weakness | 10% |
| Telemetry gap | 5% |

The normalized 0–100 score uses H0 (80+), H1 (65+), H2 (45+) and H3. These bands mean defensive attention, not likelihood of compromise.

### Proposed versus accepted

~~~text
proposed forecast
       |
       v
 analyst review
       |
       v
accepted forecast
~~~

Machine output and analyst judgment remain separate through accepted_forecasts.

## Intelligence quality and decay

Only signals in an accepted, active, validated or confirmed lifecycle state affect forecasting.

A signal can include severity, analytical confidence, source reliability, information credibility, context relevance, observation time, expiry and half-life. Accepted signals decay over time:

~~~text
decay = 0.5 ^ (age_days / half_life_days)
~~~

This prevents old intelligence from becoming immortal merely because a spreadsheet survived longer than its assumptions.

## RedFrameworks intelligence bridge

TCE already uses RedFrameworks v6 as a review-gated domain-context provider. Horizon can convert a saved context-enrichment snapshot into **candidate intelligence signals**:

~~~bash
tce context-enrich examples/cases/enterprise-identity \
  --output redframeworks-context.json

tce horizon-intel-candidates \
  examples/cases/enterprise-identity \
  redframeworks-context.json \
  --output horizon-intelligence-candidates.yaml
~~~

The bridge carries context, domain pack, actor/campaign IDs, crown jewels, environment targets, ATT&CK techniques and source quality into candidate signal objects.

Those signals are deliberately written with status `candidate`. They do not influence Horizon until an analyst reviews them and promotes relevant information into the Environment State. An actor being present in a sector/domain pack is not evidence that the actor is targeting the organization.

## Vulnerability pressure

A vulnerability signal can include target asset, CVE when known, severity, CISA KEV state and EPSS. KEV raises the defensive pressure floor. EPSS is an input to prioritization, not a promise that exploitation will occur.

## Risk-weighted choke points

The original TCE choke-point calculation counts architecture nodes across accepted high-priority scenarios. Horizon adds risk-weighted enterprise convergence. It records total modeled risk touching each node, defensive leverage, path count, transit count, entry/target roles and crown jewels behind the convergence point.

Transit convergence is weighted more strongly than simply being the destination, so the crown jewel does not win the choke-point contest merely for having the poor taste to be important.

## Detection by Absence

For every candidate path Horizon asks:

> If this path matters, what must be observable and what is missing?

It compares local telemetry requirements with actual enterprise telemetry capabilities and, when ATT&CK data is available, current Detection Strategy / Data Component requirements from the repository's existing ATT&CK STIX index.

No extra mitreattack-python dependency is required. TCE already parses current ATT&CK STIX and its defensive metadata, so a second parser would mostly create a second maintenance problem.

~~~bash
tce horizon-absence examples/cases/enterprise-identity --offline

tce standards-sync --attack-only
tce horizon-absence examples/cases/enterprise-identity
~~~

Horizon blind paths are also appended to the normal Detection Backlog as telemetry-blind-path work.

## Preemptive defensive actions

The built-in defensive catalog can propose exposure reduction, privileged-trust constraints, segmentation, telemetry closure, remediation priority, recovery isolation and third-party trust review.

Every action remains proposed and review-gated. When D3FEND is available, Horizon also attaches defensive D3FEND references associated with the ATT&CK behaviors covered by each action candidate.

When a budget is supplied, the optimizer uses **marginal path coverage**. Overlapping controls receive declining incremental benefit instead of each pretending to eliminate the same risk independently.

~~~bash
tce horizon-actions examples/cases/enterprise-identity --budget 8 --offline

tce horizon-export-actions examples/cases/enterprise-identity \
  --budget 8 --offline \
  --output horizon-preemptive-actions.yaml
~~~

## Scenario candidates

~~~bash
tce horizon-export examples/cases/enterprise-identity \
  --offline \
  --output horizon-scenario-candidates.yaml
~~~

The lifecycle is:

~~~text
Environment State
  -> Horizon path candidate
  -> TCE scenario candidate
  -> analyst review
  -> telemetry / detection / validation
  -> decision
~~~

Generated scenarios are never silently promoted.

## Drift

~~~bash
tce horizon-assess examples/cases/enterprise-identity \
  --offline --output horizon-before.json

# environment, CTI, controls or telemetry changes

tce horizon-assess examples/cases/enterprise-identity \
  --offline --output horizon-after.json

tce horizon-diff horizon-before.json horizon-after.json
~~~

The diff surfaces new/removed paths, score changes, component drivers, newly blind paths, resolved blind paths, and H0/H1 change. This provides the basis for a daily enterprise horizon report: **what changed, why it matters, and what defensive decision deserves review**.

## Main commands

~~~bash
tce horizon-conformance examples/cases/enterprise-identity
tce horizon-assess examples/cases/enterprise-identity --offline
tce horizon-chokepoints examples/cases/enterprise-identity --offline
tce horizon-absence examples/cases/enterprise-identity --offline
tce horizon-actions examples/cases/enterprise-identity --budget 8 --offline
~~~

## Design boundary

Horizon keeps three boundaries explicit:

1. prediction is a proposal, not fact;
2. external intelligence is review-gated, not automatic attribution;
3. paths describe enterprise trust and defensive exposure, not command-level attack execution.

## References

- [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)
- [CTID Threat Modeling with ATT&CK](https://center-for-threat-informed-defense.github.io/threat-modeling-with-attack/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE D3FEND](https://d3fend.mitre.org/)
- [CTID Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST EPSS](https://www.first.org/epss/)
