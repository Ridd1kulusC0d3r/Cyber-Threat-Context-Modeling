# TCE Methodology

## Phase 0 — Mission and decision context

Define what decision the analysis must support and what organizational outcome must be protected.

**Inputs:** business processes, service objectives, architecture diagrams, incident history, risk register, BCP/DR material, CTI requirements, and regulatory or contractual obligations.

**Outputs:** scope, mission statement, decision owner, time horizon, assumptions, exclusions, and review date.

## Phase 1 — Crown jewels

Crown jewels are not merely "important servers." They may be identities, data, cryptographic material, build pipelines, control planes, SaaS administration, business processes, safety-relevant systems, OT/ICS components, recovery infrastructure, detection infrastructure, or critical third-party dependencies.

For each crown jewel record:

- Business function
- Owner
- Confidentiality, integrity, availability, safety and regulatory impact
- Dependencies
- Recovery objective
- Privileged access paths
- Known compensating controls

Use [crown-jewel template](https://github.com/Ridd1kulusC0d3r/Cyber-Threat-Context-Modeling/blob/main/templates/crown-jewels.yaml).

## Phase 2 — Architecture and trust

Build a context map before discussing threats.

Model at minimum:

- Systems and services
- Identities
- Human administrators
- Workloads
- APIs
- Data flows
- Trust boundaries
- Network paths
- Control planes
- Third parties
- Internet exposure
- Authentication and authorization points
- Security tooling
- Logging pipelines
- Recovery paths

The point is not diagram aesthetics. The point is identifying **where trust changes** and **where a compromise can compound**.

## Phase 3 — Threat context

Use two complementary lenses.

### Evidence-driven

Sources can include internal incidents, vendor and government reporting, ATT&CK groups/campaigns/techniques/software, sector-specific reporting, exploitation trends, and internal telemetry.

### Theory-driven

Ask what could happen even when public evidence is weak:

- What would an attacker need to achieve the objective?
- What preconditions exist?
- Which trust boundary would be attractive?
- What control plane would create maximum leverage?
- Which dependency creates a single point of compromise?
- What would be hard to observe?
- What would break recovery or detection itself?

Do not collapse theory and evidence into one confidence statement. Record them separately.

## Phase 4 — Attack-path modeling

A scenario should be more than a bag of ATT&CK techniques.

Model:

1. Initial condition
2. Adversary objective
3. Preconditions
4. Entry vector
5. Required privileges
6. Sequence of adversary actions
7. Trust-boundary crossings
8. Dependencies
9. Target crown jewel
10. Expected impact
11. Defensive controls encountered
12. Required telemetry
13. Detection opportunities
14. Response decision points

Prefer **Attack Flow** or an equivalent graph when sequence matters.

ATT&CK is a vocabulary for behaviors, not the whole model.

## Phase 5 — Prioritization

Prioritize scenarios using the [TCE Priority Model](prioritization.md).

Keep two outputs:

- **Priority**: how urgently the scenario deserves defensive attention.
- **Confidence**: how strongly the available evidence supports the specific threat hypothesis.

This avoids treating "widely reported" as "most important to us" or treating "poorly documented" as "low risk."

## Phase 6 — Defensive architecture

Map controls to the attack path, not merely to a framework checklist.

For each important step ask:

- Can we prevent it?
- Can we constrain it?
- Can we detect it?
- Can we disrupt it?
- Can we recover from it?
- Can we reduce blast radius?
- Can we invalidate the precondition?

Useful references include ATT&CK mitigations, D3FEND, NIST SP 800-53, cloud-native controls, identity security, application controls, and resilience practices.

## Phase 7 — Telemetry contract

A telemetry contract defines the observations required to test a detection hypothesis.

For each scenario, specify:

- Required event or state change
- Source system
- Required fields
- Entity identifiers
- Timestamps
- Retention
- Expected latency
- Normalization
- Enrichment
- Integrity requirements
- Failure mode
- Alternate source
- Data owner

The question is not "what logs exist?" but "what observations are required?"

## Phase 8 — Detection engineering

Turn attack-path steps into detection hypotheses.

A strong hypothesis contains:

- Adversary behavior
- Preconditions
- Observable effect
- Required context
- Expected benign alternatives
- Detection logic concept
- Correlation window
- Entities to join
- Severity rationale
- Expected false-positive sources
- Validation plan
- Response decision

Sequence-aware detection is preferred when a single event has low specificity.

See [Detection Engineering](detection-engineering.md).

## Phase 9 — Validation

Validate assumptions in authorized environments using safe methods such as unit tests, historical log replay, synthetic events, purple-team exercises, approved emulation frameworks, tabletop simulation, and control walkthroughs.

Record test date, environment, expected result, actual result, and unresolved gaps.

## Phase 10 — Feedback

TCE is not a one-time document.

Triggers for review include new crown jewels, architecture changes, trust boundaries, sector targeting, new TTPs, exploitation trends, incidents, detection gaps, logging changes, acquisitions, and new SaaS/cloud platforms.

A model without a review trigger becomes archaeology.
