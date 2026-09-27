# TCE Methodology

Threat Context Engineering is a continuous analytical and defensive-engineering loop.

## Phase 0 — Mission and decision context

Define what must be protected and what decision the analysis must support.

Outputs:

- mission statement;
- decision owner;
- scope and exclusions;
- time horizon;
- assumptions;
- review trigger.

## Phase 1 — Intelligence Requirements

Translate the decision into explicit questions.

A useful Intelligence Requirement states:

- what must be known;
- why the answer matters;
- who needs it;
- when it is needed;
- which crown jewels or hypotheses it affects.

CTI without a requirement tends to become news consumption with expensive tooling.

## Phase 2 — Crown jewels

Crown jewels may be identities, data, cryptographic material, build pipelines, control planes, SaaS administration, business processes, safety-relevant systems, OT/ICS components, recovery infrastructure, security tooling, or critical third-party dependencies.

Record business function, owner, impact, dependencies, recovery needs, privileged paths, architecture nodes, and controls.

## Phase 3 — Architecture and trust

Model systems, services, identities, administrators, workloads, APIs, data flows, trust boundaries, network paths, control planes, third parties, exposure, security tooling, logging pipelines, and recovery paths.

The objective is to expose **where trust changes and where compromise compounds**.

## Phase 4 — Evidence

Register evidence with provenance.

Keep these states distinct:

- observed;
- assessed;
- inferred;
- assumed;
- unknown.

Record supporting and contradicting evidence. Preserve temporal relevance so stale evidence is visible rather than silently immortal.

## Phase 5 — Threat hypotheses

Create testable analytical propositions.

Each hypothesis should include:

- Intelligence Requirement linkage;
- target crown jewels;
- rationale;
- supporting evidence;
- contradicting evidence;
- alternative explanations;
- assumptions;
- confidence;
- information gaps;
- collection requirements;
- lifecycle state.

Priority and confidence remain separate.

## Phase 6 — Attack-path graph

A scenario is more than a bag of ATT&CK techniques.

Model initial condition, objective, preconditions, behavior sequence, architecture nodes, trust-boundary crossings, required privilege, target crown jewel, expected observables, controls, telemetry, and response decision points.

ATT&CK provides behavior vocabulary. Attack Flow or an equivalent graph can represent sequence.

## Phase 7 — Prioritization

Use the TCE Priority Model to score:

- crown-jewel criticality;
- threat relevance;
- attack-path feasibility;
- exposure;
- control weakness;
- detection gap.

Always keep the rationale with the score.

## Phase 8 — Defensive choke points

Identify architecture nodes and trust relationships that recur across P0/P1 paths.

Frequency is not enough. Also consider privilege concentration, blast radius, recoverability, and control maturity.

## Phase 9 — Defensive architecture

For each important attack-path step ask:

- Can the precondition be removed?
- Can access be prevented?
- Can privilege be constrained?
- Can blast radius be reduced?
- Can the behavior be made observable?
- Can the sequence be disrupted?
- Can recovery be accelerated?
- Can sensor or pipeline impairment be detected?

Map ATT&CK, D3FEND, NIST, cloud-native controls, product controls, identity controls, and resilience practices only when the role of the mapping is explicit.

## Phase 10 — Telemetry Contract

Define what must be observable.

Specify:

- event or state change;
- source;
- required fields;
- entity identifiers;
- retention;
- latency;
- normalization;
- enrichment;
- integrity requirements;
- failure modes;
- fallback sources;
- readiness status.

Do not ask only what logs already exist. Ask what evidence is required to test the hypothesis.

## Phase 11 — Detection engineering

Turn behavior into a detection use case.

Record:

- behavior;
- observable effect;
- entities;
- benign alternatives;
- analytic concept;
- sequence or threshold;
- correlation window;
- joins;
- triage context;
- response decision;
- implementation references.

Track telemetry, analytic, correlation, validation, and response coverage independently.

## Phase 12 — Validation

Validate safely in authorized environments through unit tests, historical log replay, synthetic events, tabletop exercises, purple-team work, approved emulation, or control walkthroughs.

Record expected result, actual result, environment, evidence, owner, and date.

## Phase 13 — Intelligence gaps and Decision Trace

Unknowns become managed collection work.

Defensive decisions become explicit objects linked to:

- Intelligence Requirements;
- crown jewels;
- evidence;
- hypotheses;
- scenarios;
- detection use cases;
- validation;
- open gaps.

The final product is not a threat-model document. It is a traceable defensive decision system.
