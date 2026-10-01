# Threat Context Matrix

Threat Context Engineering is not limited to application or system-architecture threat modeling.

The method treats **context itself as a first-class analytical object** so a scenario can be understood across mission, technology, adversary behavior, evidence, telemetry, resilience and time.

## The nine context dimensions

Every important threat scenario should be explainable through nine dimensions:

| Dimension | Question |
|---|---|
| Mission | What business or operational outcome must remain trustworthy? |
| Architecture | Which systems, identities, dependencies and trust boundaries matter? |
| Adversary | Which external threat profiles are relevant, and what evidence supports relevance? |
| Campaign | Does a known campaign materially change assumptions about this environment? |
| Behavior | Which behavior sequence could affect the crown jewel? |
| Exposure | Which trust, privilege, third party or external surface makes the sequence feasible? |
| Defensive | Which controls, telemetry, analytics and response decisions matter? |
| Evidence | What is observed, inferred, assumed, contradicted or still unknown? |
| Temporal | When was this belief last validated, and what change should trigger review? |

This prevents a common failure mode: a threat model that knows a technique but does not know **why that technique matters here**.

## Threat-context lenses

TCE v0.3.2 ships a deterministic catalog of more than twenty lenses.

### RedFrameworks-aligned domain lenses

These map directly to RedFrameworks v6 domain packs:

- Identity & Access
- Cloud & Multi-Cloud
- AI / GenAI
- Web & API
- Software Supply Chain
- Detection & Validation
- ICS / OT
- IoT & Embedded

### TCE-native cross-cutting lenses

The method also covers contexts that are often lost when teams model only applications:

- Endpoint & Compute
- Network & Edge
- Data, Database & Analytics
- Email & Collaboration
- Third-Party & SaaS Trust
- Containers & Kubernetes
- Developer & CI/CD
- Cryptography, Secrets & PKI
- Resilience & Recovery
- Insider, Human & Process
- Mobile & BYOD
- Telecommunications
- Security Control Plane

The catalog lives in `src/tce/data/threat-context-lenses.yaml`.

## Why contexts are separate objects

A context is not the same thing as a scenario.

For example:

~~~text
CTX-IDENTITY
    |
    +-- CJ-001 Enterprise Identity
    +-- ARCH-001 Identity architecture
    +-- TS-001 Privileged trust path
    +-- RedFrameworks domain pack: identity
~~~

A second context can point to the same scenario:

~~~text
CTX-THIRDPARTY
    |
    +-- CJ-001
    +-- ARCH-001
    +-- TS-001
~~~

That tells the analyst that the same technical sequence matters for more than one reason.

The model therefore becomes many-to-many:

~~~mermaid
flowchart LR
    M[Mission] --> C[Threat Context]
    CJ[Crown Jewel] --> C
    A[Architecture] --> C
    C --> S[Threat Scenario]
    RF[RedFrameworks Context] --> C
    S --> T[Telemetry]
    S --> D[Detection]
    S --> V[Validation]
    V --> DEC[Decision]
~~~

## Context applicability is not a checklist score

The catalog is not a maturity checklist where every organization must select every lens.

TCE uses deterministic signals from the case to produce **applicability candidates**.

Example:

    tce context-assess examples/cases/enterprise-identity

A result may suggest Identity, Cloud or Third-Party context because those concepts appear in mission, scope or architecture.

A suggestion is not automatically inserted into the case.

## Context lifecycle

A context can be:

- `candidate`
- `active`
- `monitoring`
- `retired`

Each context should preserve:

- rationale for relevance;
- linked crown jewels;
- linked architecture;
- linked scenarios;
- Intelligence Requirements;
- external actor/campaign candidates;
- behavioral references;
- telemetry focus;
- evidence requirements;
- assumptions;
- confidence;
- freshness;
- owner;
- review date.

## Modeling without attribution

Actor attribution is optional.

A useful threat model can exist with:

~~~text
Known trust weakness
        |
        v
Plausible behavior sequence
        |
        v
Critical asset impact
        |
        v
Required telemetry
        |
        v
Defensive decision
~~~

without claiming a specific actor.

This matters because attribution confidence and defensive priority are different analytical dimensions.

## Modeling with CTI

When CTI is available, it can refine:

- sector relevance;
- observed campaigns;
- likely behavioral clusters;
- defensive focus;
- telemetry expectations;
- collection priorities;
- validation references.

But TCE requires the source and relevance rationale to remain visible.

External threat intelligence is **context**, not automatic proof that an organization is targeted.
