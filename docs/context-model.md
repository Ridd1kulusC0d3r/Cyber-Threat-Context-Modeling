# TCE Context Model

Threat Context Engineering works best when analysis is treated as a connected model rather than a stack of documents.

## Core model

~~~mermaid
flowchart LR
    M[Mission] --> CJ[Crown Jewel]
    CJ --> CTX[Threat Context]
    CTX --> A[Architecture / Trust]
    CTI[External CTI] --> CTX
    CTX --> TH[Threat Hypothesis]
    TH --> AP[Attack Path]
    AP --> B[ATT&CK Behavior]
    AP --> CJ
    B --> TEL[Telemetry Contract]
    TEL --> DET[Detection Use Case]
    DET --> VAL[Validation Evidence]
    VAL --> DEC[Decision]
    VAL --> GAP[Gap / Residual Risk]
    GAP --> TH
~~~

## Threat Context is a first-class object

A `Threat Context` explains **why a threat scenario matters in this environment**.

It can connect the same scenario to multiple analytical lenses, such as:

- identity and privilege;
- cloud control planes;
- third-party/SaaS trust;
- resilience and recovery;
- AI/GenAI surfaces;
- supply chain;
- OT/ICS;
- security-control-plane integrity.

This is intentionally broader than application threat modeling.

## The nine context dimensions

Each important context can describe:

1. mission;
2. architecture;
3. adversary relevance;
4. campaign relevance;
5. behavior;
6. exposure and trust;
7. defensive requirements;
8. evidence and uncertainty;
9. temporal validity.

Actor or campaign attribution is optional. A trust weakness can justify a defensive scenario even when no specific actor is assigned.

## RedFrameworks relationship

RedFrameworks v6 supplies external context candidates such as domain packs, adversary profiles, campaigns, detection intelligence, validation references, AI security surfaces and CTI sources.

TCE decides whether those candidates are relevant to an organization-specific case.

~~~text
RedFrameworks v6
    |
    v
candidate context
    |
    v
TCE evidence + analyst review
    |
    v
Threat Context
    |
    v
Scenario / Telemetry / Detection / Decision
~~~

External context is never automatically promoted to evidence or attribution.

## Why a graph matters

A technique list cannot answer which business process is endangered. A crown-jewel list cannot explain how compromise reaches it. A threat-actor list cannot prove relevance to the local environment.

The graph becomes useful when those relationships are explicit.

Useful queries include:

- Which contexts affect a crown jewel?
- Which scenarios cross more than one context lens?
- Which external campaigns are only candidates versus evidence-backed?
- Which high-priority scenarios depend on stale context?
- Which contexts share the same trust boundary?
- Which contexts lack telemetry or validation?
- Which external RedFrameworks domain packs are relevant but not yet modeled?

## Evidence lineage and time

Every claim should remain distinguishable as internal observation, external source, analyst inference, assumption or unknown.

Threat context decays. Record evidence collection, architecture validation, telemetry validation, detection test, context review and next review trigger.
