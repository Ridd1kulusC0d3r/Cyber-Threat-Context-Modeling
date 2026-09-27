# Analyst Workflow

Threat Context Engineering is designed as a **decision workflow**, not a diagram exercise.

## End-to-end flow

~~~mermaid
flowchart LR
    M[Mission] --> D[Decision]
    D --> IR[Intelligence Requirements]
    IR --> CJ[Crown Jewels]
    CJ --> A[Architecture]
    A --> E[Evidence]
    E --> H[Threat Hypotheses]
    H --> AP[Attack Paths]
    AP --> P[Prioritization]
    P --> C[Controls]
    C --> T[Telemetry Contracts]
    T --> DE[Detection Use Cases]
    DE --> V[Validation]
    V --> G[Gaps]
    G --> D2[Decision / Backlog]
    D2 --> IR
~~~

## What an analyst should do

1. Define the decision that must be supported.
2. Translate the decision into Intelligence Requirements.
3. Identify crown jewels and business dependencies.
4. Model architecture, identities, trust boundaries, control planes, recovery paths, and security tooling.
5. Register evidence with provenance and freshness.
6. Create falsifiable threat hypotheses.
7. Record supporting and contradicting evidence.
8. Build attack paths that connect behaviors to architecture and crown jewels.
9. Prioritize scenarios independently from confidence.
10. Identify defensive choke points.
11. Specify telemetry required to observe each important behavior.
12. Create detection use cases and correlation logic.
13. Validate the expected visibility and analytic behavior.
14. Record intelligence, telemetry, control, detection, and validation gaps.
15. Produce explicit decisions and backlog items.
16. Revisit the model when evidence, architecture, or threats change.

## Definition of done

A TCE assessment is complete enough for a review cycle when:

- the decision and Intelligence Requirements are explicit;
- crown jewels have owners and rationale;
- architecture relationships are represented;
- high-priority hypotheses have evidence lineage;
- attack paths have identifiable architecture nodes and trust boundaries;
- high-priority paths have explicit controls and telemetry requirements;
- detection coverage is represented by dimension;
- validation status is visible;
- unresolved gaps have owners;
- decisions can be traced back to evidence.
