# TCE Knowledge Graph

The TCE data model is a graph connecting Mission, Decision, Intelligence Requirement, Crown Jewel, Architecture Node, Trust Boundary, Evidence, Threat Hypothesis, Threat Scenario, ATT&CK Behavior, Defensive Control, Telemetry Contract, Detection Use Case, Validation, Intelligence Gap, and Backlog Item.

~~~mermaid
flowchart LR
    M[Mission] --> D[Decision]
    D --> IR[Intelligence Requirement]
    IR --> H[Hypothesis]
    E[Evidence] --> H
    H --> S[Scenario]
    S --> CJ[Crown Jewel]
    S --> A[Architecture]
    S --> T[Telemetry]
    T --> DU[Detection]
    DU --> V[Validation]
    V --> G[Gap]
    G --> D2[Decision]
~~~

TCE should interoperate with existing standards rather than replace them.
