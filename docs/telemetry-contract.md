# Telemetry Contract

A telemetry contract states what must be observable for a threat or detection hypothesis to be testable.

~~~mermaid
flowchart LR
    S[Scenario] --> B[Behavior]
    B --> O[Observable]
    O --> R[Required Data]
    R --> DS[Enterprise Data Source]
    DS --> F[Required Fields]
    F --> C[Coverage]
~~~

A contract defines scenario and detection linkage, source, event or state change, entity identifiers, required fields, retention, latency target, normalization, enrichment, integrity requirements, expected failure modes, fallback source, owner, and readiness status.

Having logs is not the same thing as having evidence suitable for a detection hypothesis.
