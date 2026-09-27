# Attack Paths as a Graph

A Mermaid diagram is useful for communication. TCE also represents the same problem as data.

~~~mermaid
flowchart LR
    ID[Identity] -->|authenticates_to| SaaS[SaaS]
    SaaS -->|administers| CP[Control Plane]
    CP -->|controls| CJ[Crown Jewel]
    T1[ATT&CK behavior] --> ID
    T2[ATT&CK behavior] --> CP
~~~

Architecture nodes and relationships make it possible to ask which paths reach a crown jewel, cross the same trust boundary, share privileged identities, lack validated telemetry, or are changed by new CTI.

Each attack-path step can reference behavior, ATT&CK technique, architecture node, trust boundary, required privilege, preconditions, controls, and expected observable.
