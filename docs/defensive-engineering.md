# Defensive Engineering

Controls should be connected to attack-path steps and to the mechanism by which they change attacker options.

For each important step ask whether the precondition can be removed, access prevented, privilege constrained, blast radius reduced, action made observable, sequence disrupted, recovery accelerated, or the defensive sensor protected from impairment.

~~~mermaid
flowchart LR
    A[Attack Step] --> D[Defensive Technique]
    D --> M[Mechanism]
    M --> C[Architecture Control]
    C --> I[Implementation]
    I --> V[Validation Evidence]
~~~

TCE uses D3FEND as a defensive knowledge source, not as a decorative mapping table.
