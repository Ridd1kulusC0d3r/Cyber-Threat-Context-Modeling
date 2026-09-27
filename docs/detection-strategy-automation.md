# ATT&CK Detection Strategy Automation

TCE now reads the current ATT&CK STIX objects for:

- ATT&CK techniques;
- Detection Strategies;
- Analytics;
- Data Components;
- log-source references;
- mutable analytic elements.

The important relationship is not merely technique to rule. It becomes:

~~~mermaid
flowchart LR
    T[ATT&CK Technique] --> DS[Detection Strategy]
    DS --> AN[Analytic]
    AN --> DC[Data Component]
    DC --> LS[Log Source / Channel]
    AN --> ME[Mutable Elements]
~~~

## Query a technique

    tce standards-sync --attack-only
    tce attack-detect T1078

The command returns the technique plus Detection Strategies linked through ATT&CK detection relationships. Each strategy includes its analytics, required Data Components, concrete log-source references and mutable elements where ATT&CK provides them.

## Knowledge graph

When the operational graph is built with ATT&CK enabled, these objects become first-class nodes:

- attack_technique
- detection_strategy
- analytic
- data_component

and relationships:

- detected_by
- includes_analytic
- requires_data_component

This allows the TCE graph to answer a much more useful question than "do we map T1078?":

> Which ATT&CK detection strategies and concrete telemetry components are relevant to this organization-specific attack path, and which of those telemetry requirements do we actually satisfy?

AI may propose a mapping, but this layer is populated from ATT&CK STIX rather than invented by the model.
