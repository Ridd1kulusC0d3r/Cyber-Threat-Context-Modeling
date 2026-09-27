# Detection Engineering in TCE

## Detection starts at threat modeling

TCE treats detection requirements as an output of threat analysis.

~~~mermaid
flowchart LR
    A[Attack path] --> B[Observable behaviors]
    B --> C[Telemetry requirements]
    C --> D[Detection hypothesis]
    D --> E[Analytic]
    E --> F[Correlation]
    F --> G[Case / response]
    G --> H[Validation]
~~~

## Detection hypothesis template

A useful hypothesis should answer:

- **Behavior**: what is the adversary trying to do?
- **Entity**: user, host, workload, app, identity, session, object, network flow?
- **Observable**: what change or action should become visible?
- **Context**: what enrichment is needed to interpret it?
- **Sequence**: what happened before or after?
- **Benign explanation**: what legitimate activity can look similar?
- **Decision**: what analyst or automated action follows?

## Build chains, not alert confetti

A weak rule may detect one suspicious event.

A stronger use case correlates a chain such as:

    unexpected identity use
      -> privileged role change
      -> access to sensitive repository
      -> bulk collection behavior
      -> outbound transfer anomaly

The exact analytics depend on platform and telemetry. The model should describe the behavior first and implementation syntax second.

## Coverage model

For each attack-path step, track:

| Field | Meaning |
|---|---|
| ATT&CK technique | Behavior vocabulary |
| Detection strategy | High-level detection approach |
| Data component | Observable data concept |
| Telemetry source | Actual enterprise source |
| Analytic | Detection implementation |
| Correlation | Cross-event / cross-source logic |
| Response | Decision or playbook |
| Validation | Test evidence |
| Coverage status | Covered / partial / missing / unknown |

## Coverage quality

A technique should not be marked "covered" merely because one rule references it.

Useful coverage questions:

- Is the relevant platform covered?
- Is the required telemetry present?
- Are required fields populated?
- Does enrichment work?
- Is correlation possible?
- Does the rule detect the modeled behavior?
- Was it validated?
- Is the response path usable?
- Can the attacker impair the sensor or pipeline?

## Telemetry failure is a modeled threat

The detection stack itself may be a crown jewel.

Model:

- Sensor disablement
- Collection gaps
- Pipeline delay
- Parser failure
- Field loss
- Time skew
- Identity resolution failure
- Retention gaps
- SIEM or data-lake access abuse
- Detection-rule tampering

A detection program that cannot detect loss of visibility has an operational blind spot worth modeling explicitly.
