# Evidence Model

TCE keeps **observations, assessments, inferences, assumptions, and unknowns** distinct.

| State | Meaning |
|---|---|
| observed | Directly observed in an internal or external source |
| assessed | Analytical judgment based on evidence |
| inferred | Derived indirectly from one or more observations |
| assumed | Used provisionally to continue analysis |
| unknown | Required information is not available |

Each evidence item preserves source, source type, publication date, collection date, claim, state, source reliability, information credibility, temporal relevance, linked hypotheses, and analyst notes.

~~~mermaid
flowchart LR
    ES[Supporting Evidence] --> H[Threat Hypothesis]
    EC[Contradicting Evidence] --> H
    H --> A[Analytical Assessment]
    U[Unknowns] --> A
~~~

A framework that only stores confirming evidence becomes a confirmation-bias database with nicer YAML.
