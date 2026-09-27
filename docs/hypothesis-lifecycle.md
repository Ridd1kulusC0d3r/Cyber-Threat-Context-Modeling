# Threat Hypothesis Lifecycle

A threat hypothesis is a testable analytical proposition about how a threat could affect the organization.

~~~mermaid
flowchart LR
    P[proposed] --> A[under-analysis]
    A --> S[supported]
    A --> R[rejected]
    S --> V[validated]
    S --> X[superseded]
    V --> X
~~~

A hypothesis contains rationale, Intelligence Requirement linkage, target crown jewels, supporting evidence, contradicting evidence, alternative explanations, assumptions, confidence, information gaps, related attack paths, collection requirements, owner, and review date.

Confidence describes strength of support. It does **not** describe business priority.
