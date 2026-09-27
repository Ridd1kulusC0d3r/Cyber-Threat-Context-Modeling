# Decision Trace

Decision Trace is the explainability layer of TCE.

~~~mermaid
flowchart BT
    DEC[Decision] --> SC[Scenario]
    SC --> H[Hypothesis]
    H --> E[Evidence]
    H --> IR[Intelligence Requirement]
    SC --> CJ[Crown Jewel]
~~~

The trace should show which crown jewel is protected, which scenarios motivated the decision, which hypotheses support the scenarios, which evidence supports or contradicts them, which Intelligence Requirement initiated the analysis, and which unresolved gaps remain.

    tce trace examples/cases/enterprise-identity DEC-001
