# Intelligence Requirements

CTI should begin with a decision, not with a feed.

## Structure

An Intelligence Requirement records the question to answer, the decision it supports, stakeholder, priority, time horizon, linked crown jewels, information gaps, collection requirements, and review date.

~~~mermaid
flowchart LR
    D[Decision Need] --> IR[Intelligence Requirement]
    IR --> E[Evidence Collection]
    E --> H[Hypothesis]
    H --> S[Scenario]
    S --> DET[Detection / Control]
    DET --> DEC[Decision]
~~~

A useful requirement is specific enough to change a defensive decision.

Bad: What are the latest cyber threats?

Better: Which identity-centered attack paths could provide administrative access to the enterprise control plane, and which of those paths currently lack validated detection?
