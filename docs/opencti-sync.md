# OpenCTI Bidirectional Bridge

TCE v0.3.1 supports both directions:

~~~mermaid
flowchart LR
    O[OpenCTI] --> S[Local Snapshot]
    S --> R[Entity Resolution]
    S --> E[TCE Evidence Candidates]
    E --> A[Analyst Review]
    A --> C[TCE Case]
    C --> STIX[STIX 2.1 Export]
    STIX --> O
~~~

## OpenCTI to TCE

Configure the official PyCTI client:

    export OPENCTI_URL=https://opencti.example
    export OPENCTI_TOKEN=...

Create a local snapshot:

    tce opencti-pull --output opencti-snapshot.json

Limit entity families when useful:

    tce opencti-pull \
      --types intrusion-set,campaign,malware,report \
      --limit 50 \
      --output opencti-snapshot.json

Convert the snapshot into review-only evidence candidates:

    tce opencti-to-tce \
      opencti-snapshot.json \
      --output opencti-evidence-candidates.yaml

Nothing is automatically merged into a TCE Case.

## Entity resolution

Before linking external intelligence to internal analytical objects:

    tce opencti-resolve \
      opencti-snapshot.json \
      examples/cases/enterprise-identity \
      --threshold 0.90 \
      --output resolution.json

Exact normalized-name or alias matches score 1.0. Fuzzy matches below 1.0 remain analyst-review candidates.

## TCE to OpenCTI

Export a reviewed TCE graph:

    tce export-stix CASE_DIR --output case.stix.json

Inspect the bundle without sending it:

    tce opencti-push case.stix.json

Only an explicit commit performs transfer:

    tce opencti-push case.stix.json --commit

The bridge therefore supports bidirectional workflow while preserving analyst approval at both ingestion and publication boundaries.
