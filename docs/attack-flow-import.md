# Attack Flow Import and Export

TCE now supports both directions for Attack Flow.

## TCE to Attack Flow

    tce export-attack-flow \
      examples/cases/enterprise-identity \
      TS-001 \
      --output flow.json

TCE attack-path steps become Attack Flow actions and retain ATT&CK references when available.

## Attack Flow to TCE

    tce import-attack-flow \
      flow.json \
      --output imported-scenario.yaml

The importer:

1. finds the Attack Flow object;
2. starts from its start references;
3. follows action effect references;
4. preserves technique IDs or resolves technique STIX references when possible;
5. creates an unscored TCE scenario draft;
6. records original Attack Flow IDs;
7. marks the result as review required and disables automatic merge.

Architecture nodes, crown jewels, business impact, telemetry, priority and ownership remain blank because those are organization-specific judgments.
