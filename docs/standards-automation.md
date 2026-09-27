# Standards Automation

TCE v0.3 adds deterministic standards adapters around the AI layer.

## ATT&CK

The toolkit caches the official Enterprise ATT&CK STIX 2.1 bundle from mitre-attack/attack-stix-data.

    tce standards-sync --attack-only
    tce attack-validate examples/cases/enterprise-identity
    tce attack-search "valid accounts"

Qwen may propose a technique. The proposal remains a candidate until the ATT&CK index validates it.

## D3FEND

TCE downloads the current inferred D3FEND mapping dataset.

    tce standards-sync --d3fend-only
    tce d3fend T1078

The raw D3FEND mapping remains visible to the analyst.

## Attack Flow

    tce export-attack-flow examples/cases/enterprise-identity TS-001 --output flow.json

Attack-path steps become Attack Flow actions and retain validated ATT&CK references when available.

## ATT&CK Navigator

    tce export-navigator examples/cases/enterprise-identity --output layer.json

## STIX 2.1 and OpenCTI

    tce export-stix examples/cases/enterprise-identity --output case.stix.json
    tce opencti-push case.stix.json

The second command is a dry-run. To explicitly import after review:

    OPENCTI_URL=https://opencti.example
    OPENCTI_TOKEN=...
    tce opencti-push case.stix.json --commit

The bridge uses the official PyCTI client when the optional OpenCTI dependency is installed.
