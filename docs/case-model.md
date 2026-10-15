# TCEM Case Model

A **TCEM Case** is the unit of analysis.

    cases/
    └── ORG-2026-001/
        ├── case.yaml
        ├── intelligence-requirements.yaml
        ├── crown-jewels.yaml
        ├── architecture.yaml
        ├── evidence.yaml
        ├── hypotheses.yaml
        ├── threat-scenarios.yaml
        ├── telemetry-contracts.yaml
        ├── detections.yaml
        ├── intelligence-gaps.yaml
        ├── decisions.yaml
        └── reports/

CLI:

    tcem validate <case-dir>
    tcem score <case-dir>
    tcem graph <case-dir>
    tcem gaps <case-dir>
    tcem coverage <case-dir>
    tcem chokepoints <case-dir>
    tcem trace <case-dir> DEC-001
    tcem report <case-dir> --output report.md
