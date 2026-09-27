# TCE Case Model

A **TCE Case** is the unit of analysis.

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

    tce validate <case-dir>
    tce score <case-dir>
    tce graph <case-dir>
    tce gaps <case-dir>
    tce coverage <case-dir>
    tce chokepoints <case-dir>
    tce trace <case-dir> DEC-001
    tce report <case-dir> --output report.md
