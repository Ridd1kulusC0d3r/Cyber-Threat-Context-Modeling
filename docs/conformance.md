# TCE Conformance

TCE now exposes executable conformance checks for the 1.0 draft.

## Levels

- `TCE-Core` — mission/case, crown jewel, Threat Context, architecture and prioritized scenario.
- `TCE-Detection` — Core plus Telemetry Contract and Detection Specification.
- `TCE-Validated` — Detection plus linked validation evidence in passed state.
- `TCE-Operational` — Validated plus ownership, review dates and a managed Decision or Intelligence Gap.

Run:

    tce conformance CASE_DIR --level core
    tce conformance CASE_DIR --level detection
    tce conformance CASE_DIR --level validated
    tce conformance CASE_DIR --level operational

## Current repository checks

The CI pipeline additionally verifies:

- Python unit tests;
- semantic entity/reference validation;
- executable reference cases;
- defensive log-replay validation fixtures;
- report and dashboard generation;
- standards export smoke tests.

The 1.0 specification remains a draft until core schemas and migration rules are frozen, but the conformance model is already executable.
