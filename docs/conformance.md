# TCEM Conformance

TCEM exposes executable conformance checks for the 1.0 draft.

## Levels

- `TCEM-Core` — mission/case, crown jewel, Threat Context, architecture and prioritized scenario.
- `TCEM-Detection` — Core plus Telemetry Contract and Detection Specification.
- `TCEM-Validated` — Detection plus linked validation evidence in passed state.
- `TCEM-Operational` — Validated plus ownership, review dates and a managed Decision or Intelligence Gap.

Run:

    tce conformance CASE_DIR --level core
    tce conformance CASE_DIR --level detection
    tce conformance CASE_DIR --level validated
    tce conformance CASE_DIR --level operational

## Optional TCEM-Horizon extension

TCEM-Horizon is orthogonal to the linear Core → Detection → Validated → Operational levels.

Run:

    tce horizon-conformance CASE_DIR

The extension checks for an enterprise Environment State, entry/exposure points, crown-jewel mappings, trust/dependency relationships, defensive controls, telemetry sources, explicit intelligence-signal lifecycle states, and the separation of accepted forecasts from proposed machine scores.

## Current repository checks

The CI pipeline additionally verifies:

- Python unit tests;
- semantic entity/reference validation;
- executable reference cases;
- defensive log-replay validation fixtures;
- report and dashboard generation;
- standards export smoke tests.

The TCEM Specification 1.0 remains a draft until core schemas and migration rules are frozen, but the conformance model is already executable.
