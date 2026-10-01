# TCE Conformance

This file describes the current executable conformance direction for the 1.0 draft.

## Current repository checks

The CI pipeline verifies:

- Python unit tests;
- semantic entity/reference validation;
- executable reference cases;
- defensive log-replay validation fixtures;
- report and dashboard generation;
- standards export smoke tests.

## Planned formal conformance command

A future `tce conformance` command will evaluate a case against one of:

- TCE-Core;
- TCE-Detection;
- TCE-Validated;
- TCE-Operational.

The 1.0 specification remains a draft until schemas and migration rules are frozen.
