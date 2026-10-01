# Detection & Validation as Code

TCE v0.4 turns the chain from threat context to defensive evidence into executable, reviewable data.

## Detection Specification

A Detection Specification is the platform-neutral contract between a scenario and one or more concrete analytics.

It captures:

- linked threat scenarios;
- required telemetry contracts;
- ATT&CK behavior references;
- analytic concept and benign alternatives;
- correlation pattern;
- deterministic validation logic;
- platform implementations;
- validation objects;
- severity, owner and lifecycle.

The object uses the `DSP-*` namespace so it does not collide with ATT&CK Detection Strategy IDs.

## Correlation patterns

TCE ships a small defensive pattern library:

- single-event;
- ordered-sequence;
- threshold;
- new-entity;
- state-transition.

The goal is not to invent a query language. The pattern records the analytical idea in a portable form before it is translated into a SIEM-specific implementation.

## Sigma mapping

A Detection Specification may include a Sigma mapping.

    tce sigma-export CASE_DIR DSP-001 --output dsp-001.yml

Sigma is an implementation format, not the TCE source of truth.

## Validation harness

Validation uses structured logic over authorized fixtures or log-replay datasets.

    tce validation-run CASE_DIR VAL-001

The harness currently supports deterministic defensive checks for:

- single-event conditions;
- ordered event sequences;
- threshold groups.

The fixture contains security events, not an attack procedure.

## Telemetry health

    tce telemetry-health CASE_DIR

Each Telemetry Contract is scored on:

- required-field availability;
- entity correlation identifiers;
- declared source health;
- normalization;
- integrity requirements.

The output also maps conceptual fields to OCSF, ECS, Microsoft ASIM and Splunk CIM naming where a common mapping is known.

## Detection backlog

    tce detection-backlog CASE_DIR --output backlog.json

The backlog starts from prioritized scenarios and identifies work such as:

- no Detection Specification;
- missing or partial telemetry;
- no implemented analytic;
- missing or failed validation.

This keeps the order correct:

    Scenario -> Observable -> Telemetry -> Detection -> Validation -> Decision

## Coverage history and drift

Create a reproducible snapshot:

    tce snapshot CASE_DIR --output snapshots/2026-10-01.json

Compare two snapshots:

    tce snapshot-diff before.json after.json

The diff reports:

- added, removed and changed model entities;
- detection-coverage deltas;
- scenario priority changes;
- telemetry health regressions or improvements;
- validation-status changes.

This is the basis for continuous threat-context drift analysis.
