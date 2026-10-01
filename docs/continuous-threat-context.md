# Continuous Threat Context

TCE distinguishes two kinds of drift.

## Internal model drift

Use model snapshots:

    tce snapshot CASE_DIR --output before.json
    tce snapshot CASE_DIR --output after.json
    tce snapshot-diff before.json after.json

This detects changes to:

- entities and architecture-backed analytical objects;
- scenario scores and bands;
- detection coverage;
- telemetry health;
- validation status.

## External intelligence drift

Capture RedFrameworks context-enrichment results at two points in time:

    tce context-enrich CASE_DIR --output context-before.json
    tce redframeworks-sync
    tce context-enrich CASE_DIR --output context-after.json
    tce context-drift context-before.json context-after.json

The drift result can surface new or removed candidate:

- adversaries;
- campaigns;
- detection mappings;
- validation references;
- AI security surfaces.

Every external change remains review-gated.

New CTI does not automatically change scenario priority, attribution or evidence status. It creates analytical work.

Conceptually:

~~~text
New external intelligence
        -> candidate relation
        -> affected Threat Context
        -> analyst review
        -> scenario / telemetry / detection impact
        -> decision or managed gap
~~~
