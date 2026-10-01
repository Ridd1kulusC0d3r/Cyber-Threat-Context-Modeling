# Telemetry Schema Bridges

TCE Telemetry Contracts use conceptual field names first.

A conceptual requirement such as:

    user.id
    source.ip
    target.resource
    action
    timestamp

can then be mapped to common security-data schemas.

The built-in bridge currently includes common equivalents for:

- OCSF;
- Elastic Common Schema (ECS);
- Microsoft ASIM;
- Splunk CIM.

The bridge is deliberately small and explicit. A schema mapping is a translation aid, not proof that a source actually produces the field.

Use:

    tce telemetry-health CASE_DIR

to see both missing conceptual fields and known schema translations.
