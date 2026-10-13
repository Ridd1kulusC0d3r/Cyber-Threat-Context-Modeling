# Detection by Absence

**Detection by Absence** asks whether a high-value enterprise threat path is observable before a detection rule is written.

The question changes from:

> Which logs do we already have?

to:

> Which evidence must exist if this path happens, and which of that evidence is currently absent?

## Local observability requirements

Environment nodes can declare telemetry requirements:

~~~yaml
telemetry_requirements:
  - privileged-session
  - identity-config-change
~~~

Relationships can declare what must be observable across a trust boundary:

~~~yaml
required_telemetry:
  - external-admin-session
  - privilege-change
~~~

Telemetry sources declare the capabilities that actually exist.

## ATT&CK observability requirements

When the ATT&CK cache is available, Horizon also reads the repository's current ATT&CK Detection Strategies, Analytics and Data Components for techniques associated with a candidate path.

The repository already has an ATT&CK STIX index for this purpose. Horizon therefore does not add mitreattack-python merely to parse the same source twice.

## Output

A blind path records:

- Horizon path ID;
- H0–H3 priority band;
- proposed forecast pressure;
- crown jewels behind the path;
- ATT&CK technique references;
- missing enterprise telemetry;
- missing ATT&CK Data Components;
- current coverage ratio;
- mandatory analyst review.

Run with only local Environment State requirements:

~~~bash
tce horizon-absence examples/cases/enterprise-identity --offline
~~~

Run with ATT&CK enrichment:

~~~bash
tce standards-sync --attack-only
tce horizon-absence examples/cases/enterprise-identity
~~~

## Detection Backlog integration

The normal detection backlog now receives blind enterprise paths as:

~~~text
work_type = telemetry-blind-path
~~~

This allows the same engineering queue to contain conventional detection work and enterprise visibility debt.

## Interpretation

Detection by Absence is not a score of security quality on its own.

A path can have strong preventive controls and still need observability. It can also have excellent logs while remaining excessively exposed. Horizon therefore treats telemetry gap as one component of forecast pressure rather than allowing log volume to impersonate risk management.
