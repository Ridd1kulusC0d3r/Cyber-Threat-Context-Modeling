# Enterprise Environment State

The ENV object is the Horizon representation of the enterprise as it exists at a point in time. It complements, rather than replaces, the TCEM architecture model.

## Architecture versus Environment State

| Architecture | Environment State |
|---|---|
| Intended structure and trust | Current defensive state |
| Relatively stable design view | Time-stamped snapshot |
| Nodes and relationships | Assets, identities, controls, telemetry, vulnerability and intelligence signals |
| Threat-model input | Horizon forecasting input |

If a case has no ENV object, Horizon can derive a minimal environment from existing architecture nodes and relationships. That compatibility mode has no rich control, telemetry, vulnerability or intelligence state.

## Relationship direction

A Horizon relationship is directed according to **risk propagation**.

~~~yaml
- id: REL-SAAS-IDP
  from: NODE-SAAS-ADMIN
  to: NODE-IDP
  type: administers
~~~

This means that compromise or abuse of the modeled source relationship can create material defensive exposure toward the target.

Use bidirectional only when that propagation genuinely applies in both directions.

## Core collections

An Environment State can contain:

- assets;
- identities;
- directed trust/dependency relationships;
- controls and assessed effectiveness;
- telemetry sources and capabilities;
- vulnerability signals;
- accepted or candidate intelligence signals;
- accepted analyst forecasts.

### Intelligence lifecycle

Candidate external intelligence does not affect forecasting until it is explicitly accepted or activated.

Recommended states:

~~~text
candidate -> accepted -> active -> expired
                    \-> rejected
~~~

Accepted signals can specify source reliability, information credibility, context relevance, timestamps, expiry and half-life.

## CSV bootstrap

Large environments should not be handwritten, because humans already have enough opportunities to become unpaid YAML parsers.

~~~bash
tce environment-import-csv \
  --assets assets.csv \
  --relationships relationships.csv \
  --controls controls.csv \
  --telemetry telemetry.csv \
  --vulnerabilities vulnerabilities.csv \
  --intelligence intelligence.csv \
  --environment-id ENV-PROD \
  --name "Production enterprise" \
  --output environment.yaml
~~~

If snapshot-at is omitted, the importer stamps the current UTC time.

### Assets CSV

~~~text
record_kind,id,name,type,trust_zone,internet_exposure,entry_point,crown_jewel_ids,control_ids,telemetry_requirements,technology_tags,owner
~~~

record_kind may be asset or identity. List fields accept commas or semicolons.

### Relationships CSV

~~~text
id,from,to,type,trust_boundary,bidirectional,technique_ids,control_ids,required_telemetry
~~~

### Controls CSV

~~~text
id,name,status,effectiveness,target_ids,relationship_ids
~~~

Effectiveness is an analyst-assessed 0..1 value. It is not a vendor claim with a decimal point added for scientific atmosphere.

### Telemetry CSV

~~~text
id,name,status,target_ids,relationship_ids,capabilities,data_components
~~~

Data components may contain ATT&CK Data Component names when known.

### Vulnerability signals CSV

~~~text
id,target_id,cve,severity,kev,epss,note
~~~

Use this as the normalized defensive handoff from vulnerability management. KEV and EPSS values remain inputs to prioritization, not proof that exploitation has or will occur.

### Intelligence / OSINT signals CSV

~~~text
id,kind,scope,target_ids,technique_ids,severity,confidence,source_reliability,information_credibility,relevance,direction,status,observed_at,half_life_days,source_ref
~~~

This provides a generic bridge for authorized defensive feeds such as CTI, credential-exposure monitoring, external attack-surface management, brand/typosquat monitoring, sector trends, and other reviewed signals.

Imported signals should normally begin as candidate. Only accepted/active/validated/confirmed signals affect Horizon forecast pressure.

## Typical defensive collection sources

Environment State data can be normalized from:

- CMDB and asset inventory;
- IdP/IAM and privileged-role inventory;
- cloud resource inventory;
- SaaS administrative-role inventory;
- EDR and endpoint inventory;
- vulnerability management;
- external attack-surface management;
- network and trust-zone diagrams;
- SIEM/data-lake source catalog;
- recovery and backup authority inventory;
- OT/ICS inventory;
- AI agents, connectors, tool servers and machine identities.

Horizon does not require one product to own all of these datasets. It requires a normalized graph with explicit provenance and review boundaries.
