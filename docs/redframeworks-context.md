# RedFrameworks v6 as a TCE Context Provider

TCE consumes RedFrameworks v6 as an external, review-gated context provider rather than copying its entire catalog into a second repository.

## What TCE reads

The adapter caches selected RedFrameworks API v4 datasets:

- API discovery metadata;
- adversary profiles;
- campaign intelligence;
- detection-intelligence mappings;
- domain packs;
- AI security surfaces;
- defensive validation-plan metadata;
- intelligence sources;
- verification metadata.

The default source is:

    https://ridd1kulusc0d3r.github.io/RedFrameworks/api/v4

## Synchronize

    tce redframeworks-sync

The data is cached under:

    ~/.cache/tce/redframeworks/v4/

## Enrich modeled contexts

A TCE Threat Context can reference one or more RedFrameworks domain packs:

~~~yaml
redframeworks:
  domain_pack_ids:
    - identity
  use_as_candidate_universe: true
  require_case_evidence_for_relevance: true
~~~

Then:

    tce context-enrich examples/cases/enterprise-identity --output context-intelligence.json

The result may include candidate:

- adversaries;
- campaigns associated with those adversary profiles;
- detection-intelligence mappings;
- defensive validation references;
- AI security surfaces for the AI/GenAI pack;
- CTI collection sources.

## Important analytical boundary

RedFrameworks can answer:

> What external context is worth reviewing for this domain?

It does **not** automatically answer:

> Which actor is targeting this organization?

or:

> Which campaign explains this internal event?

Those conclusions still require TCE evidence and analytical confidence.

The adapter therefore emits:

~~~json
{
  "review_required": true,
  "auto_merge": false
}
~~~

and each domain-pack enrichment also requires case evidence before actor relevance is promoted.

## RedFrameworks domain packs in TCE

| RedFrameworks pack | TCE lens |
|---|---|
| identity | Identity & Access |
| cloud | Cloud & Multi-Cloud |
| ai-genai | AI / GenAI |
| web-api | Web & API |
| supply-chain | Software Supply Chain |
| purple-detection | Detection & Validation |
| ics-ot | ICS / OT |
| iot-embedded | IoT & Embedded |

RedFrameworks remains the canonical catalog for those external datasets. TCE remains the organization-specific analytical model.

## Why keep the projects separate

RedFrameworks answers broad ecosystem questions:

- what frameworks, tools and standards exist;
- which threat profiles and campaigns are worth knowing;
- which domain packs and defensive mappings are available;
- which research candidates need stronger verification.

TCE answers case-specific questions:

- which crown jewels matter here;
- which architecture and trust relationships exist here;
- which external context is actually relevant here;
- which scenarios deserve priority;
- what telemetry is required;
- which defensive decision is justified by the evidence.

That separation avoids turning a curated catalog into an accidental source of organization-specific claims.
