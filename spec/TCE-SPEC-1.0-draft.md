# Threat Context Engineering Specification 1.0 — Draft

Status: **working draft**

This document defines the intended stable analytical contract for Threat Context Engineering. It is not yet a final 1.0 release.

## 1. Purpose

TCE is a threat-informed intelligence and defensive-engineering method for connecting mission, crown jewels, architecture, threat context, evidence, behavior, telemetry, detection, validation and decisions in one auditable model.

## 2. Core principles

1. Business impact precedes technique count.
2. Threat context is explicit and time-bounded.
3. External intelligence is candidate context until relevance is supported by case evidence.
4. Priority and analytical confidence are independent.
5. Telemetry is a security requirement.
6. Detection is specified before platform syntax.
7. Validation must generate reproducible evidence.
8. Unknowns and contradictions are preserved.
9. Decisions must be traceable to the analytical chain.
10. AI output is advisory and cannot silently mutate evidence.

## 3. Required analytical chain

~~~text
Mission
  -> Crown Jewel
  -> Threat Context
  -> Architecture / Trust
  -> Evidence / Hypothesis
  -> Attack Path
  -> Telemetry Contract
  -> Detection Specification
  -> Validation
  -> Decision / Gap
~~~

Not every case requires actor attribution, campaign attribution, AI assistance, OpenCTI or RedFrameworks enrichment.

## 4. First-class object namespaces

| Object | Prefix | Required for core conformance |
|---|---|---|
| Case | CASE- | yes |
| Intelligence Requirement | IR- | recommended |
| Crown Jewel | CJ- | yes |
| Threat Context | CTX- | yes |
| Architecture | ARCH- | yes |
| Evidence | EV- | recommended |
| Threat Hypothesis | TH- | recommended |
| Threat Scenario | TS- | yes |
| Telemetry Contract | TC- | yes |
| Detection Use Case | DU- | compatible legacy object |
| Detection Specification | DSP- | yes for detection conformance |
| Validation | VAL- | yes for validation conformance |
| Intelligence Gap | GAP- | recommended |
| Decision | DEC- | recommended |

## 5. Conformance levels

### TCE-Core

A conforming case SHALL contain a mission, at least one crown jewel, one Threat Context, architecture, and one prioritized threat scenario.

### TCE-Detection

TCE-Core plus a Telemetry Contract and Detection Specification linked to the scenario.

### TCE-Validated

TCE-Detection plus at least one reproducible Validation object with evidence of expected versus observed behavior.

### TCE-Operational

TCE-Validated plus managed gaps, decision trace, ownership, review dates and historical snapshots sufficient to identify drift.

## 6. Detection Specification

A Detection Specification is platform-neutral. It SHALL identify its scenarios and telemetry dependencies. It SHOULD define an analytic concept, correlation pattern, benign alternatives, implementations and validation references.

Platform implementations such as Sigma, Microsoft Sentinel, Splunk or Elastic are representations of the specification, not replacements for it.

## 7. Evidence boundary

Observed internal evidence, external intelligence, analyst inference, assumptions and unknowns SHOULD remain distinguishable.

External intelligence SHALL NOT automatically create organization-specific attribution.

## 8. Historical reproducibility

An operational implementation SHOULD be able to snapshot the model and compare snapshots for entity, priority, coverage, telemetry and validation drift.

## 9. AI boundary

AI MAY assist entity extraction, hypothesis generation, summarization, mapping and gap discovery.

AI SHALL NOT silently alter immutable evidence or automatically promote candidate intelligence into confirmed case facts.

## 10. Security boundary

TCE is designed for defensive architecture, detection engineering, threat intelligence and authorized validation. A conforming implementation does not require command-level adversary execution procedures.

## 11. Draft stabilization work

Before final 1.0:

- freeze core schemas;
- publish conformance fixtures;
- version migration rules;
- publish a formal glossary;
- define extension rules;
- validate the model against the reference-case suite;
- produce a machine-readable conformance manifest.
