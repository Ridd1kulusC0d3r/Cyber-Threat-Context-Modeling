# TCEM Specification 1.0 — Draft

Status: **working draft**

This document defines the intended stable analytical contract for **Threat Context Engineering Method (TCEM)**, the formal method within the broader **Threat Context Engineering (TCE)** discipline.

## 1. Purpose

TCEM is a threat-informed intelligence and defensive-engineering method for connecting mission, crown jewels, architecture, threat context, evidence, behavior, telemetry, detection, validation and decisions in one auditable model.

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
| Detection Specification | DSP- | yes for detection conformance |
| Validation | VAL- | yes for validation conformance |
| Intelligence Gap | GAP- | recommended |
| Decision | DEC- | recommended |
| Environment State | ENV- | TCEM-Horizon extension |
| Preemptive Action | PA- | TCEM-Horizon extension |

## 5. Conformance levels

### TCEM-Core
A conforming case SHALL contain mission context, at least one crown jewel, Threat Context, architecture and a prioritized threat scenario.

### TCEM-Detection
TCEM-Core plus a Telemetry Contract and Detection Specification linked to the scenario.

### TCEM-Validated
TCEM-Detection plus at least one reproducible Validation object with expected versus observed evidence.

### TCEM-Operational
TCEM-Validated plus managed gaps, Decision Trace, ownership, review dates and historical snapshots sufficient to identify drift.

## 6. TCEM Detection

**TCEM Detection** is the telemetry and detection-engineering domain of the method. It binds modeled behavior to ATT&CK Detection Strategies, Analytics, Data Components, enterprise telemetry, analytic hypotheses, correlation and validation.

A Detection Specification is platform-neutral. Platform implementations such as Sigma, Microsoft Sentinel, Splunk or Elastic are representations of the specification, not replacements for it.

## 7. Evidence boundary

Observed internal evidence, external intelligence, analyst inference, assumptions and unknowns SHOULD remain distinguishable. External intelligence SHALL NOT automatically create organization-specific attribution.

## 8. TCEM Operational Matrix

A conforming operational implementation SHOULD expose the multidimensional relationship among Threat Context, ATT&CK behavior, observability, TCEM Detection, defensive controls, validation, Decision Trace and drift.

The **TCEM Operational Matrix** is the normative operating view for this relationship.

## 9. Historical reproducibility

An operational implementation SHOULD be able to snapshot the model and compare snapshots for entity, priority, coverage, telemetry and validation drift.

## 10. AI boundary

AI MAY assist entity extraction, hypothesis generation, summarization, mapping and gap discovery. AI SHALL NOT silently alter evidence or automatically promote candidate intelligence into confirmed case facts.

## 11. Security boundary

TCEM is designed for defensive architecture, detection engineering, threat intelligence and authorized validation. Conformance does not require command-level adversary execution procedures.

## 12. TCEM-Horizon extension

TCEM-Horizon is an optional enterprise extension for predictive and preemptive defensive analysis. It SHALL preserve the TCEM evidence boundary and SHALL NOT treat machine-generated forecast pressure as attack probability or accepted analyst judgment.

## 13. Draft stabilization work

Before final 1.0:

- freeze core schemas;
- publish conformance fixtures;
- publish version migration rules;
- publish a formal glossary;
- define extension rules;
- validate the model against the reference-case suite;
- produce a machine-readable conformance manifest.
