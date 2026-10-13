# Threat Context Engineering

**Threat Context Engineering (TCE)** is a threat-informed defense method that turns organizational context and threat intelligence into defensive engineering decisions.

The method is built around a simple premise:

> A useful threat model must eventually change architecture, telemetry, detections, validation, or risk decisions.

## The four inherited questions

TCE keeps the four questions popularized by the Threat Modeling Manifesto:

1. What are we working on?
2. What can go wrong?
3. What are we going to do about it?
4. Did we do a good enough job?

It extends them with operational sub-questions:

- What is mission-critical?
- Which assets are crown jewels?
- Which adversaries and behaviors are relevant?
- Which enterprise exposure paths are plausible or becoming more defensively urgent?
- Which controls alter those paths?
- Which events must exist for those paths to be observable?
- Which detections and correlations prove we can see them?
- How will we validate the assumptions?
- What new CTI would cause us to change the model?

## Core artifacts

A complete TCE assessment should leave behind:

- Mission map
- Crown-jewel register
- Architecture / trust-boundary map
- Threat-context register
- Enterprise Environment State (for Horizon assessments)
- Attack-path or Attack Flow model
- Prioritized scenario backlog
- Defensive-control mapping
- Telemetry contract
- Detection-use-case specification
- Validation evidence
- Detection-by-Absence findings
- Review-gated preemptive-action candidates
- Residual-risk statement
- Review date and owner

Start with the [Methodology](methodology.md).


## TCE Horizon

For enterprise-wide analysis, TCE Horizon adds a time-stamped Environment State and continuously prioritizes review-only paths from modeled exposure points toward crown jewels using architecture, controls, telemetry, vulnerability pressure and accepted threat intelligence.

Horizon forecast pressure is a defensive prioritization signal, not a prediction that a specific attack will occur.

Start with [TCE Horizon](horizon.md) and [Enterprise Environment State](environment-state.md).
