# TCE Context Model

Threat Context Engineering works best when the analysis is treated as a connected model rather than a stack of documents.

## Core entities

~~~mermaid
flowchart LR
    M[Mission] --> P[Critical Process]
    P --> CJ[Crown Jewel]
    CJ --> A[Architecture Node]
    A --> TB[Trust Boundary]

    TI[Threat Intelligence] --> TH[Threat Hypothesis]
    TA[Threat Actor / Campaign] --> TH
    TH --> AP[Attack Path]
    AP --> TTP[ATT&CK Behavior]
    AP --> CJ

    TTP --> CTRL[Control / Countermeasure]
    TTP --> OBS[Observable]
    OBS --> TEL[Telemetry Contract]
    TEL --> DET[Detection Hypothesis]
    DET --> AN[Analytic / Correlation]
    AN --> UC[Use Case / Case]
    UC --> VAL[Validation Evidence]
    VAL --> GAP[Gap / Residual Risk]
    GAP --> TH
~~~

## Why a graph matters

A list of techniques cannot answer which business process is endangered.

A list of crown jewels cannot answer how an adversary reaches them.

A list of controls cannot prove an attack path is observable.

The model becomes useful when relationships are explicit.

## Minimum relationships

A mature implementation should be able to answer queries such as:

- Which crown jewels support this mission?
- Which architecture nodes expose or administer those crown jewels?
- Which attack paths cross the most important trust boundaries?
- Which ATT&CK behaviors appear in those paths?
- Which paths have weak controls?
- Which behaviors require telemetry that does not exist?
- Which detection hypotheses have never been validated?
- Which high-priority scenarios depend on low-confidence CTI?
- Which controls reduce several high-priority attack paths at once?
- Which new threat report changes an existing scenario?

## Evidence lineage

Every threat claim should be traceable to one of:

- Internal observation
- External primary source
- External secondary source
- Analyst inference
- Assumption
- Unknown

The model should preserve the distinction. Otherwise confidence becomes decorative arithmetic.

## Time

Threat context decays.

Record timestamps for:

- Evidence collection
- Last architecture validation
- Last telemetry validation
- Last detection test
- Last scenario review
- Next review trigger

TCE should be able to show not only what is covered, but **when that belief was last tested**.
