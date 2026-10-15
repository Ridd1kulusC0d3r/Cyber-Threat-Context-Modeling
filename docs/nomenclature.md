# TCEM naming and architecture

The project uses a deliberate two-level naming model.

| Name | Role | What it means |
|---|---|---|
| **Threat Context Engineering — TCE** | Discipline / umbrella concept | The broader practice of engineering defensive decisions from mission, threat context, evidence, environment, observability and change over time. |
| **Threat Context Engineering Method — TCEM** | Formal method | The auditable method implemented by this repository. |
| **TCEM Detection** | Telemetry + detection engineering | The domain that turns modeled behavior into observability requirements, Detection Specifications, correlation, coverage and validation. |
| **TCEM Operational Matrix** | Continuous operational model | The multidimensional visual layer connecting Decision Trace, drift, context, MITRE ATT&CK, observability, defensive options and operating state. |
| **TCEM Specification 1.0** | Formal specification | The normative contract for objects, conformance, evidence boundaries and extension rules. |

## Why TCE and TCEM both remain

**TCE** names the discipline.

**TCEM** names one formal method for practicing that discipline.

~~~text
Threat Context Engineering (TCE)
│
└── Threat Context Engineering Method (TCEM)
    ├── TCEM Detection
    ├── TCEM Operational Matrix
    ├── TCEM Horizon
    └── TCEM Specification 1.0
~~~

## Compatibility names

The Python implementation keeps the internal package namespace `tce` for backward compatibility.

The preferred CLI is:

~~~bash
tcem --help
~~~

The existing `tce` command remains an alias during the pre-1.0 transition.

Object prefixes such as `CASE-`, `CTX-`, `DSP-`, `ENV-` and `PA-` do not change merely because the method name was formalized.
