# Reference Cases

TCE v0.4 includes executable defensive reference cases that prove the method across different threat contexts.

| Case | Primary context | Defensive focus |
|---|---|---|
| enterprise-identity | Identity & Access | privileged identity trust and control-plane change |
| cloud-control-plane | Cloud & Multi-Cloud | control-plane administration and policy change |
| software-supply-chain | Software Supply Chain | source/dependency context and release integrity |
| ai-agent-enterprise | AI / GenAI | agent authority, tool use and sensitive connectors |
| critical-saas-third-party | Third-Party & SaaS Trust | delegated administration and critical configuration |
| ics-ot-resilience | ICS / OT | engineering access, control changes and resilient operations |

Every v0.4 reference case contains:

- mission and case context;
- crown jewel;
- architecture node;
- Threat Context;
- prioritized scenario;
- Telemetry Contract;
- Detection Specification;
- safe log-replay fixture;
- deterministic Validation object.

Validate a case:

    tce validate examples/reference-cases/cloud-control-plane

Run its defensive fixture:

    tce validation-run examples/reference-cases/cloud-control-plane VAL-CLOUD

These cases are examples of modeling and defensive validation, not operational attack instructions.
