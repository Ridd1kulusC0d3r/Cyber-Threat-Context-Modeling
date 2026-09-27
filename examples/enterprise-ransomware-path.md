# Example: enterprise ransomware path

This is a **method example**, not an implementation recipe.

## Mission context

Business operations rely on:

- Central identity
- Virtualization or cloud control plane
- Shared file services
- Backup and recovery
- Endpoint management
- Security telemetry

## Crown jewels

1. Privileged identity
2. Recovery infrastructure
3. Business-critical data
4. Security tooling and logging

## Scenario

An adversary obtains an initial foothold, expands identity privileges, reaches centralized administration, impairs recovery or visibility, accesses critical data, and causes business interruption.

## Why the sequence matters

Any one event may be ambiguous. The chain is not.

~~~mermaid
flowchart LR
    A[Initial access] --> B[Credential / identity abuse]
    B --> C[Privilege escalation]
    C --> D[Administrative control plane]
    D --> E[Recovery or visibility impairment]
    E --> F[Critical data access]
    F --> G[Business impact]
~~~

## Detection design

The model should require telemetry that can correlate:

- First-seen or unusual identity use
- Privileged changes
- Administrative actions
- Changes to security or backup configuration
- High-risk access to sensitive data
- Material changes in host or workload behavior

## Defensive outputs

- Identity hardening requirements
- Administrative-tier separation
- Recovery isolation
- Logging integrity requirements
- Correlation use case
- Response decision points
- Validation plan

The exact implementation depends on the environment and must be validated against local telemetry.
