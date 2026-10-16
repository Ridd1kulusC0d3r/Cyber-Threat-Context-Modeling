# TCEM in practice

TCEM is designed to answer a practical question:

> **What should this organization observe, detect, constrain, validate and decide before a modeled threat path becomes an incident?**

The method is deliberately broader than application threat modeling. The examples below use synthetic or public-source context only and focus on defensive engineering.

## Six practical applicability patterns

<div class="grid cards" markdown>

-   **Identity & privileged trust**

    ---

    **Situation:** a trusted administrative relationship can affect the enterprise identity control plane.

    **TCEM asks:** which privileged paths reach identity crown jewels, which ATT&CK behaviors describe the path, and what must be observable?

    **Output:** Telemetry Contract, ordered-sequence detection, validation evidence and a decision to reduce privilege or close visibility gaps.

    [Open the full case →](../examples/cases/enterprise-identity/)

-   **Cloud control plane**

    ---

    **Situation:** privileged cloud activity is followed by a high-impact organization-wide policy change.

    **ATT&CK:** T1078 + T1098.

    **Output:** cloud audit requirements, correlation by actor, target-context gap and validated detection specification.

    [Open the reference case →](../examples/reference-cases/cloud-control-plane/case.yaml)

-   **Software supply chain**

    ---

    **Situation:** a source or dependency change precedes publication of a trusted release artifact.

    **ATT&CK:** T1195.

    **Output:** CI/CD provenance requirements, pipeline correlation, release-integrity detection and safe log-replay validation.

    [Open the reference case →](../examples/reference-cases/software-supply-chain/case.yaml)

-   **Enterprise AI agent**

    ---

    **Situation:** an agent receives privileged tool authorization and then invokes a sensitive connector.

    **TCEM focus:** machine identity, connector authority, target-resource telemetry and auditable tool use.

    **Output:** agent/tool Telemetry Contract, correlation by agent.id, review-gated detection and validation.

    [Open the reference case →](../examples/reference-cases/ai-agent-enterprise/case.yaml)

-   **Critical SaaS / third party**

    ---

    **Situation:** external or delegated administration is followed by a critical SaaS configuration change.

    **TCEM focus:** trust boundary, delegated role scope, source attribution and target configuration.

    **Output:** external-admin visibility, correlation, evidence requirements and a decision on delegated trust.

    [Open the reference case →](../examples/reference-cases/critical-saas-third-party/case.yaml)

-   **ICS / OT resilience**

    ---

    **Situation:** remote engineering access is followed by a control configuration change.

    **ATT&CK:** T1078 + T1021.

    **Output:** engineering-session telemetry, control-change observability, validation and recovery-oriented decision support.

    [Open the reference case →](../examples/reference-cases/ics-ot-resilience/case.yaml)

</div>

## Worked example: enterprise identity

The full enterprise-identity case shows the intended TCEM chain.

~~~mermaid
flowchart LR
    M["Mission: trusted enterprise authentication"] --> CJ["Crown Jewel: identity control plane"]
    CJ --> C["Threat Context: identity + third-party + recovery"]
    C --> P["Path: privileged SaaS administration → identity change"]
    P --> A["ATT&CK: T1078 → T1098"]
    A --> T["Telemetry Contract: actor, source, target, action, time"]
    T --> G["Gap: target.resource is not consistently present"]
    G --> D["TCEM Detection: privileged context → identity-control modification"]
    D --> V["Safe log-replay validation"]
    V --> DEC["Decision: strengthen authentication, scope and target telemetry"]
~~~

### 1. Start from the mission

The case does not begin with a technique list. It begins with a mission:

> Preserve trusted enterprise authentication and recoverability.

The identity control plane becomes the crown jewel because compromise there can create organization-wide impact.

### 2. Model context, not just components

Three contexts are explicit:

- enterprise identity and privileged trust;
- third-party / SaaS administrative trust;
- identity resilience and recovery.

That prevents the scenario from collapsing into a generic T1078 heatmap.

### 3. Describe the plausible path

The accepted scenario models a high-level defensive sequence:

~~~text
trusted privileged administration
        ↓
use of privileged identity/session
        ↓
identity configuration change
        ↓
enterprise identity impact
~~~

ATT&CK provides the behavior vocabulary. The architecture and evidence explain why that behavior matters **here**.

### 4. Design visibility before writing a rule

The Telemetry Contract requires:

~~~text
user.id
source.ip
target.resource
action
timestamp
~~~

The case records that target.resource is not consistently available.

That becomes an engineering gap rather than an unpleasant surprise during incident response.

### 5. Turn the scenario into TCEM Detection

The Detection Specification models an ordered correlation:

~~~text
privileged administrative context
        ↓ same administrator / bounded window
high-impact identity configuration change
~~~

It also records benign alternatives and required context. Platform syntax is secondary to the analytic idea.

### 6. Validate safely

The repository uses defensive event fixtures and log replay. No command-level adversary procedure is required.

~~~bash
tcem validation-run examples/cases/enterprise-identity VAL-001
~~~

### 7. Produce a decision, not another diagram

The case ends with a reviewable defensive decision:

- strengthen privileged authentication;
- reduce administrative scope;
- complete target-resource telemetry;
- preserve recovery paths;
- keep the remaining intelligence gap managed.

That is the TCEM definition of useful threat modeling: the model changes engineering work.

## Practical workflows

### Architecture / security design review

Use TCEM when a new cloud, SaaS, identity, AI or OT capability is being designed.

~~~text
Architecture
→ crown jewels
→ trust boundaries
→ threat contexts
→ plausible paths
→ required controls
→ required telemetry
→ acceptance decision
~~~

### CTI-to-engineering

Use TCEM when threat intelligence needs to become local defensive work.

~~~text
CTI report
→ evidence candidate
→ local relevance review
→ Threat Context
→ ATT&CK behavior
→ affected enterprise path
→ telemetry / detection impact
→ decision or managed gap
~~~

External intelligence remains candidate context until the organization-specific relevance is supported.

### Detection engineering

Use TCEM before starting with SIEM syntax.

~~~text
Scenario
→ observable effect
→ ATT&CK Detection Strategy / Data Components
→ enterprise Telemetry Contract
→ Detection Specification
→ implementation
→ validation
~~~

### Continuous threat landscape review

Use TCEM Operational Matrix + Horizon to answer:

- Which crown jewels gained a new high-pressure path?
- Which accepted CTI signal changed the defensive picture?
- Which high-priority path is telemetry-blind?
- Which detection is implemented but not validated?
- Which decision depends on stale or inferred evidence?
- Which shared choke point gives the largest defensive leverage?

## Run the examples

Install the toolkit:

~~~bash
pip install -e .
~~~

Full enterprise case:

~~~bash
tcem validate examples/cases/enterprise-identity
tcem operational-matrix examples/cases/enterprise-identity --offline
tcem detection-backlog examples/cases/enterprise-identity
tcem validation-run examples/cases/enterprise-identity VAL-001
~~~

Compact cloud reference case:

~~~bash
tcem validate examples/reference-cases/cloud-control-plane
tcem validation-run examples/reference-cases/cloud-control-plane VAL-CLOUD
~~~

The reference fixtures are synthetic and designed for defensive validation.
