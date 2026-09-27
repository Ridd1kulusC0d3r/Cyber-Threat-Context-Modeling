# Colab AI Workbench

TCE v0.3 includes a Google Colab profile with **GLiNER ON by default** and **Qwen ON by default**.

## Runtime policy

~~~mermaid
flowchart LR
    S[Source Text] --> P[Immutable Evidence Packet]
    P --> G[GLiNER Entity Candidates]
    P --> Q[Qwen Analytical Candidates]
    G --> R[Analyst Review Queue]
    Q --> R
    R --> V[Deterministic ATT&CK Validation]
    V --> K[Knowledge Graph]
~~~

The AI layer never silently modifies evidence or writes directly into the case.

## Defaults

- TCE_AI_GLINER=1
- TCE_AI_QWEN=1
- GLiNER: urchade/gliner_medium-v2.1
- Qwen: automatic hardware profile
  - larger Colab GPU: Qwen/Qwen3-4B
  - smaller GPU: Qwen/Qwen3-1.7B
  - CPU fallback: Qwen/Qwen3-0.6B
- Qwen uses 4-bit loading on CUDA by default when supported.

You can override TCE_GLINER_MODEL, TCE_QWEN_MODEL and TCE_QWEN_4BIT.

## Roles

**GLiNER** proposes entities: threat actors, campaigns, malware, tools, vulnerabilities, organizations, technologies, identities, assets, controls, techniques and data sources.

**Qwen** receives the immutable Evidence Packet plus entity candidates and proposes hypotheses, alternative explanations, intelligence gaps and candidate ATT&CK mappings.

AI results remain a review queue. Candidate ATT&CK IDs are checked against the deterministic ATT&CK index before operational use.

## Notebook

Use colab/TCE_v0_3_AI_Knowledge_Graph.ipynb.

The notebook checks hardware, installs TCE, loads both models, synchronizes ATT&CK and D3FEND, builds the graph, runs the AI pipeline, exports Attack Flow, Navigator and STIX, and provides an optional reviewed OpenCTI import step.

OpenCTI transfer is not automatic.
