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

## Colab setup behavior

The notebook setup cell does four things before loading the models:

1. clones the repository if it is absent;
2. refreshes an existing Colab clone to the selected branch, avoiding stale code after a re-run;
3. installs the project in editable mode with the Colab extras;
4. explicitly adds the repository `src/` directory to the live Python kernel and invalidates import caches.

The fourth step is intentional. In a long-lived notebook kernel, a new editable install can rely on a path file that is normally processed only when Python starts. A terminal launches a new interpreter after installation; Colab does not. Explicitly attaching `src/` makes the notebook immediately importable without a runtime restart.

After setup, the notebook prints the TCE version and the exact imported module path. If that check fails, stop there rather than continuing into model loading.

## Defaults

- `TCE_AI_GLINER=1`
- `TCE_AI_QWEN=1`
- GLiNER: `urchade/gliner_medium-v2.1`
- Qwen: automatic hardware profile
  - larger Colab GPU: `Qwen/Qwen3-4B`
  - smaller GPU: `Qwen/Qwen3-1.7B`
  - CPU fallback: `Qwen/Qwen3-0.6B`
- Qwen uses 4-bit loading on CUDA by default when supported.

You can override `TCE_GLINER_MODEL`, `TCE_QWEN_MODEL` and `TCE_QWEN_4BIT`.

## Roles

**GLiNER** proposes entities: threat actors, campaigns, malware, tools, vulnerabilities, organizations, technologies, identities, assets, controls, techniques and data sources.

**Qwen** receives the immutable Evidence Packet plus entity candidates and proposes hypotheses, alternative explanations, intelligence gaps and candidate ATT&CK mappings.

AI results remain a review queue. Candidate ATT&CK IDs are checked against the deterministic ATT&CK index before operational use.

## Notebook

Use `colab/TCE_v0_3_AI_Knowledge_Graph.ipynb`.

The notebook checks hardware, installs TCE, verifies the live-kernel import, loads both models, synchronizes ATT&CK and D3FEND, builds the graph, runs the AI pipeline, exports Attack Flow, Navigator and STIX, and provides an optional reviewed OpenCTI import step.

OpenCTI transfer is not automatic.
