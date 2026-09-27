# Entity Resolution

TCE uses a conservative deterministic entity-resolution layer before external CTI is linked to internal analytical objects.

## Normalization

Names are:

- Unicode-normalized;
- accent-folded;
- lowercased;
- punctuation-normalized;
- whitespace-normalized.

Aliases are included in comparison.

## Decision model

For each incoming entity:

- exact normalized name or alias match: score 1.0;
- otherwise a string-similarity candidate is computed;
- default match threshold: 0.90;
- non-exact matches require analyst review;
- unmatched entities remain new candidates.

The current resolver is intentionally transparent and deterministic. GLiNER and Qwen can help discover or reason about entities, but they do not silently decide identity equivalence.

Future work can add sector, temporal, infrastructure, ATT&CK and provenance features without sacrificing the review boundary.
