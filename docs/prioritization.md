# TCE Prioritization Model

The default scoring model is intentionally simple enough for workshops and structured enough to automate later.

## Priority dimensions

Score each dimension from **0 to 5**.

| Dimension | Weight | Question |
|---|---:|---|
| Crown-jewel criticality | 25% | How severe is compromise of the target to mission/business? |
| Threat relevance | 20% | How aligned is the scenario with relevant actors, campaigns, sector patterns, or observed behaviors? |
| Attack-path feasibility | 15% | How realistic are the required preconditions and sequence? |
| Exposure | 15% | How reachable or exposed are the required components and trust paths? |
| Control weakness | 10% | How limited are preventive or constraining controls? |
| Detection gap | 15% | How likely is the sequence to proceed without timely detection? |

## Formula

**TCE Priority = 0.25C + 0.20R + 0.15F + 0.15E + 0.10W + 0.15D**

Where each variable is scored from 0–5.

## Suggested bands

| Score | Band | Meaning |
|---:|---|---|
| 4.25–5.00 | P0 | Immediate engineering / leadership attention |
| 3.50–4.24 | P1 | High-priority backlog |
| 2.50–3.49 | P2 | Planned treatment / monitoring |
| 0.00–2.49 | P3 | Track, document assumptions, revisit on change |

Do not use the number as a substitute for analyst judgment. Record the rationale.

## Confidence is separate

Score confidence independently:

| Level | Description |
|---|---|
| High | Multiple reliable sources or strong internal evidence support the specific hypothesis |
| Medium | Some reliable evidence plus reasonable inference |
| Low | Primarily theoretical, weak evidence, or important unresolved assumptions |
| Unknown | Evidence has not been collected or cannot be assessed |

## Theory × evidence matrix

| | Low evidence | Medium evidence | Strong evidence |
|---|---|---|---|
| Strong theory | Important hypothesis; validate | High analytical interest | Strong candidate |
| Medium theory | Explore assumptions | Candidate | Strong candidate |
| Weak theory | Track | Evidence-led anomaly | Investigate why evidence is strong |

The matrix is a thinking aid, not a replacement for the priority score.
