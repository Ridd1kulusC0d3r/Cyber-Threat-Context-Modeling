# Analyst Dashboard

The repository now generates a self-contained HTML dashboard from the same case data used by the CLI.

    tce dashboard examples/cases/enterprise-identity --output dashboard.html

The dashboard focuses attention on:

- number of crown jewels;
- hypotheses;
- attack scenarios by priority band;
- open intelligence, telemetry, detection, and validation gaps;
- detection coverage by dimension;
- top defensive choke points;
- proposed or pending decisions.

The dashboard is intentionally generated from the case files. It is not a separate database, because maintaining two versions of security truth is a remarkably efficient way to create three versions of security truth.
