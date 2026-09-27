# Defensive Choke Points

A defensive choke point is an architecture node, trust relationship, identity, or control plane that appears across multiple important attack paths.

If five high-priority paths converge on the same identity provider, reducing risk there may have more defensive value than five unrelated downstream controls.

The CLI counts architecture nodes referenced by P0/P1 scenario steps:

    tce chokepoints examples/cases/enterprise-identity

Frequency is a starting point. Analysts should also consider blast radius, privilege concentration, control maturity, and recoverability.
