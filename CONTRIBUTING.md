# Contributing

Contributions are welcome when they improve rigor, reproducibility, defensive usefulness, or source quality.

## Good contributions

- Primary-source references
- New methodology comparisons
- Better templates
- Defensive detection patterns
- Telemetry modeling
- Threat-model examples
- Attack Flow examples
- Cloud, identity, SaaS or OT adaptations
- Corrections and deprecations

## Public-data requirement

Everything committed to this repository must be safe for unrestricted public disclosure.

Examples and fixtures must be synthetic. Do not copy names, email addresses, internal hostnames, private IPs, tenant/account identifiers, screenshots, logs, case excerpts, notebook proxy URLs, agent/session URLs, signed links, or other organization-specific material from a real environment.

When an example needs realistic-looking values, use reserved documentation domains and address ranges. Keep real case material outside the repository.

Before submitting:

~~~bash
python scripts/check_public_repo_hygiene.py
~~~

The scanner is intentionally conservative. If it blocks a legitimate public value, replace it with a reserved example where possible rather than weakening the rule. Humans have a remarkable talent for turning "temporary exceptions" into permanent archaeology.

## Resource submissions

For every external resource, include:

- Title
- URL
- Category
- Why it is useful
- Whether it is primary or secondary
- Last-checked date when practical

Avoid link dumping. A curated repository is useful because someone did the filtering. Humanity has already produced enough bookmarks.

## Method changes

Changes to the TCE method should explain:

1. What problem the change solves.
2. Which artifact or phase it affects.
3. How it improves repeatability or decision quality.
4. Whether it changes scoring or compatibility.
5. A worked example when appropriate.

## Defensive scope

Examples and validation guidance should remain focused on defensive security and authorized testing.
