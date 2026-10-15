# Public Repository Data Safety

TCE is designed to work with sensitive enterprise context, which makes repository hygiene part of the threat model rather than an administrative afterthought.

The public repository must contain only:

- source code;
- public-source references;
- synthetic examples and fixtures;
- reserved example domains and network ranges;
- documentation that is safe for unrestricted disclosure.

## Never commit real environment data

Keep the following outside the repository:

- organization/customer names tied to a real assessment;
- personal or business email addresses from an engagement;
- internal domains, hostnames, device names, tenant IDs, cloud account IDs, subscriptions, project IDs, ticket IDs, or case IDs;
- private network addresses copied from a real environment;
- raw logs, SIEM exports, EDR events, screenshots, architecture diagrams, inventories, CMDB exports, vulnerability exports, identity inventories, or evidence excerpts;
- temporary notebook proxy links, agent/session links, signed download links, share URLs, or other non-public references;
- credentials, tokens, API keys, cookies, private keys, certificates containing private material, or connection strings;
- any non-public case document whose handling marking does not permit unrestricted publication.

A value being "only an example" is not enough if it was copied from a real environment.

## Public-safe examples

Prefer reserved values:

| Need | Public-safe example |
|---|---|
| Domain | `example.com`, `example.org`, `example.net` |
| Public-looking IP | `192.0.2.10`, `198.51.100.20`, `203.0.113.30` |
| Email | `analyst@example.com` |
| Organization | `Example Organization` |
| Tenant / account | `TENANT-DEMO-001` |
| Host | `idp-demo-01.example.com` |
| Case | `CASE-DEMO-001` |

Avoid private-looking suffixes such as `.local`, `.internal`, or `.corp` in committed examples. They look like copied internal infrastructure even when invented.

## Automated check

Run:

~~~bash
python scripts/check_public_repo_hygiene.py
~~~

The check detects several classes of accidental disclosure in tracked textual files, including non-example emails, RFC1918 addresses, private-looking domains, local user paths, per-instance Colab proxy URLs, agent/session URLs, private keys, and common token formats.

An optional organization-specific denylist can be supplied outside the repository:

~~~bash
TCE_PUBLIC_REPO_DENYLIST="organization-name,internal-project-name" \
  python scripts/check_public_repo_hygiene.py
~~~

Do not commit the denylist itself.

## Branches and history matter

Removing a value from `main` does not remove it from:

- old branches;
- pull-request refs;
- commit history;
- workflow artifacts;
- releases;
- Pages deployments;
- copied forks or clones.

If sensitive data ever reaches GitHub, rotate/invalidate anything actionable first. Then remove the current references and decide whether history rewrite and GitHub's sensitive-data removal process are required.

## TCE case boundary

Real assessments should live in a separate private working location. The public repository should receive only sanitized, synthetic reproductions when an example is genuinely useful to the method.

The goal is boring by design: a public repository that remains publishable even if somebody reads every file, branch and generated page. A rare luxury in cybersecurity repositories.
