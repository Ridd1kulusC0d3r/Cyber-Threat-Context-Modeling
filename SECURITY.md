# Security Policy

## Reporting a repository security issue

If you identify a vulnerability in code added to this repository, avoid publishing exploit details in a public issue before maintainers can assess the problem.

For documentation errors, broken links, unsafe examples, or inaccurate mappings, a normal GitHub issue is appropriate.

## Public repository data boundary

This repository is **public-data only**.

Do not commit or paste organization-specific or restricted material, including:

- organization or customer names when they identify a real engagement;
- employee, analyst, customer, or vendor email addresses;
- internal hostnames, domains, tenant IDs, account IDs, device names, ticket IDs, or private URLs;
- RFC1918 addresses copied from a real environment;
- screenshots, architecture diagrams, logs, exports, evidence excerpts, or case files from a real environment;
- non-public temporary access URLs, notebook proxy URLs, agent/session URLs, signed links, or share tokens;
- credentials, API keys, private keys, cookies, bearer tokens, secrets, or connection strings;
- documents classified above public disclosure, including TLP:AMBER, TLP:AMBER+STRICT, or TLP:RED case material.

All committed cases, events, identities, domains, addresses, and evidence must be synthetic or derived exclusively from public sources.

Use reserved example values such as `example.com`, `example.org`, `example.net`, `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` when an example needs network-looking data.

Run:

~~~bash
python scripts/check_public_repo_hygiene.py
~~~

before opening a pull request. CI runs the same check.

## If sensitive data is committed

Treat the event as an exposure, not merely a documentation typo:

1. remove it from the current tree;
2. rotate or invalidate any credential, token, signed link, temporary URL, or session reference;
3. review branches, pull requests, issues, workflow artifacts, Pages output, and release artifacts;
4. determine whether Git history must be rewritten;
5. if a public object must be purged beyond a normal force update, follow GitHub's sensitive-data removal process.

A cleanup commit alone does not erase content from previous Git objects.

## Scope

This project focuses on defensive threat modeling, threat-informed defense, detection engineering, and authorized validation.
