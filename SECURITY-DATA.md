# Public repository data-safety policy

This repository is a public, vendor-neutral defensive threat-modeling toolkit. All committed examples must be synthetic and explicitly marked as such. Do not commit customer names, employer names, real organizational domains, IP inventories, identity-provider tenant IDs, credentials, internal topology, production logs, ticket references, unpublished incident details, or customer-specific assessments.

Keep real cases outside the repository and point `TCE_CASES_DIR` at a private location. Sanitization must happen **before** copying anything into a public example. Use fictional organization names, reserved example domains (`example.com`, `example.org`, `example.net`), and documentation-only IP addresses. Never substitute a pseudonym while preserving a uniquely identifying topology.

A CI content guard rejects known organization references, credential patterns, and risky internal-data indicators in committed text. It is a defense in depth measure, not proof of confidentiality. Review diffs, notebooks, fixtures, generated reports, archives, images, commit metadata, PR discussions, and published Actions artifacts manually.

If a real secret or confidential item was previously committed, deleting it in a new commit is **not enough**: revoke/rotate affected credentials, assess disclosure, and coordinate history rewrite or GitHub support as appropriate. GitHub forks, caches and clones may retain prior versions.

Report potential exposures privately using the process in SECURITY.md. Do not paste the suspected secret into an issue or pull request.
