# Security policy

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** on this repository (Security → Report a vulnerability). Do not open a public issue.

You should receive an acknowledgement within 3 working days. We aim to ship a fix or mitigation for confirmed issues within 30 days, and will credit you unless you ask us not to.

## In scope

- Anything that makes Wardmap issue non-GET requests, read or print secret values, or execute content from scanned repositories.
- **False negatives in trust evaluation:** a reachable cloud identity reported as *not reachable*. We treat these as security bugs. Please include a redacted trust policy and the OIDC claims.
- Supply-chain weaknesses in the Action or the release pipeline.

## Out of scope

- Findings Wardmap reports about *your* estate. Those are the product working.
- IOC pack accuracy. Please open a normal pull request for that.

## Disclaimer

Wardmap is provided without warranty (see LICENSE). It reports exposure and indicators. It is not an incident-response service, and a clean result does not prove the absence of compromise.
