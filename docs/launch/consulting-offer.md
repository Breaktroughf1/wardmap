# Offer: CI-to-cloud trust review (fixed scope)

*One-pager for Breaktrough's sales conversations. Price and terms are a business decision and are left blank on purpose.*

## Who it is for

Indian SaaS, fintech and IT-services teams (5–200 engineers) that deploy from GitHub Actions to AWS, Azure or GCP, especially any team that saw wfx-loot or GhostAction activity in November 2026.

## What the client gets

| Deliverable | Detail |
|---|---|
| Reach map | Wardmap scan of the GitHub organisation plus cloud trust exports: which secrets and cloud roles one compromised write credential reaches, per repository |
| Compromise check | `wardmap hunt` against GitHub, CloudTrail and Entra audit exports for wfx-loot and GhostAction indicators, with each hit reviewed by a person |
| Fix plan | A prioritised remediation list: trust policies rewritten to protected refs or gated environments, environment reviewers, org secret visibility, static cloud keys moved to OIDC |
| Rotation runbook | Ordered runbook (`rotate-plan`) if anything was reachable during a campaign window |
| CI gate | Wardmap Action with an approved baseline, so new reach fails pull requests |
| Read-out | A 60-minute session with engineering leads, plus a written report |

## How we work

- **Read-only access only.** A GitHub App or fine-grained token with read permissions, and cloud exports the client runs themselves. We never ask for admin tokens or cloud credentials.
- Snapshots are processed on the client's machine or ours under NDA, and deleted at the end of the engagement.
- **Duration:** [__] working days. **Price:** [__] (fixed). **Optional:** [__] days of remediation support.

## What it is not

- It is not an incident-response retainer, and not a guarantee of no compromise. A clean hunt reduces risk but cannot prove absence.
- It is not legal or compliance advice. DPDP/CERT-In breach notification obligations stay with the client.
