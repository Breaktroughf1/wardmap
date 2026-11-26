# Wardmap: revised plan (one-week launch)

Owner: Noeal Rajeev · Revised: 26 Nov 2026

This replaces the original 9-week plan. It fixes the weaknesses found when the original recommendation was reviewed, and compresses the schedule to **7 days from today to v1.0**. The core engine is already built and tested in this repository (day 0).

## 1. What changed and why

| # | Weakness in the original plan | Fix | Where |
|---|---|---|---|
| 1 | Competition understated. ActionScope (MIT, v0.5.0) already maps the AWS blast radius of named roles. | Positioned explicitly *alongside* zizmor and ActionScope. Wardmap's distinct core is **attacker-mintable** tokens (any role reachable, not only the one a workflow names), three clouds, environments and branch protection, baseline gate, and hunt. | `README.md`, `docs/positioning.md` |
| 2 | Self-serving scoring (Gap 4, Fit 5) | Re-scored honestly below. Wardmap still wins, 30 to 26. | §3 |
| 3 | Over-scoped 8-week plan; Azure/GCP planned in holiday weeks | All three clouds use **offline import** of the providers' own CLI output: JSON parsing instead of three cloud SDKs. That cut most of the cloud work, so v1.0 ships in a week. | `internal/importer` |
| 4 | OIDC `sub` prediction was the unsized hard part | Built first, with an explicit threat model and test vectors. Verdicts have three states, so unknown is never reported as safe. Covers custom subject templates, protected-branch exclusions, auto-created environments and the external-repo probe. | `internal/oidc`, `docs/threat-model.md` |
| 5 | Hunt's news window was closing; it missed the main cloud evidence | `hunt` ships on day 0. It includes CloudTrail import and **OIDC sessions from deleted branches** (the throwaway-branch signal) alongside run-number gaps. | `internal/hunt` |
| 6 | Asking for admin tokens after a token-theft wave | The Action defaults to **offline** with no token. Live mode is documented for a GitHub App or fine-grained read-only token. Missing access becomes a visible collection gap, never "safe". Only GET requests, which a test asserts. | `action.yml`, `docs/permissions.md` |
| 7 | Missed the SME reality of static cloud keys | WM011 flags stored cloud keys and non-OIDC cloud logins. | `internal/analysis` |
| 8 | Launch numbers at risk of overclaiming | Messaging rules: "probed 61,764"; execution counts quoted as ranges with sources. | `docs/positioning.md` |
| 9 | DPDP follow-on timing and competition | See §5. | §5 |
| 10 | Name not verified | `wardmap` is free on npm and PyPI. The 17 same-named GitHub repos have 0 stars and are unrelated. Avoid `reachgate` and `blastgraph` (both used by security tools). A trademark search is still to do (day 1). | §4 |

## 2. One-week plan

Today is day 0 (Thu 26 Nov 2026). The launch is day 6 (Wed 2 Dec), avoiding a Friday or weekend launch.

| Day | Date | Deliverable | Done when |
|---|---|---|---|
| 0 | Thu 26 Nov | Core engine, 18 rules, SARIF, baseline, hunt, rotate-plan, Action, CI, release pipeline, demo estate, docs | `make lint test` green; demo reproduces every finding (**done**) |
| 1 | Fri 27 Nov | **Live validation.** Run `collect --hunt` against your own org plus 2–3 design-partner orgs. Fix collector edge cases (pagination, 403 handling, rulesets). Trademark and name check. Make the repository public behind a "pre-release" banner. | Three real orgs scanned; no crash; every gap explained |
| 2 | Sat 28 Nov | **Hunt hardening.** Re-verify each IOC against the primary sources (Aikido, GitGuardian, StepSecurity, Endor). Add an Entra audit-log import for `wfx-ci-*` creation events. Publish IOC packs `2026.11.28`. | Each indicator cites a primary source |
| 3 | Sun 29 Nov | Buffer, plus a 2-minute demo recording and screenshots (demo estate only; no client data) | — |
| 4 | Mon 30 Nov | Tag **v0.9.0** to prove the release pipeline (attestations, checksums). Draft the Marketplace listing. Give design partners the Action. | `gh attestation verify` passes on the release assets |
| 5 | Tue 1 Dec | **Launch content.** Blog post "wfx-loot didn't need a GitHub bug — it needed your defaults", with anonymised design-partner aggregates. Pre-brief 3–5 researchers and maintainers (zizmor, ActionScope, OpenSSF). | Post reviewed by one external person |
| 6 | Wed 2 Dec | **v1.0.0 launch**: Show HN (morning US Eastern), r/devops, r/netsec, LinkedIn, OpenSSF Slack, Indian developer communities. Announce the fixed-price "CI-to-cloud trust review" offer. | — |
| 7 | Thu 3 Dec | Triage issues and pull requests; ship v1.0.1 with fixes; thank contributors | All issues labelled within 24 hours |

**Scope for v1.0 is frozen at day 0's feature set.** Anything new goes to v1.1:

- Terraform plan input
- Rulesets API for branch-creation restrictions
- GCP service-account binding evaluation
- Ingesting zizmor SARIF into one report
- Following reusable workflows across repositories
- GitLab support

## 3. Honest re-scoring

| Candidate | Urgency | Gap vs OSS | Fit | 1-week feasibility | Visibility | Business value | Synergy | **Total /35** |
|---|---|---|---|---|---|---|---|---|
| **Wardmap** | 5 | **3** (ActionScope, zizmor) | **4** (CI/cloud, not AI) | 5 (built) | 5 | 4 | 4 | **30** |
| DPDP data-map scanner | 4 | 3 | 4 | 2 | 3 | 5 | 3 | 24 |
| Agent credential proxy | 4 | 2 | 5 | 1 | 4 | 3 | 4 | 23 |

Even with the stricter scores, Wardmap leads by 6 points.

## 4. Name

| Name | Status (26 Nov 2026) | Decision |
|---|---|---|
| wardmap | npm: free · PyPI: free · GitHub: 17 repos, all 0 stars, unrelated | **Use** (trademark search day 1) |
| reachgate | 3 repos, one a reachability-triage security gate | Avoid |
| blastgraph | Two existing cloud-IAM "blastgraph" tools | Avoid |

## 5. Project #4 (DPDP), adjusted

- **Product:** a language-agnostic data-map plus Rule 6 safeguards-evidence scanner. Interoperate with dpdp-kit and dpdpkit rather than competing with them.
- **Competition the original missed:** general PII and data-discovery tools (Presidio-based scanners, piicatcher, DataHub classifiers). The differentiation must be DPDP-specific evidence (ROPA, Rule 6 artefacts, and the 72-hour DPDP and 6-hour CERT-In breach clocks), not PII detection.
- **Timing:** alpha with design partners in **Jan–Feb 2027**, and v1.0 by mid-March, two months before 13 May 2027. Compliance buyers procure early; a launch six weeks out is too late.
- **Urgency caveat:** the Data Protection Board is not yet functional, so enforcement may lag the commencement date. Sell it as readiness evidence, not as a way to avoid penalties.
- Ship it with a prominent "not legal advice" notice. Re-verify all dates on egazette.gov.in.

## 6. Risks

| Risk | Mitigation |
|---|---|
| A false negative in trust evaluation | Three-state verdicts, test vectors, fuzzing; false negatives treated as security bugs (SECURITY.md) |
| GitHub ships scoped secrets (roadmap item) | That narrows WM002 but not the cloud-trust join; Wardmap then reports the new scoping |
| Incumbents extend scope | Own the attacker-mintable model, the IOC packs and the baseline UX; contribute upstream where overlapping |
| A clean report read as "no compromise" | Disclaimers in the report, the hunt output, the README and SECURITY.md |
| Snapshots leaking estate structure | Default names are gitignored; docs say to treat snapshots as internal |
