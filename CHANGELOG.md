# Changelog

## v0.9.0 — 2026-11-26

First public pre-release, cut to prove the release pipeline (signed build provenance, checksums) before v1.0.0.

### Fixed after a live GitHub run

- Collection gaps were listed twice and gap messages ended with a doubled full stop; an empty blast-radius section now says so.
- `*` in ARNs and trust policies no longer turns into Markdown emphasis; IOC pack versions are no longer autolinked as e-mail addresses.
- `go install …@vX.Y.Z` builds report the module version.

### IOC packs 2026.11.26.2

- Re-checked every indicator against public reporting; each now records `sources` and a `verified` level, and single-source indicators are listed in the pack headers. The primary-source check is still pending (original posts were unreachable from the build environment).
- wfx-loot: added the probe file `docs/wfx-audit.md`, delivery branches `ci-check-NNNN` and `chore/XXXXXXXX`, commit messages `chore: add ci helper`, `chore: add dependency audit workflow` and `ci: cleanup`; tightened `build-audit-??????.yml`; window now starts at 12:45 UTC on 10 Nov 2026; added AWS session `wfx-*` follow-ups (trust rewrites, access keys) and Entra audit detection. The base payload SHA-256 is recorded in the pack.
- GhostAction: added `github_actions_security.yml`, the "Add/Update Github Actions Security workflow" commit messages and the reported exfiltration IPs; **removed** `audit.yml` and `ci-check.yml`, which no source supports; window set to 31 Aug–31 Oct 2026.
- New indicator types: `workflow_endpoint`, `workflow_secrets_dump`, `cloudtrail_session_name`, `cloudtrail_event`, `azure_audit_fic_name`.
- Packs are validated on load: unknown types, missing patterns, duplicate ids and bad confidence values are errors.
- `import --azure-audit` reads Entra directory audit logs; `--cloudtrail` now also keeps IAM persistence events (`UpdateAssumeRolePolicy`, `CreateAccessKey`, …) and role-session names.

### Initial feature set

- `collect`: read-only GitHub collector (secrets, org secret visibility, environments, reviewers, branch policies, branch protection, OIDC subject template, workflows; `--hunt` adds PRs, commits with file lists, and runs).
- `local`: offline workflow-only snapshot.
- `import`: AWS (`list-roles` / `get-account-authorization-details`, URL-encoded or decoded), Azure federated credentials (including flexible expressions), GCP providers, CloudTrail `AssumeRoleWithWebIdentity`.
- OIDC engine: attacker-mintable candidates (unprotected branches, tags, auto-created environments, same-repo PRs, external repositories); three-state verdicts; custom subject templates.
- 18 rules; Markdown, JSON, SARIF 2.1.0, Mermaid and DOT output; stable fingerprints.
- `baseline` and `scan --baseline` drift gate.
- `hunt` with versioned IOC packs for wfx-loot and GhostAction, run-number gaps, and OIDC sessions from deleted branches.
- `rotate-plan` ordered rotation runbook.
- Composite GitHub Action (offline by default), CI with race tests, coverage gate and fuzzing; release pipeline with build-provenance attestations.
