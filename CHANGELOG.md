# Changelog

## v1.0.0 — 2026-11-26

First stable release.

### Stability promises (until v2)

- Snapshot schema version 1 stays readable; new fields are additive.
- Rule IDs `WM001`–`WM019` keep their meaning, and SARIF `partialFingerprints` stay stable, so baselines and code-scanning alerts carry over.
- CLI exit codes: `0` ok, `1` threshold exceeded or new reach, `2` error.
- IOC packs keep shipping as data, with a version per pack.

### Fixed and added after the first real-organisation scan

Running v0.9.0 against a 33-repository organisation found these gaps:

- **New rule WM019:** GitHub personal access tokens stored as Actions secrets (for example `*_SYNC_PAT`, `GHCR_PAT`) are flagged. Whoever can read one can act as its owner on every repository it reaches.
- WM011 also flags server SSH private keys stored as secrets (for example `EC2_SSH_KEY`).
- Workflow files that the contents API does not inline (large files) are now fetched raw instead of being reported as unparsable. Parse errors now say whether a file was empty or the wrong shape.
- Empty repositories no longer produce a collection gap or a branch-protection notice.
- The hunt's commit sampling limit is worded as a sampling limit, not a permission gap, and can be raised with `--max-commit-files`.

### Added since v0.9.0

- Launch kit in `docs/launch/`: release checklist, Marketplace listing, blog post, launch posts, pre-brief messages and the CI-to-cloud trust review one-pager.
- Issue templates for bugs, false positives and IOC pack updates. Security issues and false negatives go to private vulnerability reporting.
- Release v0.9.0 verified end to end: `gh attestation verify` passes on the published binaries.
- Preliminary name check recorded in `docs/launch/name-check.md`.

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
