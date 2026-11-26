# Changelog

## Unreleased (v0.9.0 candidate)

- `collect`: read-only GitHub collector (secrets, org secret visibility, environments, reviewers, branch policies, branch protection, OIDC subject template, workflows; `--hunt` adds PRs, commits with file lists, and runs).
- `local`: offline workflow-only snapshot.
- `import`: AWS (`list-roles` / `get-account-authorization-details`, URL-encoded or decoded), Azure federated credentials (including flexible expressions), GCP providers, CloudTrail `AssumeRoleWithWebIdentity`.
- OIDC engine: attacker-mintable candidates (unprotected branches, tags, auto-created environments, same-repo PRs, external repositories); three-state verdicts; custom subject templates.
- 18 rules; Markdown, JSON, SARIF 2.1.0, Mermaid and DOT output; stable fingerprints.
- `baseline` and `scan --baseline` drift gate.
- `hunt` with versioned IOC packs for wfx-loot and GhostAction, run-number gaps, and OIDC sessions from deleted branches.
- `rotate-plan` ordered rotation runbook.
- Composite GitHub Action (offline by default), CI with race tests, coverage gate and fuzzing; release pipeline with build-provenance attestations.
