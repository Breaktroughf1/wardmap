# Changelog

## v1.1.0 — 2026-11-27

### Fixed: GitHub immutable OIDC subject claims (false negative)

GitHub's default `sub` claim includes immutable IDs (`repo:OWNER@ID/REPO@ID:…`) for repositories created after 15 July 2026, for repositories renamed or transferred after that date, and for opted-in repositories. Earlier versions modelled only the name-based format, so they could report a role trusting the new format as **not reachable**. Wardmap now does the following:
- Collects repository and owner IDs, the creation date, `use_immutable_subject` and `sub_claim_prefix`.
- Evaluates the exact format when GitHub reports it, and both formats when it cannot be determined.
- Applies the immutable format to custom templates, the unknown-template probe and the internet-wide check.
- Adds WM021, which flags trust that identifies repositories by name only (name-squatting risk).

**Upgrading is strongly recommended.**

### Added

- `wardmap demo`: scan and hunt a built-in fictional estate from any install, with no token and no clone.
- `--format html`: a single self-contained report for security leads and auditors. It has no external assets, supports dark mode and prints cleanly to PDF.
- `import --terraform`: reads AWS role trust policies, Entra federated credentials and GCP workload identity providers from `terraform show -json` output (plan or state), for teams that manage trust as code.

### Fixed: branch protection that does not stop a write credential (false negative)

Earlier versions trusted GitHub's `protected` flag. That flag is also set when a branch only requires status checks, and an attacker with write access can open a pull request and merge it into such a branch. A branch now counts as protected only when an active ruleset or classic protection requires at least one approving review, or restricts updates. If that cannot be confirmed, Wardmap treats the branch as weak (fail safe).

As a result, trust scoped to a weakly protected branch is reported as reachable, and "protected branches only" environments are treated as ungated when any protected branch is weak. New rule WM020 reports default branches that are unprotected or weakly protected.

Wardmap is now installable from every common channel, each delivering the same signed binary.

- **Release archives** are built reproducibly with GoReleaser: tar.gz for Linux and macOS, zip for Windows, amd64 and arm64, plus a source archive. `checksums.txt` carries a keyless Sigstore signature (`checksums.txt.sigstore.json`), and the archives keep SLSA build provenance. Archive names change from `wardmap_vX.Y.Z_<os>_<arch>` (raw binaries) to `wardmap_X.Y.Z_<os>_<arch>.tar.gz` / `.zip`.
- **npm** (`npx wardmap`) and **PyPI** (`uvx wardmap`, `pipx install wardmap`) packages: launchers that pin the SHA-256 values from the signature-verified checksums, download the archive for the platform on first use, refuse any mismatch, and re-check the cached binary on every run. They are tested on Linux, macOS and Windows before being published with trusted publishing (npm provenance, PyPI attestations). Launcher errors exit 2, like Wardmap's own errors.
- **Container image** `ghcr.io/breaktroughf1/wardmap`: distroless and non-root, built from the verified archives for linux/amd64 and linux/arm64, signed with cosign and attested.
- **Homebrew:** `brew install breaktroughf1/tap/wardmap`.
- CI builds the archives on every push and tests both launchers, including refusal of tampered downloads and tampered cached binaries.
- WM008 now resolves `workflow_run` sources. Such a trigger is trusted only when every source workflow is in the repository and starts solely on `push`, `schedule`, `workflow_dispatch` or `release`. Unresolved sources still fail safe as untrusted. Found by Wardmap scanning its own new publishing workflows.
- Packaging and container publishing start from the release workflow's completion (`workflow_run`), because a release created with `GITHUB_TOKEN` does not trigger other workflows.

## v1.0.1 — 2026-11-26

Fail-safe hardening. A review of every path where missing data or unusual input could turn into a "safe" result found the false negatives below. Upgrading is recommended.

### Fixed (false negatives)

- IAM condition keys are now matched case-insensitively (`token.actions.githubusercontent.com:Sub` was previously not recognised, so the role looked unreachable).
- `...IfExists` condition operators now pass when the token lacks the claim, as IAM does. Previously `StringEqualsIfExists` on `environment` made branch tokens look rejected.
- If a repository's custom OIDC subject template cannot be read, Wardmap no longer assumes the default: it records a gap and reports any trust that mentions the repository as needing review.

### Fixed (robustness)

- Fuzzing found a crash in the GCP attribute-condition parser on malformed input such as `'x' in`. It is fixed, and both trust evaluators now turn any internal error into *needs review* instead of crashing the scan.

### Changed (fail closed)

- WM014 *trust-needs-review* is now **high** severity (was low), so `--fail-on high` no longer passes undecidable trust.
- Pagination limits produce an error or a collection gap instead of silently truncating results.
- `hunt` states which sources were not checked. With `--fail-on` and no data at all it exits 2 instead of reporting a clean result.
- New `--fail-on-gaps` flag (Action input `fail-on-gaps`, live mode) fails CI when data is incomplete.
- New fuzz targets for the AWS trust evaluator and the GCP CEL evaluator. A fail-safe contract is documented in docs/threat-model.md.

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
