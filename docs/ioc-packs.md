# IOC packs

IOC packs are YAML data files. New campaigns ship as a pack update, not a code release. Built-in packs live in `internal/hunt/packs/`. A directory passed with `--iocs` adds packs, and a local pack with the same `id` replaces the built-in one.

```yaml
id: example-campaign
name: Example campaign
version: 2026.12.01
window: { start: 2026-12-01T00:00:00Z, end: 2026-12-15T00:00:00Z }
primary: [https://researcher.example/original-write-up]   # the researchers' own posts
references: [https://news.example/coverage]               # corroborating reporting
indicators:
  - id: example-branch
    type: branch_name          # see types below
    pattern: "probe-*"         # '*' and '?' wildcards, case-insensitive
    confidence: high           # low | medium | high
    description: Why this matters.
    sources: [researcher, news]  # who reports this indicator
    verified: secondary          # primary = checked against the original post
```

| Type | Matches against |
|---|---|
| `branch_name` | current branch names |
| `pr_title`, `pr_head_ref` | pull requests created within `--since` |
| `commit_message` | first line of commit messages on the default branch within `--since` |
| `commit_file` | files touched by those commits (catches files that were later deleted) |
| `workflow_path` | current workflow files and the workflow paths of runs |
| `workflow_endpoint` | URLs and IPv4 addresses found in workflow files (exfiltration hosts) |
| `workflow_secrets_dump` | jobs that serialise the whole `secrets` or `vars` context (no pattern) |
| `azure_fic_name` | imported Entra federated credentials |
| `azure_audit_fic_name` | federated credentials *added* according to Entra audit logs (catches deleted ones) |
| `aws_wildcard_principal` | imported IAM trust policies (no pattern) |
| `run_number_gap` | missing run numbers per workflow (deleted runs) |
| `cloudtrail_deleted_branch` | OIDC sessions issued to branches that no longer exist |
| `cloudtrail_unknown_repo` | OIDC sessions issued to repositories outside the estate |
| `cloudtrail_pull_request` | OIDC sessions issued to `pull_request` tokens |
| `cloudtrail_session_name` | AWS role-session names, on OIDC assumptions and follow-up events |
| `cloudtrail_event` | IAM persistence events by name (`UpdateAssumeRolePolicy`, `CreateAccessKey`, …); optional `session` pattern |

Packs are validated on load. An unknown type, a missing pattern, a duplicate id or a bad confidence level is an error, so a typo can never silently switch an indicator off.

Hits inside the pack's `window` are marked. Treat indicators as leads and confirm each one. In particular, generic names such as `audit.yml` are low confidence on their own.

When contributing a pack, list the researchers' own write-ups under `primary`, record per indicator who reports it (`sources`), and set `verified: primary` only after checking the indicator against an original post. Keep confidence honest.

## Verification status of the built-in packs

| Pack | Version | Status |
|---|---|---|
| wfx-loot | 2026.11.26.2 | Every indicator backed by public reporting; most by two or more independent write-ups, seven by a single source (listed in the pack header). **Primary-source check pending**: the original posts were unreachable from the build environment. |
| ghostaction | 2026.11.26.2 | Backed by public reporting; `security-check.yml` and the 2025 exfiltration IP come from a single source. Primary check pending. Version 2026.11.26 listed `audit.yml` and `ci-check.yml`; they were removed because no source supports them. |
| generic | 2026.11.26.2 | Campaign-independent heuristics. |
