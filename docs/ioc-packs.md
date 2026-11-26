# IOC packs

IOC packs are YAML data files. New campaigns ship as a pack update, not a code release. Built-in packs live in `internal/hunt/packs/`. A directory passed with `--iocs` adds packs, and a local pack with the same `id` replaces the built-in one.

```yaml
id: example-campaign
name: Example campaign
version: 2026.12.01
window: { start: 2026-12-01T00:00:00Z, end: 2026-12-15T00:00:00Z }
references: [https://example.com/write-up]
indicators:
  - id: example-branch
    type: branch_name          # see types below
    pattern: "probe-*"         # '*' and '?' wildcards, case-insensitive
    confidence: high           # low | medium | high
    description: Why this matters.
```

| Type | Matches against |
|---|---|
| `branch_name` | current branch names |
| `pr_title`, `pr_head_ref` | pull requests created within `--since` |
| `commit_message` | first line of commit messages on the default branch within `--since` |
| `commit_file` | files touched by those commits (catches files that were later deleted) |
| `workflow_path` | current workflow files and the workflow paths of runs |
| `azure_fic_name` | imported Entra federated credentials |
| `aws_wildcard_principal` | imported IAM trust policies (no pattern) |
| `run_number_gap` | missing run numbers per workflow (deleted runs) |
| `cloudtrail_deleted_branch` | OIDC sessions issued to branches that no longer exist |
| `cloudtrail_unknown_repo` | OIDC sessions issued to repositories outside the estate |
| `cloudtrail_pull_request` | OIDC sessions issued to `pull_request` tokens |

Hits inside the pack's `window` are marked. Treat indicators as leads and confirm each one. In particular, generic names such as `audit.yml` are low confidence on their own.

When contributing a pack, cite primary sources (the researchers' own write-ups) in `references`, and keep confidence honest.
