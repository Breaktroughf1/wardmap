# Wardmap

[![ci](https://github.com/Breaktroughf1/wardmap/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Breaktroughf1/wardmap/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Pre-release.** v1.0 is planned for 2 December 2026. Interfaces and the snapshot format may still change. Reports of false negatives in trust evaluation are especially welcome: see [SECURITY.md](SECURITY.md).

**Map what one compromised CI credential can reach.**

Wardmap answers the question incident responders and platform teams keep scripting by hand:

> *If an attacker gets write access to repository X (a stolen PAT, a hijacked maintainer account), which GitHub Actions secrets and which AWS, Azure and GCP identities fall?*

It joins GitHub secret scoping (repository, organisation and environment secrets, reviewers, branch policies, branch protection) with cloud OIDC trust (IAM role trust policies, Entra federated credentials, GCP workload identity providers). The result is a reach graph you can query, gate in CI, and hunt over.

- **Read-only by construction.** Only `GET` requests. Secret values are never read; GitHub does not expose them anyway. Cloud trust comes from exports made with your own CLIs, so Wardmap never holds cloud credentials.
- **Never silently "safe".** Every trust decision is *reachable*, *not reachable* or *needs review*. Conditions Wardmap cannot evaluate are reported, never dropped.
- **Built for the wfx-loot / GhostAction threat model.** Attackers with write access push a throwaway branch and workflow, request `id-token: write`, and exchange the token for cloud sessions. Wardmap models exactly that, including environments that GitHub auto-creates on first reference.

```text
$ wardmap reach -s snapshot.json org-artifacts-read
reachable    write@example-org/api -> aws-role:arn:aws:iam::111122223333:role/org-artifacts-read
             via any unprotected branch (new branch + new workflow) (admitted by StringLike sub [repo:example-org/*])
reachable    write@example-org/website -> aws-role:arn:aws:iam::111122223333:role/org-artifacts-read
             via any unprotected branch (new branch + new workflow) (admitted by StringLike sub [repo:example-org/*])
```

## Install

```bash
go install github.com/Breaktroughf1/wardmap/cmd/wardmap@latest
```

Signed binaries with build provenance are attached to each [release](https://github.com/Breaktroughf1/wardmap/releases). Verify them with `gh attestation verify <file> --repo Breaktroughf1/wardmap`.

## Quick start

Try it on the bundled fictional estate (no token needed):

```bash
make demo
```

Scan your own organisation:

```bash
export WARDMAP_GITHUB_TOKEN=...      # read-only, see docs/permissions.md
wardmap collect --org your-org --hunt -o snapshot.json

# Optional: cloud trust, exported with your own read-only credentials
aws iam list-roles > aws.json
az ad app federated-credential list --id "$APP_ID" > "fic-$APP_ID.json"
gcloud iam workload-identity-pools providers list --workload-identity-pool=POOL --location=global --format=json > gcp.json
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity > ct.json
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateAssumeRolePolicy > ct-trust.json
az rest --method get --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$filter=activityDisplayName eq 'Update application'" > entra-audit.json

wardmap import -s snapshot.json --aws aws.json --azure "fic-$APP_ID.json" --gcp gcp.json \
  --cloudtrail ct.json --cloudtrail ct-trust.json --azure-audit entra-audit.json
wardmap scan -s snapshot.json                  # Markdown report
wardmap hunt -s snapshot.json                  # wfx-loot / GhostAction indicators
wardmap rotate-plan -s snapshot.json --repo your-org/affected-repo
```

No token at all? `wardmap local --dir .` scans the workflows in a checkout.

## Commands

| Command | What it does |
|---|---|
| `collect` | Read-only GitHub collection into a snapshot (`--hunt` adds PRs, commits, runs) |
| `local` | Offline snapshot from workflows on disk |
| `import` | Add AWS, Azure, GCP, CloudTrail and Entra audit-log exports to a snapshot |
| `scan` | Reach graph and 18 rules; `md`, `json`, `sarif`, `mermaid`, `dot` |
| `reach QUERY` | Who can reach a secret, role, environment or repository |
| `baseline` / `scan --baseline` | Approve today's reach; fail CI on *new* reach or findings |
| `hunt` | Match versioned IOC packs; run-number gaps; OIDC sessions from deleted branches; trust rewrites and backdoor credentials in CloudTrail and Entra audit logs |
| `rotate-plan` | Ordered runbook: persistence → cloud trust → registries → GitHub → cloud keys → app secrets |
| `run` | `collect`/`local` + `import` + `scan` in one step (used by the Action) |

Exit codes: `0` ok, `1` threshold exceeded or new reach since baseline, `2` error.

## GitHub Action

```yaml
permissions:
  contents: read
  actions: read          # needed by the SARIF upload on private repositories
  security-events: write
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with: { persist-credentials: false }
  - uses: Breaktroughf1/wardmap@<full-commit-sha> # pin to a release commit
    with:
      mode: offline          # no token needed; or `live` with a read-only token
      fail-on: high
      baseline: .github/wardmap-baseline.json
```

The Action builds Wardmap from the pinned action source; nothing is downloaded at run time. Findings appear in code scanning. Code scanning is free on public repositories; private repositories need GitHub Code Security, or set `upload-sarif: false` and use the threshold gate alone.

## How it relates to other tools

Wardmap is meant to run **alongside** these tools, not replace them.

| Tool | What it does well | What Wardmap adds |
|---|---|---|
| [zizmor](https://github.com/zizmorcore/zizmor), poutine, octoscan | Workflow-file linting (injection, permissions, pinning) | Live secret scoping and cloud trust; reach graph; baseline gate. Run zizmor for workflow linting. |
| [ActionScope](https://github.com/r12habh/ActionScope) | AWS blast radius of the roles a workflow *names* | Any role an attacker *can* assume (not just the named one), Azure + GCP, environments, branch protection, org secrets |
| legitify | GitHub/GitLab org posture | The secret → workflow → cloud chain |
| keyspan, aws-iam-trust-audit | Secret consumer graph / AWS trust JSON lint | Joined, live GitHub side, three clouds, incident hunting |
| Kingfisher | Validating *leaked* keys | Exposure of secrets that have *not* leaked yet |

See [docs/positioning.md](docs/positioning.md) for detail.

## Documentation

- [Threat model and evaluation semantics](docs/threat-model.md)
- [Rules](docs/rules.md)
- [Token permissions](docs/permissions.md)
- [IOC packs](docs/ioc-packs.md)
- [Project plan](docs/PLAN.md)

## Limits (read before trusting a clean report)

- A clean `hunt` does not prove no compromise. wfx-loot deleted runs, logs and commits.
- Branch protection comes from the branches API. Where it is missing, Wardmap assumes nothing is protected. That can produce extra findings, but never fewer.
- GCP reach stops at the provider; service-account IAM bindings are not yet evaluated.
- The CEL subset covers conditions seen in practice. Anything else is *needs review*.
- Only GitHub is supported; GitLab, Azure DevOps and Bitbucket are not.

## Licence

Apache-2.0. IOC packs in `internal/hunt/packs` are data and accept community pull requests. Wardmap is a security tool provided without warranty. It is not an incident-response service.
