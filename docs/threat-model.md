# Threat model and evaluation semantics

## The attacker Wardmap models

**Write access to one repository**, through a stolen personal access token, a hijacked maintainer account, a compromised bot or a malicious insider. This is how wfx-loot (Nov 2026) and GhostAction (Oct 2026) operated: no GitHub vulnerability was involved.

With write access, an attacker can:

| Capability | Resulting OIDC context | Wardmap candidate |
|---|---|---|
| Push a new branch containing a new workflow with `id-token: write` | `ref:refs/heads/<anything>` | *any unprotected branch* |
| Push a tag | `ref:refs/tags/<anything>` | *any tag* |
| Reference an environment in a job. A missing environment is **created on first use with no protection.** | `environment:<anything not already gated>` | *any ungated environment* |
| Open a pull request from a branch in the same repository | `pull_request` | *same-repository pull request* |
| Choose the token audience (`core.getIDToken(aud)`) | any `aud` | `aud` is always attacker-controlled |

The attacker **cannot**:

- push to protected branches;
- run a job in an environment with required reviewers;
- run a job in an environment restricted to protected branches.

Wardmap excludes those values precisely.

A separate **external candidate** models a repository Wardmap does not own. It catches trust that admits any GitHub user (rule WM006).

Secret reach follows the same model. Repository secrets, and organisation secrets visible to the repository, are readable by any workflow on any branch. Environment secrets are readable unless the environment is gated.

## How trust is evaluated

Each candidate is a set of claims in which attacker-chosen parts are `*`. Trust conditions are patterns. Wardmap decides whether the two can match a common string using exact wildcard-intersection logic (`internal/glob`). It then removes matches that only hit excluded values, such as protected branch names or gated environments.

- **AWS:**
  - `StringEquals`, `StringLike`, the `IgnoreCase` variants, `ForAnyValue:` / `ForAllValues:` and the `Not` forms on `token.actions.githubusercontent.com:*` claims are evaluated.
  - Any other operator or key makes the verdict *needs review*.
  - A Deny statement on the GitHub provider also downgrades *reachable* to *needs review*.
  - Wildcard principals (`"*"`, `{"AWS":"*"}`) are flagged separately; this is the wfx-loot persistence pattern.
- **Azure:**
  - Subjects are compared exactly, as Entra does.
  - Flexible-credential expressions of the form `claims['x'] matches '...'` / `eq '...'` joined by `and` are evaluated. Anything else is *needs review*.
- **GCP:**
  - A CEL subset is evaluated in three states: `==`, `!=`, `&&`, `||`, `!( )`, `in [...]`, `startsWith`, `endsWith`, on `assertion.*` and mapped `attribute.*`.
  - Anything else is *needs review*.
  - A provider with no condition is reachable by anyone.

The repository's custom OIDC subject template (`include_claim_keys`) is honoured.

**Immutable subject claims.** Since 15 July 2026, GitHub's default `sub` for new repositories is `repo:OWNER@OWNER-ID/REPO@REPO-ID:…`. The same applies to repositories renamed or transferred after that date, and to any repository or organisation that opts in. Custom templates keep the IDs in the `repo` segment. Wardmap chooses the format as follows:
1. If GitHub reports the repository's `sub_claim_prefix`, Wardmap uses exactly that.
2. Otherwise, if the repository was created after the cutoff or reports `use_immutable_subject: true`, it uses the immutable format.
3. Otherwise it evaluates **both** formats, because an organisation-level opt-in or a rename cannot be ruled out.

Offline snapshots have no IDs, so the IDs are treated as unknown. Trust written for name-only subjects is flagged by WM021 (name-squatting risk).

## Fail-safe contract

When Wardmap is unsure, it errs towards reporting exposure. It never errs towards reporting safety.

| Situation | Behaviour |
|---|---|
| Trust condition, operator or CEL it cannot evaluate | *needs review*, **high** (WM014). Never "not reachable". |
| Trust policy that cannot be parsed | WM014, **high** |
| Repository's custom OIDC subject template not readable | Recorded as a gap. Any trust that mentions the repository is WM014 **high**. |
| Branch protection unknown | Every branch is treated as pushable |
| Environments unreadable | Every environment is treated as ungated |
| Any GitHub data not readable (permissions, errors) | Collection gap (WM016), shown at the top of the report. `--fail-on-gaps` (Action: `fail-on-gaps`) turns it into a failing exit code. |
| Pagination limit reached | An error (listing repositories) or a gap (everything else), never a silent truncation |
| `hunt` without history or cloud exports | Says exactly which sources were not checked. With `--fail-on` and no data at all, it exits 2 instead of passing. |
| Baseline, snapshot or IOC pack malformed, or snapshot from a newer schema | Exit 2 (error), never a pass |
| IAM condition key case and `...IfExists` operators | Handled per IAM semantics (keys are case-insensitive; IfExists passes when the claim is absent) |

The AWS policy evaluator, the GCP CEL evaluator, the glob engine and the workflow parser are fuzzed in CI.

## Known limitations

- Branch protection uses the branches API `protected` flag. Rulesets that restrict branch *creation* are not modelled. If anything this produces extra findings, never fewer.
- GCP: service-account impersonation bindings are not evaluated.
- Reusable workflows called from other repositories are not followed.
- Self-hosted runners and persistence on runners are out of scope. Use runtime tooling for those.

## Wardmap's own security

- Read-only HTTP (`GET` only, which a test asserts). No secret values are read or printed.
- Snapshots contain secret *names*, repository structure and trust policies. Treat them as internal. `.gitignore` excludes default snapshot names.
- No network calls at all in `local`, `import`, `scan`, `hunt`, `reach` and `rotate-plan`.
- The Action builds from the pinned action source with `-trimpath`. All third-party actions are pinned to full commit SHAs. Releases carry build-provenance attestations.
- The YAML workflow parser and the glob engine are fuzzed in CI.
