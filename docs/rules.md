# Rules

`wardmap rules` prints this list. Severities map to SARIF levels: critical and high → error, medium → warning, low and info → note. Each SARIF result also carries `security-severity` for code-scanning triage.

| ID | Severity | Name | Meaning |
|---|---|---|---|
| <a id="wm001"></a>WM001 | medium/high | org-secret-visibility-all | An organisation secret is visible to every repository. Severity is high if any repository is public. |
| <a id="wm002"></a>WM002 | medium | secret-readable-from-any-branch | Repository and org secrets that any workflow on any branch can read. This is what wfx-loot harvested. |
| <a id="wm003"></a>WM003 | high | cloud-role-reachable-by-write-credential | A write credential can mint an OIDC token the cloud identity accepts (via branch, tag, auto-created environment or PR). |
| <a id="wm004"></a>WM004 | high | trust-admits-whole-owner | A `repo:<owner>/*` subject, no `sub` condition, or an owner-only GCP condition. |
| <a id="wm005"></a>WM005 | low | trust-missing-audience | AWS trust has no `aud` check. This is defence in depth only, because the requester chooses `aud`. |
| <a id="wm006"></a>WM006 | critical | trust-admits-any-github-repository | Anyone on GitHub can obtain the identity. |
| <a id="wm007"></a>WM007 | medium | ungated-environment-with-secrets | An environment with secrets but no reviewers and no protected-branch restriction. |
| <a id="wm008"></a>WM008 | high | id-token-on-untrusted-trigger | `id-token: write` on `pull_request_target`, comment triggers, or a `workflow_run` whose source workflows are not all maintainer-triggered (`push`, `schedule`, `workflow_dispatch`, `release`) workflows in the same repository. |
| <a id="wm009"></a>WM009 | medium | secret-to-unpinned-action | A secret passed to a third-party action that is not pinned to a commit SHA. |
| <a id="wm010"></a>WM010 | low | stale-secret | A secret older than `--stale-days` (default 180). |
| <a id="wm011"></a>WM011 | medium | static-cloud-credential | A long-lived cloud key or server SSH private key stored as a secret, or a cloud login that does not use OIDC. |
| <a id="wm012"></a>WM012 | critical | cloud-persistence-indicator | An AWS wildcard principal or a `wfx-ci-*` Entra federated credential. |
| <a id="wm013"></a>WM013 | critical | gcp-provider-without-condition | A GCP provider for GitHub with no attribute condition. |
| <a id="wm014"></a>WM014 | high | trust-needs-review | A trust Wardmap cannot decide: an unsupported condition, an unparsable policy, or a custom OIDC subject template it could not read. It fails closed (high) until a person reviews it and accepts it in a baseline. |
| <a id="wm015"></a>WM015 | high | pull-request-target-checkout | A "pwn request": PR code runs with secrets or id-token. |
| <a id="wm016"></a>WM016 | info | collection-gap | Data could not be collected; results for that scope are incomplete. |
| <a id="wm017"></a>WM017 | low | secrets-inherit-to-third-party | `secrets: inherit` passes every secret to a third-party reusable workflow. |
| <a id="wm018"></a>WM018 | info | workflow-parse-error | The workflow YAML could not be parsed (the message says whether it was empty or the wrong shape). |
| <a id="wm021"></a>WM021 | low | trust-pins-repository-names | AWS trust names repositories without immutable IDs; a re-registered organisation or repository name would inherit it. |
| <a id="wm019"></a>WM019 | medium | github-token-in-secrets | A GitHub personal access token is stored as a secret. Anyone who can read it can act as its owner on every repository it reaches, which is a lateral-movement path. Prefer `GITHUB_TOKEN` or a GitHub App token. |

Each finding has a stable fingerprint (`partialFingerprints["wardmap/v1"]`). Baselines use it, and code scanning uses it to track alerts across runs.
