# Positioning

Competitor facts below were checked on 26–27 Nov 2026. Re-check them before quoting in launch material.

## The gap Wardmap fills

Each existing tool covers one slice. None of them answers *"which secrets and cloud identities fall if this one write credential is compromised?"* across GitHub and three clouds, with a CI gate and incident hunting.

| | Workflow lint | Live GitHub secret scoping | Environments / reviewers / branch protection | AWS trust | Azure FIC | GCP WIF | Attacker-mintable tokens (not just named roles) | Baseline gate | IOC hunt |
|---|---|---|---|---|---|---|---|---|---|
| zizmor / poutine | ✔ | | partial | | | | | | |
| ActionScope (MIT, Python, v0.5.0 Aug 2026) | | | partial | ✔ | | | named roles only | | |
| gha-oidc-auditor (Go, Apache-2.0, v0.1.0) | OIDC rules | not stated | partial (env gates in workflows) | ✔ | ✔ | ✔ | not modelled | fail-on only | |
| TrustFix / oidc-audit | | | | ✔ (misconfig checks) | | | | | |
| subcheck | | | | claims check of one token | | | | | |
| gha-audit | ✔ | | | | | | | | |
| legitify | | posture | ✔ | | | | | | |
| keyspan | | local files | | | | | | | |
| aws-iam-trust-audit | | | | ✔ (offline) | | | | | |
| **Wardmap** | defers to zizmor | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |

gha-oidc-auditor is the closest tool and is worth respecting: it generates least-privilege trust policies, which Wardmap does not. Recommend it for writing new policies, and Wardmap for proving what existing ones let an attacker reach.

## The one-line difference

Trust-policy checkers ask *"is this policy written badly?"*. Wardmap asks *"given what a stolen write token can make GitHub sign, which of these policies say yes?"*. That is why Wardmap generates candidate subjects, in both the legacy and the immutable `repo:OWNER@ID/REPO@ID` formats, and evaluates every trust against them instead of pattern-matching policy text.

## What we deliberately do not do

- **Workflow linting.** Wardmap's workflow rules are limited to the ones that feed the reach graph. Recommend zizmor for everything else.
- **Secret values or validation.** Kingfisher covers that.
- **Runtime monitoring.** harden-runner covers that.
- **Write or auto-remediation.** Wardmap stays read-only so it is safe to run with minimal permissions.

## Messaging rules

- Say "**probed** 61,764 repositories", not "compromised". Sources differ on how many repositories ran the payload: Aikido reports at least 1,835 in one place and 1,806 in another. OX Security counted 8,093 repositories with a malicious commit on the default branch. These figures measure different things.
- Credit the researchers (Aikido, GitGuardian, StepSecurity, Endor Labs, OX Security) and link their primary write-ups.
- Never imply that a clean report proves no compromise.
