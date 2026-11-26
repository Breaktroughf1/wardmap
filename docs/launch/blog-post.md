# wfx-loot didn't need a GitHub bug. It needed your defaults.

*Noeal Rajeev, Breaktrough · draft for 1 December 2026*

On 10 November 2026, from 12:45 UTC, hijacked GitHub accounts opened pull requests titled "docs: dependency audit notes" against tens of thousands of repositories. Aikido Security counted **4,837 accounts probing 61,764 repositories**. In **roughly 1,800 of them** (1,806 or 1,835, depending on the count) a credential stealer actually ran. It harvested CI secrets, swapped GitHub OIDC tokens for AWS, Azure and GCP sessions, and then left itself a way back in: wildcard AWS trust policies and `wfx-ci-*` federated credentials in Entra ID.

A month earlier, GhostAction had done much the same thing, at a smaller scale per repository but against more than 30,000 of them.

Neither campaign used a vulnerability in GitHub. Each used a stolen credential with **write access**, plus defaults that nobody had looked at closely.

## What write access buys an attacker

If I can push to your repository, I can:

- **Read every repository secret, and every organisation secret visible to the repository.** I push a new branch with a new workflow, and the secrets are there. Branch protection doesn't help, because I never touch your protected branch.
- **Mint an OIDC token for `ref:refs/heads/<anything>`.** If your AWS role trusts `repo:your-org/*`, I'm in. The same applies to `repo:your-org/your-repo:*`.
- **Mint a token for `environment:<anything>` that isn't gated.** GitHub creates an environment the first time a workflow references it, with no protection rules. A trust policy for `environment:production` is only safe if `production` already exists and has required reviewers.
- **Choose my own audience.** `aud` is a parameter in the request. Checking it is good hygiene, but it doesn't stop me.

None of this is new. What is new is attackers doing it to 60,000 repositories in two days.

## The question nobody could answer quickly

When a responder asks *"which secrets and which cloud roles fall if this account is compromised?"*, the honest answer has usually been a few hours of `gh api` loops, reading IAM trust policies by eye, and hoping nothing was missed.

So we built **[Wardmap](https://github.com/Breaktroughf1/wardmap)**, an open-source (Apache-2.0) tool that answers it in one command.

```text
$ wardmap reach -s snapshot.json org-artifacts-read
reachable    write@example-org/api -> aws-role:arn:aws:iam::111122223333:role/org-artifacts-read
             via any unprotected branch (new branch + new workflow) (admitted by StringLike sub [repo:example-org/*])
```

Wardmap joins two things:

- **GitHub secret scoping:** repository, organisation and environment secrets, required reviewers, deployment-branch policies and branch protection.
- **Cloud OIDC trust:** IAM role trust policies, Entra federated credentials and GCP workload-identity conditions.

From those it builds a graph of what one compromised write credential can reach.

Most tools check the role a workflow *names*. Wardmap asks a different question: which roles *could* an attacker assume? It models every token family the attacker can mint (new branches, tags, auto-created environments, same-repository pull requests) and excludes what they genuinely can't reach (protected branches, gated environments). Every trust decision is *reachable*, *not reachable* or *needs review*. Anything Wardmap can't evaluate is reported, never quietly marked safe.

## If you were hit

`wardmap hunt` matches versioned indicator packs for wfx-loot and GhostAction:

- probe branches and pull requests;
- the inject-then-revert commits;
- throwaway `build-audit-*` workflows;
- **gaps in workflow run numbers** where the attacker deleted runs;
- CloudTrail sessions issued to **branches that no longer exist**;
- `wfx-*` sessions rewriting trust policies or creating access keys;
- `wfx-ci-*` credentials appearing in Entra audit logs, even ones already deleted.

Then `wardmap rotate-plan` produces an ordered runbook:

1. Remove the persistence.
2. Tighten cloud trust.
3. Rotate registry tokens, then GitHub credentials, then cloud keys, then application secrets.

If you rotate first and close the trust policy second, the new secret can simply be stolen again.

A clean hunt does not prove you weren't compromised. wfx-loot deleted its runs and logs. Wardmap says so every time, and so do we.

## Designed to be safe to run

- **Read-only.** It only issues `GET` requests (a test enforces this) and never reads secret values.
- **No cloud credentials.** Cloud data comes from exports you make with your own CLIs.
- **Offline by default in CI.** The GitHub Action scans the checkout without a token. Live mode takes a read-only GitHub App or fine-grained token, and anything it cannot read becomes a visible *collection gap*.
- **Verifiable.** Releases carry build-provenance attestations. Every third-party action is pinned to a commit SHA.

## Try it

```bash
go install github.com/Breaktroughf1/wardmap/cmd/wardmap@latest
git clone https://github.com/Breaktroughf1/wardmap && cd wardmap && make demo
```

Wardmap runs alongside **zizmor** (workflow linting) and **ActionScope** (AWS blast radius of named roles). It does not replace them.

<!-- If design-partner scans have been run, add anonymised aggregates here,
     e.g. "Across N organisations, X% had an AWS role reachable from any branch".
     Do not publish numbers that were not measured. -->

---

*Thanks to the researchers at Aikido Security, GitGuardian, StepSecurity, Endor Labs and OX Security, whose public write-ups made the indicator packs possible. Breaktrough offers a fixed-scope CI-to-cloud trust review for teams that want help acting on the results.*
