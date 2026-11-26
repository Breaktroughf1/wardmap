# Launch posts (copy-ready)

Post in this order on launch day:

1. Hacker News, Tuesday or Wednesday, 08:00–09:00 US Eastern (18:30–19:30 IST)
2. Reddit, about 2 hours later
3. LinkedIn
4. OpenSSF Slack
5. Indian developer communities

Reply to every comment in the first three hours.

Rules for all posts:
- Say "**probed** 61,764 repositories", not "compromised".
- Quote execution counts as "about 1,800".
- Never claim a clean scan proves no compromise.
- Credit the researchers.

---

## Show HN

**Title** (80-character limit):

> Show HN: Wardmap – see which cloud roles one stolen GitHub credential can reach

**URL:** https://github.com/Breaktroughf1/wardmap

**First comment (post immediately):**

> Hi HN. In November the wfx-loot campaign used 4,837 hijacked GitHub accounts to probe 61,764 repositories and ran a CI secret stealer in about 1,800 of them. It needed no GitHub bug. Write access was enough to push a throwaway branch, read every repo and org secret, and swap a GitHub OIDC token for AWS/Azure/GCP sessions wherever trust policies were loose. It then persisted with wildcard AWS trust policies and extra Entra federated credentials.
>
> Wardmap answers "if this credential is compromised, what falls?" It joins GitHub secret scoping (repo/org/environment secrets, reviewers, branch policies, branch protection) with cloud OIDC trust (IAM trust policies, Entra federated credentials, GCP attribute conditions) and reports which secrets and cloud identities are reachable.
>
> The part I'd most like feedback on is the OIDC model. Instead of checking the role a workflow names, it enumerates the tokens an attacker can actually mint: any unprotected branch, any tag, any environment that isn't gated (GitHub auto-creates environments on first reference, so `environment:production` is only safe if that environment exists and has reviewers), and same-repo PRs. It then intersects those wildcard patterns with the trust conditions. Anything it can't evaluate (unusual IAM operators, CEL beyond a common subset) is reported as "needs review", never as safe.
>
> It's read-only (GET only, enforced by a test), never touches secret values, and reads cloud trust from exports you make yourself, so it never holds cloud credentials. There's also a `hunt` command with IOC packs for wfx-loot and GhostAction (run-number gaps from deleted runs, CloudTrail sessions from deleted branches, `wfx-ci-*` in Entra audit logs) and a rotation runbook that closes persistence before rotating.
>
> `make demo` runs it on a fictional org. Go, Apache-2.0. It complements zizmor (workflow linting) rather than replacing it. False-negative reports are treated as security bugs.

---

## Reddit: r/devops

**Title:** I built an open-source tool that maps which secrets and cloud roles a single compromised GitHub credential can reach (wfx-loot / GhostAction)

**Body:**

> After wfx-loot (4,837 hijacked accounts, 61,764 repos probed, stealer ran in about 1,800) I wanted one command to answer "if this account or branch is compromised, what falls?"
>
> Wardmap joins GitHub secret scoping (repo/org/environment secrets, reviewers, branch policies, branch protection) with cloud OIDC trust (AWS role trust, Entra federated credentials, GCP WIF conditions). It outputs a reach graph, 19 rules as SARIF, and a CI baseline gate that fails on *new* reach.
>
> Things it catches that are easy to miss:
> - `repo:org/*` trust, which means every repo in the org can assume the role
> - environment-based trust where the environment doesn't exist yet (GitHub auto-creates it with no protection)
> - org secrets with visibility "all"
> - long-lived cloud keys still stored as Actions secrets
>
> Read-only, runs offline in CI by default, Apache-2.0: https://github.com/Breaktroughf1/wardmap
>
> I'd value feedback on false positives and negatives from real orgs.

## Reddit: r/netsec

**Title:** Wardmap: modelling attacker-mintable GitHub OIDC tokens against AWS/Azure/GCP trust, plus wfx-loot/GhostAction hunting

**Body:** Use the Show HN first comment, then add:

> Threat model and evaluation semantics: https://github.com/Breaktroughf1/wardmap/blob/main/docs/threat-model.md
> The IOC packs record a source and verification level for each indicator: https://github.com/Breaktroughf1/wardmap/blob/main/docs/ioc-packs.md

---

## LinkedIn

> In November, hijacked GitHub accounts probed 61,764 repositories and ran a CI secret stealer in about 1,800 of them. No GitHub vulnerability was involved: write access plus default secret scoping was enough to reach AWS, Azure and GCP through GitHub OIDC.
>
> Today we're open-sourcing **Wardmap**. It answers one question: *if this GitHub credential is compromised, which secrets and which cloud roles fall?*
>
> ✅ Joins GitHub secret scoping with AWS, Azure and GCP OIDC trust
> ✅ Finds roles an attacker can reach, not just the ones a workflow names
> ✅ Hunts for wfx-loot and GhostAction indicators, including persistence in CloudTrail and Entra audit logs
> ✅ Generates an ordered rotation runbook
> ✅ Read-only, offline in CI, Apache-2.0
>
> Credit to Aikido Security, GitGuardian, StepSecurity, Endor Labs and OX Security for their public research.
>
> https://github.com/Breaktroughf1/wardmap
>
> If your team deploys from GitHub Actions to the cloud and wants a second pair of eyes, we run a fixed-scope CI-to-cloud trust review. Message me.
>
> #DevSecOps #GitHubActions #CloudSecurity #SupplyChainSecurity #OpenSource

---

## OpenSSF Slack (#general or a supply-chain channel) and Indian communities

> Sharing an open-source tool we released this week: Wardmap maps what one compromised GitHub credential can reach (Actions secrets, plus AWS/Azure/GCP roles via OIDC) and hunts for wfx-loot/GhostAction indicators. Read-only, Apache-2.0. Feedback on the OIDC trust model is very welcome, especially false negatives: https://github.com/Breaktroughf1/wardmap
