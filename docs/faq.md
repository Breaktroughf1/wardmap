# FAQ

**Does Wardmap need my secrets or cloud credentials?**
No. It reads secret *names*, never values, and issues only `GET` requests to GitHub. Cloud trust comes from JSON files you export, or from a `terraform show -json` plan (`--terraform`). Offline mode (`wardmap local`) needs no token at all. See [permissions](permissions.md).

**How is this different from zizmor?**
zizmor lints workflow files. Wardmap joins live GitHub state (secrets, environments, branch protection, OIDC templates) with cloud trust policies and answers *what can a stolen write token reach?* Run both. See [positioning](positioning.md).

**How is it different from an OIDC trust-policy checker?**
A checker looks for badly written policies. Wardmap generates every OIDC subject an attacker with write access could get GitHub to sign, in both the legacy and the immutable `repo:OWNER@ID/REPO@ID` format, and evaluates each trust against them. A policy that looks strict can still match a subject an attacker can mint, for example on an unprotected branch or an auto-created environment.

**A clean report: am I safe?**
Not necessarily. Read the [limits](../README.md#limits-read-before-trusting-a-clean-report). Anything Wardmap cannot decide is reported as *needs review*, and anything it cannot read is a collection gap. Use `--fail-on-gaps` in CI.

**Why do I get findings for branches I think are protected?**
A branch counts as protected only if merging needs a pull-request review (a ruleset or classic protection with at least one approval). Protection that only blocks force pushes does not stop someone who can push. If Wardmap cannot read the protection details, it treats the branch as weakly protected and records a gap.

**Does it work with GitLab, Azure DevOps or Bitbucket?**
Not yet. Only GitHub Actions to AWS, Azure and GCP.

**Will it fail my CI on day one?**
Not if you approve today's state first: `wardmap baseline`, then `scan --baseline`. Only new reach fails the build.

**Can I see it working without connecting anything?**
Yes: `wardmap demo`, or `wardmap demo --format html -o wardmap-demo.html`.
