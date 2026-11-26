# Pre-brief messages (send on day 5, the day before launch)

Send these to 3–5 people whose work Wardmap builds on or sits next to. Use the projects' public contact routes: GitHub Discussions, a maintainer's published e-mail, or Slack.

Ask for feedback, not endorsement. Never imply they reviewed or endorse Wardmap unless they say so in writing.

---

## To the zizmor maintainers

**Subject:** Heads-up: Wardmap, a CI-to-cloud reach mapper designed to run alongside zizmor

> Hi — I'm Noeal from Breaktrough. Tomorrow we're open-sourcing Wardmap (Apache-2.0), which maps which Actions secrets and cloud roles (via GitHub OIDC) a single compromised write credential can reach. We deliberately don't do workflow linting: our README recommends zizmor for that, and positions Wardmap as the cloud-trust and secret-reach layer next to it.
>
> If you have five minutes, I'd value a sanity check on how we describe zizmor in https://github.com/Breaktroughf1/wardmap/blob/main/docs/positioning.md, so we don't misrepresent your project. Happy to change anything.

## To the ActionScope author

**Subject:** Wardmap and ActionScope: overlapping on AWS OIDC, comparison wording check

> Hi — I'm releasing Wardmap tomorrow. It overlaps with ActionScope on AWS OIDC trust. Our docs credit ActionScope for mapping the AWS blast radius of the roles a workflow names, and describe Wardmap's difference as modelling any role an attacker could assume, plus Azure/GCP and environments. Could you check that our description of ActionScope is fair? Link: https://github.com/Breaktroughf1/wardmap/blob/main/docs/positioning.md

## To researchers whose IOCs we used (Aikido, GitGuardian, StepSecurity, Endor Labs)

**Subject:** Your wfx-loot / GhostAction indicators in an open-source hunting tool, with attribution

> Hi — Wardmap's `hunt` command ships versioned IOC packs for wfx-loot and GhostAction, with per-indicator attribution and links to your write-ups. We built them from public reporting, and several indicators are still marked "secondary" because we couldn't check them against your original posts. If anything is wrong or missing, a reply (or a PR to `internal/hunt/packs/`) would help everyone hunting. Packs: https://github.com/Breaktroughf1/wardmap/tree/main/internal/hunt/packs

## To OpenSSF (Securing Software Repositories WG or the supply-chain channel)

**Subject:** New Apache-2.0 tool for CI credential blast radius, feedback welcome

> Hi all — sharing Wardmap before it launches tomorrow. It's read-only and models attacker-mintable GitHub OIDC tokens against AWS/Azure/GCP trust, with a CI baseline gate and wfx-loot/GhostAction hunting. We'd value feedback on the threat model (docs/threat-model.md), especially cases where it would say "not reachable" incorrectly.
