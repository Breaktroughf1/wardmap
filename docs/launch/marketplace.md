# GitHub Marketplace listing

The Action is already Marketplace-ready: `action.yml` is at the repository root with `name`, `description` and `branding`. Publishing is a checkbox on the release page, and only a repository owner can tick it.

## Steps (after the v1.0.1 release exists)

1. Open https://github.com/Breaktroughf1/wardmap/releases, then the v1.0.1 release, then **Edit**.
2. Tick **Publish this Action to the GitHub Marketplace**. Accept the Marketplace Developer Agreement if GitHub asks; it requires two-factor authentication on the account.
3. **Primary category:** Security. **Secondary category:** Continuous integration.
4. GitHub checks that the name "Wardmap" is unique on the Marketplace. If it is taken, change `name:` in `action.yml` to "Wardmap CI blast radius" and release again.
5. Click **Update release**.

## Listing text (taken from action.yml and the README)

- **Name:** Wardmap
- **Description:** Map what a compromised CI credential can reach (secrets and cloud roles via GitHub OIDC) and gate on new reach.
- **Icon / colour:** map / orange

## Suggested usage snippet for the listing README section

```yaml
permissions:
  contents: read
  actions: read
  security-events: write
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with: { persist-credentials: false }
  - uses: Breaktroughf1/wardmap@2b12f444a1a660ed604283d48a38d0cc00ff04a6 # v1.1.0
    with:
      mode: offline
      fail-on: high
```

`2b12f444a1a660ed604283d48a38d0cc00ff04a6` is the commit the v1.1.0 tag points to; README.md uses the same pin.
