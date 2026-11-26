# Release and launch checklist

Pushing tags is the maintainer's job. Run these from your own machine, in a clone of this repository.

## 1. Cut v0.9.0 (proves the pipeline) ✅ done 26 Nov 2026: published as a pre-release; attestation verified

`v0.9.0` is the commit "Release v0.9.0" on `main` (`a0b3847`).

```bash
git fetch origin && git tag -a v0.9.0 a0b3847 -m "Wardmap v0.9.0 (pre-release)" && git push origin v0.9.0
```

The `release` workflow then:
- runs the tests;
- builds binaries for Linux, macOS and Windows;
- writes `checksums.txt`;
- attests build provenance;
- publishes a **pre-release** with the CHANGELOG section as notes.

Verify one asset:

```bash
gh release download v0.9.0 --repo Breaktroughf1/wardmap --pattern '*darwin_arm64*' --pattern checksums.txt
```

```bash
gh attestation verify wardmap_v0.9.0_darwin_arm64 --repo Breaktroughf1/wardmap && shasum -a 256 -c checksums.txt --ignore-missing
```

**Done when:** the attestation verifies, the checksum matches, and `./wardmap_v0.9.0_darwin_arm64 version` prints `wardmap v0.9.0`. On macOS you may need `xattr -d com.apple.quarantine <file>` first.

## 2. Before v1.0.0

- [x] Run a live scan on your own org and fix anything it shows. Done 26 Nov 2026: 33 repositories, no IOCs; the gaps it exposed are fixed in v1.0.0.
- [ ] Scan 2–3 design-partner orgs, with their written consent. Only anonymised aggregates go into the blog post.
- [ ] Turn on private vulnerability reporting: Settings → Code security.
- [x] Do a trademark search for "Wardmap". Preliminary desk search done (docs/launch/name-check.md); a lawyer still needs to clear it, because WORDMAP is a close live US mark.
- [ ] Optionally, check the IOC packs against the primary posts and set `verified: primary` where they match.

## 3. Cut v1.0.0

The release commit is ready on `main`: "Fix gaps found by the first real-organisation scan" (`08c1f76`). The CHANGELOG is dated, the pre-release notice is gone, and the README Action pin points at this commit. Tag exactly that commit:

```bash
git pull && git tag -a v1.0.0 08c1f76c11324a01e12d11e5c866752f9c4abb45 -m "Wardmap v1.0.0" && git push origin v1.0.0
```

After the release is published:
- [ ] Publish the Action to the Marketplace (docs/launch/marketplace.md).
- [x] README Action snippet pinned to the v1.0.0 commit.

## 4. Launch day

- [ ] Day before: send the pre-brief messages (docs/launch/prebrief.md).
- [ ] Publish the blog post (docs/launch/blog-post.md) on the Breaktrough site.
- [ ] Post Show HN, then Reddit, LinkedIn, OpenSSF Slack and Indian communities (docs/launch/posts.md).
- [ ] Watch issues and discussions. Label each new issue within 24 hours.

## 5. The day after: triage and v1.0.1

- [ ] Fix confirmed bugs, then add a `## v1.0.1` CHANGELOG section and push the tag. **False negatives in trust evaluation come first**; SECURITY.md treats them as security bugs.
- [ ] Thank contributors in the release notes.
