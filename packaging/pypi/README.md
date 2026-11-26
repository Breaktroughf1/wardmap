# wardmap (PyPI)

Runs [Wardmap](https://github.com/Breaktroughf1/wardmap), which maps what one compromised CI credential can reach: GitHub Actions secrets and AWS, Azure and GCP identities via GitHub OIDC. It also hunts for wfx-loot and GhostAction indicators.

```sh
uvx wardmap local --dir . --repo your-org/your-repo -o snapshot.json
uvx wardmap scan -s snapshot.json
uvx wardmap hunt -s snapshot.json
```

or `pipx install wardmap` / `pip install wardmap`.

This package contains no binary and runs nothing at install time. On first run it downloads the Wardmap release archive for your platform from GitHub, checks it against the SHA-256 baked into this package (copied from the release's Sigstore-verified `checksums.txt` when the package was built in CI, and published to PyPI with trusted publishing and attestations), extracts only the `wardmap` binary into your user cache, and re-checks the binary's hash on every run. A mismatch stops it before anything runs.

The package version matches the Wardmap version it installs. Exit codes are Wardmap's: 0 ok, 1 threshold exceeded or new reach, 2 error (including a failed download or checksum mismatch). Other ways to install: Homebrew (`brew install breaktroughf1/tap/wardmap`), `go install`, the GitHub Action, the container image and signed release downloads; see the [README](https://github.com/Breaktroughf1/wardmap#install).
