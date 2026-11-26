# Contributing

Thanks for helping. A few ground rules keep Wardmap trustworthy:

1. **Read-only forever.** No change may add non-GET requests or read secret values.
2. **No silent "safe".** When the evaluator meets something it does not understand, it must return *needs review*.
3. **Test vectors first.** Changes to `internal/oidc` need a test vector in `oidc_test.go` showing the claim set, the condition and the expected verdict.
4. **IOC packs** need primary-source references and honest confidence levels (see `docs/ioc-packs.md`).

```bash
make lint test fuzz
```

Pin any new GitHub Action to a full commit SHA with a version comment. Dependabot keeps them current with a 7-day cooldown.
