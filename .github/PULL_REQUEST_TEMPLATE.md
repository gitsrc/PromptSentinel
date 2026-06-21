## What & why

<!-- What does this PR change, and why? Link related issues. -->

## Checklist

- [ ] `make test` passes (service unit tests + SDK tests)
- [ ] `make benchmark-gate` passes — **recall / FPR did not regress** (required if you touched detection logic)
- [ ] No secrets / tokens / `.llmenv` / coverage artifacts committed
- [ ] Did **not** weaken the security core (`service/app/`) or any `fail-closed` wrapper just to make a test pass
- [ ] Data-residency preserved (no new network egress on the detection path)
- [ ] Docs updated if behavior / config changed
- [ ] 4-language SDKs kept consistent (if an SDK was touched)

> Golden rules & safety boundaries: see [AGENTS.md](../AGENTS.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).
