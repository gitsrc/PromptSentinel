# Contributing to PromptSentinel

> 贡献指南 — 本项目是**安全产品**。改检测逻辑必须过门禁(`make benchmark-gate` + 单测),
> 绝不为了让测试通过而削弱检测能力。详见下文与 [`AGENTS.md`](AGENTS.md)。

Thanks for your interest in improving **PromptSentinel**, a prompt-security
gateway that screens LLM input/output and hardens system prompts. Contributions
of all kinds are welcome: bug reports, detection rules, datasets, SDK fixes,
docs, and benchmarks.

Because this is a **security control protecting other systems**, contributions
are held to a higher bar than a typical app. Please read the **non-negotiable
safety baseline** below before you start. It mirrors the golden rules in
[`AGENTS.md`](AGENTS.md), which is the canonical reference for both humans and
AI coding agents.

---

## Code of Conduct

This project adopts the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating you agree to uphold it. Report unacceptable behavior through the
channel named in that document.

## Reporting security vulnerabilities

**Do not file public issues or PRs for security vulnerabilities.** Detection
bypasses, fail-open bugs, auth bypasses, and data-leak regressions must go
through the private process in [`SECURITY.md`](SECURITY.md).

---

## The safety baseline (read this first)

The security core is **`service/app/`** (`engine.py`, `patterns.py`,
`scanners/`, `config.py`, `main.py`). A contribution that violates any of the
following **will not be merged**:

1. **Never weaken detection to make a test pass.** If a test fails because the
   engine now catches something it shouldn't, fix the rule — don't loosen the
   detector. Teams customize behavior via `sentinel.config.yaml`, not by
   blunting the core.
2. **Fail closed.** Any engine exception must *block*, never silently allow.
   Preserve the `try/except` wrappers in `engine.py`
   (`screen_input` / `screen_output`).
3. **Never log or persist prompt/response bodies.** Telemetry records only
   reasons / risk / latency. No exceptions.
4. **Data residency.** All inference is local. Do not add network egress to the
   detection path. `use_llm_judge` (external call) stays off by default.
5. **Threat model is the prompt layer** — injection, jailbreak, system-prompt
   extraction, canary/identifier/secret/PII leak. **Do not** add
   content-moderation / toxicity rules or datasets.
6. **No secrets in the repo.** `.llmenv`, auth tokens, and keys are gitignored;
   keep it that way. Never commit credentials, even in tests or examples.
7. **The portal front end is zero-dependency** vanilla CSS/JS — no build step,
   no npm dependencies added to the portal front end.

When in doubt, **fail closed and ask** in an issue before opening a PR.

---

## Development environment

**Prerequisites**

- Python **3.11** (code is kept 3.9-compatible via `from __future__ import
  annotations`)
- Docker + Docker Compose (for the full stack / Web Console)
- For SDK work: Node.js 20, Go 1.21+, JDK 17+ with Maven

**Set up the service**

```bash
make install        # install service runtime deps (service/requirements.txt)
make test           # service unit tests
make selfcheck      # config validity + data-residency warnings
```

**Run the full stack**

```bash
docker compose up -d --build   # Web Console → http://127.0.0.1:18080
make down                      # stop it
```

Optional tiers install on demand: ML cascade
(`service/requirements-ml.txt` / `requirements-pg2.txt`) and NER
(`WITH_LLM_GUARD`, Presidio). The deterministic rule engine is always present
and is the zero-cost baseline.

---

## The workflow

1. **Open an issue first** for anything non-trivial (new rule, new dataset, SDK
   surface change, behavior change). Use the issue templates. This avoids wasted
   work and lets us flag safety concerns early.
2. **Fork & branch** from the default branch. Use a descriptive branch name
   (`fix/output-scanner-canary`, `rules/add-zh-injection`).
3. **Make the change** following the conventions below.
4. **Run the gates** (see next section) — the task is not done until they pass.
5. **Open a PR** and fill in the
   [pull request template](.github/PULL_REQUEST_TEMPLATE.md) honestly,
   including the checklist.

---

## ⚠️ After ANY change to detection logic

This is the most important rule for contributors. After touching
`service/app/` (rules, scanners, engine), the task is **not done** until both
of these pass locally:

```bash
cd service
python3 -m pytest -q          # unit tests (incl. de-obfuscation & shadow-mode regressions)
python3 -m benchmark.gate     # REGRESSION GATE — recall/FPR must not regress (exit 1 on drop)
```

Or from the repo root:

```bash
make test
make benchmark-gate
```

- If you **tightened** a rule, also confirm benign false-positive rate did
  **not** rise (check the `deepset` / `business_benign` sets via
  `make eval-regex`).
- `make benchmark-perf` reports QPS / p50 / p95 / p99 if your change could
  affect latency.

The same gate runs in CI and **blocks the merge** on regression.

### How to do common detection tasks

- **Add an injection rule** → `service/app/patterns.py` (`INJECTION_PHRASES`).
  Mine on a *train* split, validate on a *holdout* split, keep benign FPR at 0,
  then run the gate.
- **Add a dataset** → drop `service/benchmark/datasets/<name>.jsonl`
  (`{text,label,split}` per line) and register one line in
  `service/app/main.py` `_DATASETS`; optionally add a threshold in
  `benchmark/gate.py`.
- **Add/change an SDK method** → keep **all four** languages consistent (same
  fields, fail-closed on non-200 / network error). Add a test per language.

---

## Testing the SDKs

Keep the four SDKs in lockstep. Each must have a test for any surface change:

```bash
make sdk-py-test      # (cd sdks/python && python3 -m pytest -q)
make sdk-js-test      # (cd sdks/javascript && node --test)
make sdk-go-test      # (cd sdks/go && go test ./... ; also: go vet ./... && gofmt -l .)
make sdk-java-test    # (cd sdks/java && mvn -q test)   # needs JDK 17+
```

`make verify` runs everything that can execute on a typical dev machine
(service + benchmark + Python/JS/Go SDKs; Java needs a JVM and is run
separately).

For Go, `gofmt -l .` must print **nothing** and `go vet ./...` must be clean.

---

## Coding conventions

- **Python 3.11, 3.9-compatible.** Start modules with
  `from __future__ import annotations`. FastAPI sync endpoints run on a thread
  pool — any shared mutable state needs a lock (see `_METRICS` / rate buckets).
- **Tiered by cost.** Deterministic rules are the sub-millisecond baseline; ML
  (Llama Prompt Guard 2 ONNX) and NER (Presidio) are optional,
  gracefully-degrading tiers. New detection should degrade gracefully if an
  optional tier is absent.
- **Honest metrics.** Pure-attack sets have no benign samples, so
  precision/F1 are reported as `None` (recall + Wilson CI only). Don't
  manufacture a "1.0 precision" artifact.
- **Engine invariants.** Preserve fail-closed behavior, the eval bypass
  (`_apply_mode=False`, so shadow mode never skews benchmarks), and
  thread-safety.

---

## Commit & PR standards

- **Commit messages**: clear, imperative subject (`Add zh injection phrases`),
  body explaining *why* when not obvious. Group related changes; keep unrelated
  changes in separate PRs.
- **Commit authorship**: commits use the **maintainer identity**
  (`BlockCraftsman`). Per [`AGENTS.md`](AGENTS.md), do **not** add AI co-author
  trailers or tool/vendor branding to commits in this repository.
- **Keep PRs focused and reviewable.** A detection change + an unrelated refactor
  in one PR is hard to review safely — split them.
- **Sign off** that you have the right to contribute the code (it will be
  licensed under the project's [Apache-2.0 License](LICENSE)).

### Pull request checklist (also in the PR template)

- [ ] Tests pass (`make test`) and, if detection logic changed,
      `make benchmark-gate` passes with no regression.
- [ ] No prompt/response bodies logged or persisted; no network egress added to
      the detection path.
- [ ] No secrets, tokens, or real PII committed.
- [ ] The security core was not weakened to make a test pass.
- [ ] SDK changes are mirrored across all four languages with tests.
- [ ] Docs / `CHANGELOG.md` updated if user-facing behavior changed.

---

## License

By contributing, you agree that your contributions are licensed under the
project's [Apache License 2.0](LICENSE).

Thank you for helping make LLM applications safer. 谢谢你的贡献!
