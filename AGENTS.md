# AGENTS.md

Guidance for **AI coding agents** (Claude Code, Cursor, Copilot, Windsurf, …) working in this repository, and a concise contributor guide for humans. This project is **AI-native**: its structure, conventions, commands, and safety boundaries are made explicit so an agent can understand and change it correctly **and safely**.

English first; 中文摘要见末尾。

---

## What this project is

**PromptSentinel** is a prompt-security gateway that sits in front of an LLM. It:
- screens **input** (prompt injection / jailbreak / system-prompt extraction),
- screens **output** (canary leak / protected identifiers / secrets / PII),
- hardens the **system prompt** with a canary sentinel.

Sidecar, zero application rewrite, **local inference, data-residency safe**.

## Repository map

```
service/app/          # SECURITY CORE — engine.py / patterns.py / scanners/ / config.py / main.py. Do NOT weaken.
service/benchmark/    # Evaluation — run / gate / perf + 9 threat-model-aligned datasets
service/tests/        # Unit tests (44) incl. de-obfuscation & shadow-mode regressions
sdks/{python,javascript,go,java}/   # 4 SDKs — each with examples/ + tests
portal/               # Bundled Web Console (FastAPI BFF + zero-dependency front end)
docs/                 # Methodology / security / engineering report / overview
```

## Golden rules — read before editing

1. **The security core is `service/app/`.** Teams customize only via `sentinel.config.yaml`. **Never weaken detection to make a test pass.**
2. **fail-closed.** Any engine exception must *block*, never silently allow. Preserve the `try/except` wrappers in `engine.py` (`screen_input`/`screen_output`).
3. **Never log or persist prompt/response bodies.** Telemetry records only reasons / risk / latency.
4. **Data residency.** All inference is local. `use_llm_judge` (external call) is off by default; `selfcheck` warns if it points outside.
5. **Threat model is the prompt layer** (injection / extraction / leak) — **NOT** content safety / toxicity. Do not add content-moderation rules or datasets.
6. **The front end is zero-dependency** vanilla CSS/JS — no build step, no npm deps in the portal front end.

## Commands

```bash
docker compose up -d --build   # full stack → Web Console http://127.0.0.1:18080
make test                      # service unit tests + SDK tests
make selfcheck                 # config validity + data-residency warnings
make benchmark-gate            # REGRESSION GATE — recall/FPR must not regress (CI-enforced; exit 1 on drop)
make benchmark-perf            # QPS / p50 / p95 / p99
make eval-hybrid               # full public-dataset eval (rules + ML cascade)
```

Per-SDK:
```bash
(cd sdks/python     && python3 -m pytest -q)
(cd sdks/go         && go test ./... && go vet ./... && gofmt -l .)   # gofmt -l must print nothing
(cd sdks/javascript && npm test)
(cd sdks/java       && mvn -q -DskipTests package)                    # needs a JVM
```

## ⚠️ After ANY change to detection logic

The task is **not done** until both pass:
```bash
(cd service && python3 -m pytest -q && python3 -m benchmark.gate)
```
If you *tightened* a rule, also confirm benign FPR didn't rise (deepset / business_benign sets).

## How to do common tasks

- **Add an injection rule** → `service/app/patterns.py` `INJECTION_PHRASES`. Mine on a *train* split, validate on *holdout*, keep benign FPR at 0, then run the gate.
- **Add a dataset** → drop `service/benchmark/datasets/<name>.jsonl` (`{text,label,split}` per line) + register one line in `service/app/main.py` `_DATASETS`; optionally add a threshold in `benchmark/gate.py`.
- **Add/change an SDK method** → keep all 4 languages consistent (same fields, fail-closed on non-200/network). Add a test per language.
- **Touch the engine** → preserve fail-closed, the eval bypass `_apply_mode=False` (so shadow mode never skews benchmarks), and thread-safety (`_METRICS` / rate buckets are lock-guarded).
- **Front-end view** → register via `PS.view(name, {render})`, inject a scoped `<style>`, reuse CSS vars (`--accent/--ok/--warn/--block/--purple`).

## Conventions

- Python 3.11, kept 3.9-compatible (`from __future__ import annotations`). FastAPI sync endpoints run on a thread pool — shared mutable state needs a lock.
- **Tiered by cost**: deterministic rules are the zero-cost baseline (sub-ms); ML (Llama Prompt Guard 2 ONNX) and NER (Presidio, `WITH_LLM_GUARD`) are optional, gracefully-degrading tiers.
- **Honesty in metrics**: pure-attack sets have no benign samples → precision/F1 are `None` (recall + Wilson CI only). Don't report a "1.0 precision" artifact.
- **Commits**: the repo author is the maintainer (`BlockCraftsman`). Do **not** add AI co-author trailers or tool branding to commits.

## Safety rules for agents

This is a **security product** guarding other systems. When unsure, fail closed and ask. **Do not**:
- weaken/disable a scanner or remove a fail-closed wrapper to pass a test,
- add network egress to the detection path,
- log or persist request/response bodies,
- commit secrets (`.llmenv`, auth tokens) — they are gitignored; keep it that way.

## 中文摘要

PromptSentinel 是大模型前的提示词安全网关。**安全核心在 `service/app/`(勿削弱)**,团队只改 `sentinel.config.yaml`。改检测逻辑后**必须**跑 `make benchmark-gate` + 单测才算完成。不可破的底线:**fail-closed**(异常一律拦)、**数据不出域**、**绝不记录正文**、**威胁模型只针对提示词层**(非内容安全)、**前端零依赖**。提交时用维护者身份、不加 AI 署名或工具标识。
```