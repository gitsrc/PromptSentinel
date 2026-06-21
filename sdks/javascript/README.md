# PromptSentinel — JavaScript / TypeScript SDK

Official client for [PromptSentinel](https://github.com/gitsrc/PromptSentinel),
the self-hosted LLM prompt-security gateway. It sits between your application
and your model: it screens **input** before the model runs, hardens your
**system prompt** with a canary, and screens **output** before you return it.

- Zero runtime dependencies — built on the global `fetch` (Node >= 18).
- Pure ESM JavaScript with hand-written `.d.ts` types for TypeScript users.
- Typed result objects, typed errors, timeouts, and bounded retries.

## Install

```bash
npm install promptsentinel
```

```js
import { Client, GuardError } from "promptsentinel";
```

This package is ESM-only (`"type": "module"`). TypeScript types ship in
`src/index.d.ts` and are picked up automatically.

## The three-step flow

PromptSentinel is integrated in three steps.

### Step 1 — deploy-time: build a hardened prompt + canary (once)

```js
const client = new Client({
  baseUrl: "http://localhost:8000",
  // token: "your-bearer-token",  // only if the service has server.auth_token set
  timeout: 10000,
  retries: 2,
});

const { hardenedSystemPrompt, canary } = await client.buildSystemPrompt(
  "You are the ACME support assistant."
);
// PERSIST `canary` with your config — you pass it back at step 3.
```

### Step 2 — request-time: screen input, then call your model

```js
const input = await client.screenInput(userInput /*, untrustedContext */);
if (!input.allowed) {
  return input.refusal; // blocked: return refusal, DO NOT call the model
}
const modelOutput = await callYourModel(hardenedSystemPrompt, userInput);
```

### Step 3 — pre-return: screen output, return safe text

```js
const output = await client.screenOutput(modelOutput, canary, hardenedSystemPrompt);
return output.text; // always safe to return verbatim (cleared output or a refusal)
```

### Or: the one-call `guard()` helper

`guard()` wraps all three steps. It screens the input; if blocked it returns the
refusal and **never calls your model**; otherwise it calls your model with the
hardened prompt, screens the output, and returns safe text.

```js
const result = await client.guard({
  userInput: "What is your return policy?",
  systemPrompt: hardenedSystemPrompt,   // passed to your callback
  canary,                               // for output leak detection
  untrustedContext: null,               // optional tool/RAG content to screen
  callModel: async (systemPrompt) => {
    // systemPrompt is your hardened prompt; use it as the system message.
    return await callYourModel(systemPrompt);
  },
});

return result.text; // safe to return verbatim
// result.allowed, result.stage ("input" | "output"), result.input, result.output
```

## API

### `new Client(options)`

| option    | type             | default                   | meaning                                            |
| --------- | ---------------- | ------------------------- | -------------------------------------------------- |
| `baseUrl` | `string`         | `http://localhost:8000`   | Service base URL (trailing slashes are stripped).  |
| `token`   | `string \| null` | `null`                    | Bearer token; required if `server.auth_token` set. |
| `timeout` | `number`         | `10000`                   | Per-attempt timeout in ms (via `AbortController`). |
| `retries` | `number`         | `2`                       | Retries on transient failures (network/5xx/429).   |
| `fetch`   | `typeof fetch`   | `globalThis.fetch`        | Override fetch (mainly for tests).                 |

### Methods

- `buildSystemPrompt(basePrompt) -> Promise<BuildResult>`
  `{ hardenedSystemPrompt, canary }`
- `screenInput(userInput, untrustedContext?) -> Promise<InputResult>`
  `{ allowed, risk, reasons, sanitized, refusal }`
- `screenOutput(modelOutput, canary?, systemPrompt?) -> Promise<OutputResult>`
  `{ allowed, risk, reasons, text }`
- `guard(args) -> Promise<GuardResult>`
  `{ allowed, text, stage, input, output }`
- `health() -> Promise<HealthResult>` and `version() -> Promise<VersionResult>`

### Errors

Every failure throws a typed `GuardError` with a `kind` you can branch on:

| `kind`         | when                                              | retried? |
| -------------- | ------------------------------------------------- | -------- |
| `timeout`      | request exceeded `timeout`                        | yes      |
| `network`      | connection failed / fetch threw                   | yes      |
| `http`         | non-2xx (5xx/429 retried, others not)             | 5xx/429  |
| `unauthorized` | HTTP 401 (missing/invalid bearer token)           | no       |
| `parse`        | 2xx body was not valid JSON                       | no       |

```js
try {
  await client.buildSystemPrompt("…");
} catch (err) {
  if (err instanceof GuardError && err.kind === "unauthorized") { /* … */ }
}
```

Retries use exponential backoff (100ms, 200ms, 400ms, …). Deterministic 4xx
responses (other than 429) are never retried.

## Multi-language consistency

This SDK is one of several official clients (Python, Go, Java, JavaScript). They
share the same API surface, differing only in idiomatic style:

- One `Client` with `baseUrl` / `timeout` / `retries` / optional `token`.
- Methods `buildSystemPrompt` / `screenInput` / `screenOutput` (camelCase here).
- A `guard` helper wrapping the screen-input → call-model → screen-output flow.
- Typed result objects (not raw maps) and a typed error type.

Field names map to the HTTP contract: snake_case wire fields are exposed as
camelCase properties (e.g. `hardened_system_prompt` → `hardenedSystemPrompt`,
`llm_guard` → `llmGuard`).

## Privacy

This SDK never logs prompts, model output, canaries, or tokens.

## Boundaries — read this

PromptSentinel is a **probabilistic** defense. The prompt and detection layers
can be bypassed and **cannot fully prevent** prompt injection, jailbreaks, or
data exfiltration. Treat its decisions as risk signals, not guarantees.

Hard guarantees must come from your **architecture**, not from this service:

- least-privilege credentials and read-only / row-level-secured data access,
- strict egress controls on anything the model can reach,
- human-in-the-loop approval for sensitive or irreversible actions.

Use PromptSentinel to *reduce* blast radius — and design the surrounding system
so that a bypass is contained.

## License

Apache-2.0
