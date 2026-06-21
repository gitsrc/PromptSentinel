# PromptSentinel Python SDK

Typed, production-ready Python client for the [PromptSentinel](../../) self-hosted
LLM prompt-security service. It screens user input before you call your model and
screens model output before you return it, all over the stable PromptSentinel HTTP
contract.

- Python 3.9+
- Single dependency: [`httpx`](https://www.python-httpx.org/)
- Fully typed (`py.typed`), typed result objects (not raw dicts)
- Bounded exponential-backoff retries for transient failures
- Never logs prompts, responses, or your token

## Installation

```bash
pip install promptsentinel
```

From source (this repo):

```bash
git clone https://github.com/gitsrc/PromptSentinel.git
pip install ./PromptSentinel/sdks/python
```

## The three-step flow

PromptSentinel sits in front of your model as a security gate. The canonical
integration is three steps:

1. **Build time (once, at deploy):** harden your base system prompt and get a
   `canary`. Persist the canary.
2. **Per request:** screen the user input. If blocked, return the refusal and do
   **not** call your model. Otherwise call your model with the hardened prompt.
3. **Before responding:** screen the model output (passing the canary to detect
   leakage). Return the screened `text`.

### Manual usage

```python
from promptsentinel import Client

client = Client(base_url="http://localhost:8000", token=None, timeout=10.0, retries=2)

# 1) Build time (run once, persist the canary)
built = client.build_system_prompt("You are a helpful weather assistant.")
hardened = built.hardened_system_prompt
canary = built.canary

# 2) Per request
screened = client.screen_input("What is the weather?", untrusted_context=None)
if not screened.allowed:
    return screened.refusal          # blocked: return refusal, do NOT call the model

model_output = my_llm(hardened, "What is the weather?")   # your model call

# 3) Before responding
out = client.screen_output(model_output, canary=canary, system_prompt=hardened)
return out.text                       # always safe to return directly
```

### Using the `guard` helper

`guard()` wraps all three steps. The callback receives the hardened system prompt
(when you pass one) and must return the model output as a string.

```python
result = client.guard(
    user_input="What is the weather?",
    untrusted_context=None,                 # optional retrieved/3rd-party text
    canary=canary,                          # from build_system_prompt()
    hardened_system_prompt=hardened,
    call_model=lambda hardened: my_llm(hardened, "What is the weather?"),
)
return result.text                          # refusal or screened output, either way safe
```

If input screening blocks the request, `guard()` returns an `OutputResult` carrying
the refusal text and **never calls your model**. If your `call_model` callback
raises, `guard()` raises `GuardError` (the original exception is in `__cause__`).

## API surface

### `Client(base_url="http://localhost:8000", token=None, timeout=10.0, retries=2, transport=None)`

| Param | Meaning |
| --- | --- |
| `base_url` | Service base URL. |
| `token` | Optional bearer token. Sent as `Authorization: Bearer <token>` on every `/v1` request. |
| `timeout` | Per-request timeout in seconds. |
| `retries` | Additional attempts for transient failures (network errors, 5xx, 429). `2` -> up to 3 attempts, exponential backoff. |
| `transport` | Optional `httpx` transport (used for mocking in tests). |

`Client` is a context manager (`with Client(...) as c:`); otherwise call `c.close()`.

### Methods

- `build_system_prompt(base_prompt: str) -> BuildResult`
- `screen_input(user_input: str, untrusted_context: str | None = None) -> InputResult`
- `screen_output(model_output: str, canary: str | None = None, system_prompt: str | None = None) -> OutputResult`
- `guard(user_input, call_model, untrusted_context=None, canary=None, hardened_system_prompt=None) -> OutputResult`

### Result objects (all `@dataclass`)

- `BuildResult(hardened_system_prompt, canary)`
- `InputResult(allowed, risk, reasons, sanitized, refusal)`
- `OutputResult(allowed, risk, reasons, text)`

### Errors

| Exception | When |
| --- | --- |
| `PromptSentinelError` | Base class for all SDK errors. |
| `TransportError` | Network failure (timeout, connection refused) after retries. |
| `APIError` | Non-2xx HTTP status. Has `.status_code` and `.detail`. |
| `AuthError` | HTTP 401 (subclass of `APIError`). Missing/invalid token. |
| `GuardError` | Your `call_model` callback raised inside `guard()`. |

Only network errors, `5xx`, and `429` are retried. `401` and other `4xx` raise
immediately.

## Multi-language consistency

This SDK is one of several official PromptSentinel clients (Python, JavaScript, Go,
Java). They share one API surface, adapted to each language's idioms:

- One `Client` type: `baseUrl` (default `http://localhost:8000`), `timeout`,
  `retries` (exponential backoff, default 2), optional `token`.
- Methods `buildSystemPrompt` / `screenInput` / `screenOutput` returning **typed
  result objects** with contract-aligned fields. (Python uses `snake_case`:
  `build_system_prompt` / `screen_input` / `screen_output`.)
- A high-level `guard(...)` helper implementing the same three-step flow with a
  `(hardenedOrContext) -> modelOutputString` callback.
- The same retry policy (network / 5xx / 429 only) and typed errors, including a
  distinct auth error for 401.

## Boundaries and honest limitations

PromptSentinel reduces risk; it does not eliminate it.

- **Probabilistic.** Detection is heuristic and/or model-based. Expect both false
  positives and false negatives. `risk` is a score, not a guarantee.
- **Not a cure.** It cannot fully prevent prompt injection, jailbreaks, or data
  exfiltration. Determined attackers can find phrasings that pass screening.
- **Needs architectural defense-in-depth.** Treat screening as one layer. You still
  need least-privilege tool access, output/action allow-lists, human-in-the-loop for
  high-impact actions, rate limiting, and isolation of untrusted context. Always pass
  retrieved/third-party text via `untrusted_context` so it is screened too, and always
  pass the `canary` to `screen_output` to catch system-prompt leakage.
- **You own the fallback.** Decide deliberately what to do when the service is
  unavailable (fail closed vs. degraded mode); the SDK surfaces errors, it does not
  decide policy for you.

## Development

```bash
cd sdks/python
python3 -m pytest -q          # tests mock the HTTP layer; no running service needed
```

## License

Apache-2.0
