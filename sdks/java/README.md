# PromptSentinel Java Client

Official Java SDK for [PromptSentinel](https://github.com/gitsrc/PromptSentinel) — a
self-hosted, data-stays-home LLM prompt-safety guard service. It sits between
your business agent and your LLM as a "security checkpoint": screen input before
the model, screen output before the user, and harden your system prompt against
verbatim leaks.

- **Group / Artifact:** `io.promptsentinel:promptsentinel-client:1.0.0`
- **Java:** 17+ (model classes use `record`, GA in JDK 16; `pom.xml` sets `maven.compiler.release=17`)
- **Dependencies:** `com.fasterxml.jackson.core:jackson-databind` (HTTP via the
  built-in `java.net.http.HttpClient`)
- **License:** Apache-2.0

---

## Install

Maven:

```xml
<dependency>
  <groupId>io.promptsentinel</groupId>
  <artifactId>promptsentinel-client</artifactId>
  <version>1.0.0</version>
</dependency>
```

Gradle:

```gradle
implementation "io.promptsentinel:promptsentinel-client:1.0.0"
```

Build from source:

```bash
git clone https://github.com/gitsrc/PromptSentinel.git
cd PromptSentinel/sdks/java
mvn clean test     # run the unit tests (in-process HTTP stub, no live service)
mvn clean package  # build the jar
```

---

## Quick start (the three-step flow)

PromptSentinel's standard integration has three steps:

1. **Build (deploy-time, once):** harden your system prompt and mint a `canary`.
   **Persist the canary.**
2. **Per request:** screen the user input. If it is not allowed, return the
   refusal and **do not call the model**. Otherwise call your LLM with the
   hardened system prompt.
3. **Before returning:** screen the model output and return the safe `text`.

### Option A — let the SDK orchestrate it (`guard`)

```java
import io.promptsentinel.*;
import io.promptsentinel.models.*;

PromptSentinelClient client = PromptSentinelClient.builder()
        .baseUrl("http://localhost:8000")  // default
        .timeout(java.time.Duration.ofSeconds(15))
        .retries(2)                        // exponential backoff; default 2
        .token(null)                       // optional bearer token
        .build();

// Step 1 (once, at deploy): persist the canary.
BuildResult built = client.buildSystemPrompt("You are ACME's support assistant...");
String hardened = built.hardenedSystemPrompt();
String canary   = built.canary();

// Steps 2 + 3 (per request):
GuardResult result = client.guard(
        "How much is my latest invoice?",  // user_input
        null,                              // untrusted_context (RAG/tool output) or null
        hardened,                          // passed to your callback
        canary,                            // output leak detection
        (hardenedPrompt) -> yourLlm.chat(hardenedPrompt, userMessage));

// result.text() is ALWAYS safe to return to the end user.
return result.text();
```

If input screening blocks the request, `result.blockedAtInput()` is `true`, the
model callback is **never invoked**, and `result.text()` holds the refusal.

### Option B — call the three steps yourself

```java
// Step 2
InputResult in = client.screenInput(userInput, untrustedContext /* or null */);
if (!in.allowed()) {
    return in.refusal();          // return refusal; DO NOT call the model
}

// Call your model with the hardened system prompt
String raw = yourLlm.chat(hardened, in.sanitized());

// Step 3
OutputResult out = client.screenOutput(raw, canary, hardened);
return out.text();                // always return text()
```

---

## API surface

| Method | Maps to | Returns |
| --- | --- | --- |
| `buildSystemPrompt(basePrompt)` | `POST /v1/system-prompt/build` | `BuildResult(hardenedSystemPrompt, canary)` |
| `screenInput(userInput[, untrustedContext])` | `POST /v1/screen/input` | `InputResult(allowed, risk, reasons, sanitized, refusal)` |
| `screenOutput(modelOutput[, canary[, systemPrompt]])` | `POST /v1/screen/output` | `OutputResult(allowed, risk, reasons, text)` |
| `guard(userInput, untrustedContext, hardenedSystemPrompt, canary, model)` | all three | `GuardResult(text, blockedAtInput, inputResult, outputResult)` |
| `health()` | `GET /health` | `HealthResult` |
| `version()` | `GET /version` | `VersionResult` |

Results are **typed records**, not raw maps. The `guard` callback is the
functional interface `ModelInvocation`: `(hardenedSystemPrompt) -> String`.

### Authentication

If the service was started with `server.auth_token`, every `/v1` request must
carry `Authorization: Bearer <token>`. Configure it once on the client:

```java
PromptSentinelClient.builder().token("my-token").build();
```

A missing/invalid token yields HTTP 401, surfaced as a typed
`PromptSentinelException` with `kind() == UNAUTHORIZED` (`isUnauthorized()`).

### Errors and retries

All failures raise `PromptSentinelException` with a `kind()`:

- `TIMEOUT` — request exceeded the per-attempt timeout
- `CONNECTION` — connection refused / DNS / TLS / I/O error
- `UNAUTHORIZED` — HTTP 401 (`statusCode() == 401`)
- `HTTP_STATUS` — other 4xx / 5xx (`statusCode()` carries the code)
- `DECODE` — malformed JSON response
- `INVALID_ARGUMENT` — bad arguments / serialization failure

**Retries** (default 2, exponential backoff) apply **only** to transient
failures: connection errors, timeouts, HTTP 429, and HTTP 5xx. 401 and other 4xx
are never retried. The SDK never logs prompt or response bodies.

---

## Cross-language consistency

This SDK mirrors the official Python, JavaScript, and Go clients exactly:

- Same `Client` shape: `baseUrl` (default `http://localhost:8000`), `timeout`,
  `retries` (exponential backoff, default 2), optional `token`.
- Same methods: `buildSystemPrompt` / `screenInput` / `screenOutput`, plus the
  `guard` helper that runs the three-step flow with a model callback.
- Same typed result objects with fields matching the HTTP contract verbatim.
- Same retry policy (network / 5xx / 429 only) and the same leak-safe logging
  discipline (prompts and responses are never logged).

Switching languages requires no change in mental model — only idiomatic syntax.

---

## Boundaries (read this)

PromptSentinel is a **probabilistic** defense, not a cure.

- The prompt layer and the detection layer **can be bypassed**. Treat screening
  as defense-in-depth, not a hard guarantee.
- Hard security properties — authorization, data exfiltration limits, least
  privilege — **must be enforced by your architecture** (read-only / row-level
  security, egress controls, human-in-the-loop), not by this service.
- A "allowed" verdict means "no known attack pattern matched", **not** "safe".
  A "blocked" verdict means "matched a pattern", which can include false
  positives.

Use PromptSentinel as one layer in a defense-in-depth design, always backed by
architectural controls.

---

## Example

See [`examples/Example.java`](examples/Example.java) for a fully commented,
end-to-end usage demo against a live service.
