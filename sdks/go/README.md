# promptsentinel-go

Official Go client SDK for [PromptSentinel](../../) — a self-hosted LLM
prompt-security gateway. The SDK mirrors the service HTTP contract one-to-one
and gives you a typed, idiomatic surface plus a one-call `Guard` helper for the
standard protected request flow.

- Zero external dependencies (standard library only).
- Context-aware methods, typed results, typed errors.
- Configurable timeout, exponential-backoff retries, and optional bearer auth.
- Never logs prompt or response bodies.

## Install

```sh
go get github.com/gitsrc/PromptSentinel/sdks/go
```

```go
import ps "github.com/gitsrc/PromptSentinel/sdks/go"
```

Requires Go 1.21+.

## The three-step flow

PromptSentinel sits in front of your LLM as a security checkpoint. Standard
integration:

1. **Build (once, at deploy time).** Harden your base system prompt and obtain a
   `canary`. Persist both.
2. **Screen input (per request).** If the input is not allowed, return the
   refusal and **do not call your model**.
3. **Screen output (before responding).** Pass the canary; return the safe text.

### Quick start with `Guard`

`Guard` runs all three steps for you. Your only job is the model callback.

```go
client := ps.NewClient(
    ps.WithBaseURL("http://localhost:8000"),
    ps.WithToken(os.Getenv("PROMPTSENTINEL_TOKEN")), // optional
    ps.WithTimeout(10*time.Second),
    ps.WithRetries(2),
)

ctx := context.Background()

// Step ① (once at deploy): keep `built.HardenedSystemPrompt` and `built.Canary`.
built, err := client.BuildSystemPrompt(ctx, "You are the ACME support assistant.")
if err != nil { /* handle */ }

// Steps ②③ (per request):
res, err := client.Guard(ctx, ps.GuardRequest{
    UserInput:            "How do I reset my password?",
    UntrustedContext:     "",                       // retrieved/3rd-party text, if any
    Canary:               built.Canary,
    HardenedSystemPrompt: built.HardenedSystemPrompt,
}, func(modelInput string) (string, error) {
    // modelInput is the hardened system prompt. Call your LLM and return text.
    return callYourLLM(modelInput, "How do I reset my password?")
})
if err != nil { /* handle */ }

// res.Text is always safe to return to the user (cleared output or a refusal).
fmt.Println(res.Text)
```

### Manual flow (equivalent to `Guard`)

```go
in, err := client.ScreenInput(ctx, userInput, untrustedContext)
if err != nil { /* handle */ }
if !in.Allowed {
    return *in.Refusal // blocked: do NOT call the model
}

modelOutput, err := callYourLLM(built.HardenedSystemPrompt, in.Sanitized)
if err != nil { /* handle */ }

out, err := client.ScreenOutput(ctx, modelOutput, built.Canary, built.HardenedSystemPrompt)
if err != nil { /* handle */ }
return out.Text // safe text (cleared output or refusal)
```

A complete, runnable example is in [`examples/main.go`](examples/main.go):

```sh
go run ./examples
```

## API surface

| Method | Endpoint | Returns |
| --- | --- | --- |
| `NewClient(opts ...Option)` | — | `*Client` |
| `BuildSystemPrompt(ctx, basePrompt)` | `POST /v1/system-prompt/build` | `*BuildResult` |
| `ScreenInput(ctx, userInput, untrustedContext)` | `POST /v1/screen/input` | `*InputResult` |
| `ScreenOutput(ctx, modelOutput, canary, systemPrompt)` | `POST /v1/screen/output` | `*OutputResult` |
| `Guard(ctx, GuardRequest, ModelFunc)` | (composes input+output) | `*GuardResult` |
| `Health(ctx)` / `Version(ctx)` | `GET /health` `/version` | `*Health` / `*Version` |

Optional string arguments use `""` to mean "omit": e.g. pass `""` for
`untrustedContext`, `canary`, or `systemPrompt` and the SDK leaves the field out
of the request body.

### Options

- `WithBaseURL(string)` — default `http://localhost:8000` (trailing slash trimmed).
- `WithToken(string)` — sets `Authorization: Bearer <token>`; empty = no header.
- `WithTimeout(time.Duration)` — per-request timeout (default 10s).
- `WithRetries(int)` — extra attempts for transient failures (default 2).
- `WithHTTPClient(*http.Client)` — supply a fully custom client (overrides `WithTimeout`).

## Errors

All methods return a typed `error`:

- `*APIError` — non-2xx responses. Carries `StatusCode`, `Endpoint`, and a
  bounded `Body`. Use `(*APIError).Unauthorized()` to detect HTTP 401 (missing
  or invalid token).
- `*TransportError` — network/timeout/connection failures (wraps the underlying
  error via `Unwrap`).

```go
var apiErr *ps.APIError
if errors.As(err, &apiErr) && apiErr.Unauthorized() {
    // refresh / supply a valid bearer token
}
```

**Retry policy:** only network errors, HTTP 5xx, and HTTP 429 are retried, with
exponential backoff (200ms, 400ms, 800ms, ...). Client errors such as 401/4xx
are returned immediately. Context cancellation/deadline is never retried.

## Cross-language consistency

This SDK is one of several official clients (Go, Python, JavaScript, Java). All
of them expose the same shape, adapted to each language's idioms:

- A `Client` with `baseUrl` (default `http://localhost:8000`), `timeout`,
  `retries` (exponential backoff, default 2), and an optional `token`.
- Methods `buildSystemPrompt` / `screenInput` / `screenOutput` returning typed
  result objects whose fields match the HTTP contract exactly.
- A high-level `guard(...)` helper implementing the validate-input → (refuse or
  call model) → validate-output flow with a model callback.
- Identical error semantics: clear typed errors for timeouts, connection
  failures, and non-2xx (notably 401); retries limited to network/5xx/429.

## Boundaries and honest limits

PromptSentinel reduces risk; it does not eliminate it.

- **Probabilistic, not perfect.** Detection is heuristic/model-assisted. Expect
  both false positives (legitimate input blocked) and false negatives (a novel
  jailbreak slips through). The `risk` score is a signal, not a guarantee.
- **Not a root-cause fix.** Prompt injection is a structural property of mixing
  trusted instructions with untrusted text. Screening mitigates; it cannot make
  an LLM immune.
- **Architecture must back it up.** Treat model output as untrusted. Enforce
  least privilege on tools/data the model can reach, keep secrets out of the
  prompt, require human approval for high-impact actions, and add server-side
  authorization independent of anything the model "decides". The canary detects
  some system-prompt leaks but is not a substitute for not putting secrets in
  prompts.
- **No body logging.** This SDK never logs prompts or responses. Keep that
  discipline in your own application logs too.

## License

See the repository root.
