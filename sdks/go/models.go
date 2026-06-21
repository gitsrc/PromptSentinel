// Package promptsentinel is the official Go client SDK for PromptSentinel,
// a self-hosted LLM prompt-security gateway.
//
// The SDK mirrors the HTTP contract of the PromptSentinel service one-to-one
// and exposes a small, idiomatic surface:
//
//   - Client            — configured HTTP client with retries and optional auth.
//   - BuildSystemPrompt  — harden a base system prompt and obtain a canary.
//   - ScreenInput        — screen untrusted user input before calling your model.
//   - ScreenOutput       — screen model output (canary leak / PII) before returning.
//   - Guard              — high-level helper that runs the standard 3-step flow.
//
// The SDK never logs prompt or response bodies.
package promptsentinel

// BuildResult is the response of POST /v1/system-prompt/build.
//
// HardenedSystemPrompt is the prompt you should feed to your LLM at request
// time. Canary is an embedded marker; store it and pass it to ScreenOutput so
// the service can detect system-prompt leakage in model output.
type BuildResult struct {
	HardenedSystemPrompt string `json:"hardened_system_prompt"`
	Canary               string `json:"canary"`
}

// InputResult is the response of POST /v1/screen/input.
//
// When Allowed is false the business code MUST return Refusal to the end user
// and MUST NOT call the model. Sanitized is the (possibly cleaned) input that
// is safe to forward when Allowed is true.
type InputResult struct {
	Allowed bool `json:"allowed"`
	// Risk is a probabilistic score in [0,1]; higher means more suspicious.
	Risk float64 `json:"risk"`
	// Reasons lists the scanner verdicts that contributed to the decision.
	Reasons []string `json:"reasons"`
	// Sanitized is the input cleaned for forwarding (valid when Allowed).
	Sanitized string `json:"sanitized"`
	// Refusal is the canned refusal text; non-nil only when Allowed is false.
	Refusal *string `json:"refusal"`
	// WouldBlock reports whether the service WOULD have blocked this input under
	// enforcing policy. In shadow/monitor mode Allowed may stay true while
	// WouldBlock is true. Defaults to false when the server omits the field.
	WouldBlock bool `json:"would_block"`
	// Mode is the active enforcement mode (e.g. "enforce", "shadow"). Empty when
	// the server omits the field; treat empty as enforcing.
	Mode string `json:"mode"`
}

// OutputResult is the response of POST /v1/screen/output.
//
// Text is always the string the business code should return to the user: it is
// either the cleared model output (when Allowed is true) or a refusal message
// (when Allowed is false). Either way, returning Text is safe.
type OutputResult struct {
	Allowed bool     `json:"allowed"`
	Risk    float64  `json:"risk"`
	Reasons []string `json:"reasons"`
	// Text is the safe-to-return text (cleared output or refusal).
	Text string `json:"text"`
	// WouldBlock reports whether the service WOULD have blocked this output under
	// enforcing policy. In shadow/monitor mode Allowed may stay true while
	// WouldBlock is true. Defaults to false when the server omits the field.
	WouldBlock bool `json:"would_block"`
	// Mode is the active enforcement mode (e.g. "enforce", "shadow"). Empty when
	// the server omits the field; treat empty as enforcing.
	Mode string `json:"mode"`
}

// Health is the response of GET /health.
type Health struct {
	Status         string `json:"status"`
	Team           string `json:"team"`
	Agent          string `json:"agent"`
	LLMGuard       bool   `json:"llm_guard"`
	LLMJudge       bool   `json:"llm_judge"`
	ProtectedTerms int    `json:"protected_terms"`
	// Mode is the active enforcement mode (e.g. "enforce", "shadow"). Empty when
	// the server omits the field.
	Mode string `json:"mode"`
	// MLClassifier reports whether the ML-based injection classifier is loaded
	// and active on the service. Defaults to false when the server omits it.
	MLClassifier bool `json:"ml_classifier"`
}

// Version is the response of GET /version.
type Version struct {
	Service  string          `json:"service"`
	Version  string          `json:"version"`
	Scanners map[string]bool `json:"scanners"`
}
