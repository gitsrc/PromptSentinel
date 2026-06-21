package promptsentinel

import "context"

// ModelFunc is the business callback that invokes your LLM. It receives the
// effective text to send to the model — the hardened system prompt when one is
// configured on the GuardRequest, otherwise the sanitized user input — and
// returns the model's raw output string.
//
// Returning a non-nil error aborts the guard flow and surfaces the error from
// Guard without screening any output.
type ModelFunc func(modelInput string) (string, error)

// GuardRequest bundles the inputs for the standard 3-step protected flow.
type GuardRequest struct {
	// UserInput is the end-user's input (required).
	UserInput string
	// UntrustedContext is optional retrieved/third-party text mixed into the turn.
	UntrustedContext string
	// Canary, if set, is passed to ScreenOutput to detect system-prompt leakage.
	Canary string
	// HardenedSystemPrompt, if set, is passed to the ModelFunc as the model
	// input (instead of the sanitized user input) and forwarded to ScreenOutput
	// as the system_prompt for output scanning.
	HardenedSystemPrompt string
}

// GuardResult is the outcome of the guard flow.
type GuardResult struct {
	// Text is the string to return to the user. When Blocked is true it is the
	// input refusal; otherwise it is the screened model output (which itself may
	// be a refusal if the output was blocked).
	Text string
	// Blocked is true when the input was rejected and the model was NOT called.
	Blocked bool
	// Input is the raw input-screening result.
	Input *InputResult
	// Output is the raw output-screening result; nil when the input was blocked.
	Output *OutputResult
}

// Guard runs the standard PromptSentinel 3-step flow:
//
//  1. ScreenInput(UserInput, UntrustedContext) — if not allowed, return the
//     refusal and DO NOT call the model.
//  2. Call the supplied ModelFunc with the hardened system prompt (if provided)
//     or the sanitized user input.
//  3. ScreenOutput(modelOutput, Canary, HardenedSystemPrompt) — return the safe
//     Text.
//
// On any transport/API error (or an error returned by call), Guard returns a
// nil result and the error.
func (c *Client) Guard(ctx context.Context, req GuardRequest, call ModelFunc) (*GuardResult, error) {
	in, err := c.ScreenInput(ctx, req.UserInput, req.UntrustedContext)
	if err != nil {
		return nil, err
	}
	if !in.Allowed {
		text := ""
		if in.Refusal != nil {
			text = *in.Refusal
		}
		return &GuardResult{Text: text, Blocked: true, Input: in}, nil
	}

	// Prefer the hardened system prompt as the model input when present; this is
	// what production callers feed their LLM. When no hardened prompt is supplied
	// we deliberately fall back to the sanitized input from ScreenInput (never an
	// empty string), so the callback always receives safe, cleaned text. This
	// keeps the Go SDK aligned with the Python SDK's sanitized-fallback behavior.
	modelInput := req.HardenedSystemPrompt
	if modelInput == "" {
		modelInput = in.Sanitized
	}

	modelOutput, err := call(modelInput)
	if err != nil {
		return nil, err
	}

	out, err := c.ScreenOutput(ctx, modelOutput, req.Canary, req.HardenedSystemPrompt)
	if err != nil {
		return nil, err
	}

	return &GuardResult{Text: out.Text, Blocked: false, Input: in, Output: out}, nil
}
