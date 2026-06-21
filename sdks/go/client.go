package promptsentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is used when no base URL is supplied.
const DefaultBaseURL = "http://localhost:8000"

// DefaultRetries is the default number of retry attempts (in addition to the
// initial try) for transient failures.
const DefaultRetries = 2

// DefaultTimeout is the default per-request timeout when the caller does not
// supply a custom *http.Client.
const DefaultTimeout = 10 * time.Second

// APIError is returned for non-2xx HTTP responses. It carries the status code
// so callers can branch on, e.g., 401 Unauthorized.
//
// APIError never includes prompt or response bodies in a way that would leak
// secrets beyond the server's own error message; callers should treat Body as
// diagnostic only.
type APIError struct {
	StatusCode int
	// Endpoint is the path that produced the error, e.g. "/v1/screen/input".
	Endpoint string
	// Body is the (possibly truncated) server error payload, for diagnostics.
	Body string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("promptsentinel: %s returned HTTP %d: %s", e.Endpoint, e.StatusCode, e.Body)
}

// Unauthorized reports whether the error is an HTTP 401, i.e. a missing or
// invalid bearer token.
func (e *APIError) Unauthorized() bool { return e.StatusCode == http.StatusUnauthorized }

// TransportError wraps a network/transport-level failure (timeout, connection
// refused, DNS, etc.) that occurred while talking to the service. These are the
// errors the client will retry.
type TransportError struct {
	Endpoint string
	Err      error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("promptsentinel: transport error calling %s: %v", e.Endpoint, e.Err)
}

func (e *TransportError) Unwrap() error { return e.Err }

// Client is a configured PromptSentinel HTTP client. Construct it with
// NewClient. A zero Client is not ready for use; prefer NewClient.
//
// Client is safe for concurrent use by multiple goroutines.
type Client struct {
	// BaseURL is the service root, e.g. "http://localhost:8000". No trailing slash.
	BaseURL string
	// Token, when non-empty, is sent as "Authorization: Bearer <token>".
	Token string
	// HTTPClient performs the requests; its Timeout governs per-request deadlines.
	HTTPClient *http.Client
	// Retries is the number of additional attempts for transient failures
	// (network errors, HTTP 5xx, and 429). Non-transient errors are not retried.
	Retries int
}

// Option configures a Client in NewClient.
type Option func(*Client)

// WithBaseURL sets the service base URL (trailing slashes are trimmed).
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		if baseURL != "" {
			c.BaseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

// WithToken sets the optional bearer token used for service-level auth.
func WithToken(token string) Option {
	return func(c *Client) { c.Token = token }
}

// WithTimeout sets the per-request timeout on the underlying *http.Client.
// It is ignored if WithHTTPClient is used to supply a fully custom client.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		if timeout > 0 {
			c.HTTPClient.Timeout = timeout
		}
	}
}

// WithRetries sets the number of additional retry attempts for transient
// failures. A negative value is clamped to 0.
func WithRetries(retries int) Option {
	return func(c *Client) {
		if retries < 0 {
			retries = 0
		}
		c.Retries = retries
	}
}

// WithHTTPClient supplies a fully custom *http.Client (e.g. with custom
// transport, proxy, or TLS config). When set, WithTimeout has no effect.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.HTTPClient = hc
		}
	}
}

// NewClient builds a Client with sensible defaults: BaseURL=DefaultBaseURL,
// Retries=DefaultRetries, and an *http.Client with DefaultTimeout. Override any
// of these with the provided options.
func NewClient(opts ...Option) *Client {
	c := &Client{
		BaseURL:    DefaultBaseURL,
		Retries:    DefaultRetries,
		HTTPClient: &http.Client{Timeout: DefaultTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: DefaultTimeout}
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if c.Retries < 0 {
		c.Retries = 0
	}
	return c
}

// BuildSystemPrompt calls POST /v1/system-prompt/build. Run this once at deploy
// time: persist the returned Canary and feed HardenedSystemPrompt to your LLM.
func (c *Client) BuildSystemPrompt(ctx context.Context, basePrompt string) (*BuildResult, error) {
	body := map[string]any{"base_prompt": basePrompt}
	var out BuildResult
	if err := c.do(ctx, "/v1/system-prompt/build", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ScreenInput calls POST /v1/screen/input. Pass untrustedContext for any
// retrieved/third-party text mixed into the turn; pass "" if there is none.
//
// When the returned InputResult.Allowed is false, return InputResult.Refusal to
// the user and do NOT call your model.
func (c *Client) ScreenInput(ctx context.Context, userInput, untrustedContext string) (*InputResult, error) {
	body := map[string]any{"user_input": userInput}
	if untrustedContext != "" {
		body["untrusted_context"] = untrustedContext
	}
	var out InputResult
	if err := c.do(ctx, "/v1/screen/input", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ScreenOutput calls POST /v1/screen/output. Pass the canary from
// BuildSystemPrompt to detect system-prompt leakage; pass "" to skip the canary
// check. systemPrompt is optional context for output scanning ("" is fine).
//
// Return OutputResult.Text to the user regardless of Allowed: it is either the
// cleared output or a refusal message.
func (c *Client) ScreenOutput(ctx context.Context, modelOutput, canary, systemPrompt string) (*OutputResult, error) {
	body := map[string]any{"model_output": modelOutput}
	if canary != "" {
		body["canary"] = canary
	}
	if systemPrompt != "" {
		body["system_prompt"] = systemPrompt
	}
	var out OutputResult
	if err := c.do(ctx, "/v1/screen/output", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Health calls GET /health.
func (c *Client) Health(ctx context.Context) (*Health, error) {
	var out Health
	if err := c.get(ctx, "/health", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Version calls GET /version.
func (c *Client) Version(ctx context.Context) (*Version, error) {
	var out Version
	if err := c.get(ctx, "/version", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// do issues a POST with a JSON body and decodes the JSON response into out.
func (c *Client) do(ctx context.Context, endpoint string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("promptsentinel: encoding request for %s: %w", endpoint, err)
	}
	return c.send(ctx, http.MethodPost, endpoint, raw, out)
}

// get issues a GET and decodes the JSON response into out.
func (c *Client) get(ctx context.Context, endpoint string, out any) error {
	return c.send(ctx, http.MethodGet, endpoint, nil, out)
}

// send performs the request with retry/backoff and decodes a 2xx JSON body.
func (c *Client) send(ctx context.Context, method, endpoint string, raw []byte, out any) error {
	url := c.BaseURL + endpoint
	var lastErr error

	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			if err := backoff(ctx, attempt); err != nil {
				return err
			}
		}

		var reqBody io.Reader
		if raw != nil {
			reqBody = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
		if err != nil {
			return fmt.Errorf("promptsentinel: building request for %s: %w", endpoint, err)
		}
		if raw != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Accept", "application/json")
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			// Honor caller cancellation immediately; do not retry.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return &TransportError{Endpoint: endpoint, Err: ctxErr}
			}
			lastErr = &TransportError{Endpoint: endpoint, Err: err}
			continue // transport errors are transient -> retry
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			defer resp.Body.Close()
			if out == nil {
				io.Copy(io.Discard, resp.Body)
				return nil
			}
			if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
				return fmt.Errorf("promptsentinel: decoding response from %s: %w", endpoint, err)
			}
			return nil
		}

		// Non-2xx: drain the body for diagnostics, then decide retry vs. abort.
		errBody := readErrBody(resp.Body)
		resp.Body.Close()
		apiErr := &APIError{StatusCode: resp.StatusCode, Endpoint: endpoint, Body: errBody}

		if isRetryableStatus(resp.StatusCode) {
			lastErr = apiErr
			continue
		}
		return apiErr // e.g. 401, 4xx -> not retried
	}

	if lastErr == nil {
		lastErr = errors.New("promptsentinel: request failed with no error recorded")
	}
	return lastErr
}

// backoff sleeps with exponential delay (200ms, 400ms, 800ms, ...) while
// respecting context cancellation.
func backoff(ctx context.Context, attempt int) error {
	delay := time.Duration(200*(1<<(attempt-1))) * time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// isRetryableStatus reports whether an HTTP status warrants a retry: 5xx and
// 429 (rate limited). 4xx (incl. 401) are client errors and are not retried.
func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || (code >= 500 && code <= 599)
}

// readErrBody reads a bounded amount of the error body for diagnostics.
func readErrBody(r io.Reader) string {
	const max = 2048
	data, _ := io.ReadAll(io.LimitReader(r, max))
	s := strings.TrimSpace(string(data))
	if s == "" {
		return "(empty body)"
	}
	return s
}
