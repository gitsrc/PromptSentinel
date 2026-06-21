// PromptSentinel JavaScript SDK
//
// A small, dependency-free client for the PromptSentinel self-hosted prompt
// security gateway. Built on the global `fetch` (Node >= 18 / modern browsers),
// uses `AbortController` for timeouts and does bounded exponential-backoff
// retries on transient failures (network errors, 5xx, 429).
//
// Boundary note: PromptSentinel is a *probabilistic* defense layer. It reduces
// the blast radius of prompt injection / leakage but cannot fully prevent it.
// Hard guarantees (least privilege, read-only RLS, egress controls, human in
// the loop) must live in your architecture, not in this SDK.
//
// Privacy note: this SDK never logs prompts, model output, canaries, or tokens.

const DEFAULT_BASE_URL = "http://localhost:8000";
const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_RETRIES = 2;

/**
 * Error thrown for every failure surfaced by the SDK.
 *
 * `kind` lets callers branch without string-matching messages:
 *   - "timeout"     request exceeded the configured timeout
 *   - "network"     connection failed / fetch threw
 *   - "unauthorized" HTTP 401 (missing or wrong bearer token)
 *   - "http"        any other non-2xx response
 *   - "parse"       2xx body was not valid JSON
 */
export class GuardError extends Error {
  /**
   * @param {string} message
   * @param {object} [opts]
   * @param {string} [opts.kind]
   * @param {number} [opts.status]
   * @param {unknown} [opts.cause]
   */
  constructor(message, opts = {}) {
    super(message);
    this.name = "GuardError";
    this.kind = opts.kind ?? "http";
    this.status = opts.status;
    if (opts.cause !== undefined) {
      this.cause = opts.cause;
    }
  }
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Retry only transient failures. Application-level 4xx (other than 429) are
// deterministic and must not be retried.
function isRetriableStatus(status) {
  return status === 429 || (status >= 500 && status <= 599);
}

/**
 * PromptSentinel API client.
 */
export class Client {
  /**
   * @param {object} [options]
   * @param {string} [options.baseUrl="http://localhost:8000"]
   * @param {string|null} [options.token=null]   optional bearer token
   * @param {number} [options.timeout=10000]     per-attempt timeout in ms
   * @param {number} [options.retries=2]         retry count for transient errors
   * @param {typeof fetch} [options.fetch]       override fetch (mainly for tests)
   */
  constructor(options = {}) {
    const {
      baseUrl = DEFAULT_BASE_URL,
      token = null,
      timeout = DEFAULT_TIMEOUT_MS,
      retries = DEFAULT_RETRIES,
      fetch: fetchImpl,
    } = options;

    // Normalize: strip trailing slashes so we can safely concatenate paths.
    this.baseUrl = String(baseUrl).replace(/\/+$/, "");
    this.token = token;
    this.timeout = timeout;
    this.retries = Math.max(0, retries | 0);
    // Capture the fetch implementation lazily at call time when not injected,
    // so tests can swap `globalThis.fetch` per case.
    this._fetch = fetchImpl;
  }

  _resolveFetch() {
    const fn = this._fetch ?? globalThis.fetch;
    if (typeof fn !== "function") {
      throw new GuardError("global fetch is not available; provide options.fetch", {
        kind: "network",
      });
    }
    return fn;
  }

  /**
   * Perform a single HTTP request with timeout + retry/backoff.
   * @param {string} method
   * @param {string} path
   * @param {object|undefined} body
   * @returns {Promise<any>} parsed JSON
   */
  async _request(method, path, body) {
    const fetchFn = this._resolveFetch();
    const url = this.baseUrl + path;
    const headers = { Accept: "application/json" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }
    const payload = body === undefined ? undefined : JSON.stringify(body);

    let lastError;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt > 0) {
        // Exponential backoff: 100ms, 200ms, 400ms, ...
        await sleep(100 * 2 ** (attempt - 1));
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);

      let response;
      try {
        response = await fetchFn(url, {
          method,
          headers,
          body: payload,
          signal: controller.signal,
        });
      } catch (err) {
        clearTimeout(timer);
        // AbortController.abort() surfaces as an AbortError.
        if (err && err.name === "AbortError") {
          lastError = new GuardError(
            `request to ${method} ${path} timed out after ${this.timeout}ms`,
            { kind: "timeout", cause: err }
          );
        } else {
          lastError = new GuardError(
            `network error calling ${method} ${path}`,
            { kind: "network", cause: err }
          );
        }
        continue; // both timeout and network errors are retriable
      }
      clearTimeout(timer);

      if (response.status === 401) {
        // Deterministic auth failure: do not retry, raise immediately.
        throw new GuardError(
          "unauthorized (401): missing or invalid bearer token",
          { kind: "unauthorized", status: 401 }
        );
      }

      if (!response.ok) {
        if (isRetriableStatus(response.status) && attempt < this.retries) {
          lastError = new GuardError(
            `server returned ${response.status} for ${method} ${path}`,
            { kind: "http", status: response.status }
          );
          continue;
        }
        // Non-retriable (or out of retries): try to extract a server detail.
        let detail = "";
        try {
          const errBody = await response.json();
          if (isPlainObject(errBody) && typeof errBody.detail === "string") {
            detail = `: ${errBody.detail}`;
          }
        } catch {
          /* ignore body parse failures on error responses */
        }
        throw new GuardError(
          `server returned ${response.status} for ${method} ${path}${detail}`,
          { kind: "http", status: response.status }
        );
      }

      try {
        return await response.json();
      } catch (err) {
        throw new GuardError(
          `failed to parse JSON response from ${method} ${path}`,
          { kind: "parse", cause: err }
        );
      }
    }

    // Exhausted all attempts on a retriable failure.
    throw lastError;
  }

  /**
   * GET /health
   * @returns {Promise<import("./index.js").HealthResult>}
   */
  async health() {
    const data = await this._request("GET", "/health");
    return {
      status: String(data.status ?? ""),
      team: String(data.team ?? ""),
      agent: String(data.agent ?? ""),
      llmGuard: Boolean(data.llm_guard),
      llmJudge: Boolean(data.llm_judge),
      protectedTerms: Number(data.protected_terms ?? 0),
      // Operating mode of the gateway (e.g. "enforce", "shadow"); empty when absent.
      mode: String(data.mode ?? ""),
      // Whether the ML injection classifier is loaded server-side.
      mlClassifier: Boolean(data.ml_classifier),
    };
  }

  /**
   * GET /version
   * @returns {Promise<import("./index.js").VersionResult>}
   */
  async version() {
    const data = await this._request("GET", "/version");
    return {
      service: String(data.service ?? ""),
      version: String(data.version ?? ""),
      scanners: isPlainObject(data.scanners) ? { ...data.scanners } : {},
    };
  }

  /**
   * POST /v1/system-prompt/build
   * Step 1 (deploy-time): harden a base prompt and plant a canary.
   * @param {string} basePrompt
   * @returns {Promise<import("./index.js").BuildResult>}
   */
  async buildSystemPrompt(basePrompt) {
    const data = await this._request("POST", "/v1/system-prompt/build", {
      base_prompt: String(basePrompt ?? ""),
    });
    return {
      hardenedSystemPrompt: String(data.hardened_system_prompt ?? ""),
      canary: String(data.canary ?? ""),
    };
  }

  /**
   * POST /v1/screen/input
   * Step 2 (request-time): screen user input before calling the model.
   * @param {string} userInput
   * @param {string|null} [untrustedContext]
   * @returns {Promise<import("./index.js").InputResult>}
   */
  async screenInput(userInput, untrustedContext = null) {
    const body = { user_input: String(userInput ?? "") };
    if (untrustedContext !== null && untrustedContext !== undefined) {
      body.untrusted_context = String(untrustedContext);
    }
    const data = await this._request("POST", "/v1/screen/input", body);
    return {
      allowed: Boolean(data.allowed),
      risk: Number(data.risk ?? 0),
      reasons: Array.isArray(data.reasons) ? data.reasons.map(String) : [],
      sanitized: String(data.sanitized ?? ""),
      refusal: data.refusal == null ? null : String(data.refusal),
      // Whether this verdict *would* block under enforce mode (true even in
      // shadow mode, where allowed stays true). Defaults to false when absent.
      wouldBlock: Boolean(data.would_block),
      // Gateway mode that produced this verdict; defaults to "enforce".
      mode: String(data.mode ?? "enforce"),
    };
  }

  /**
   * POST /v1/screen/output
   * Step 3 (pre-return): screen model output for leakage / canary triggers.
   * @param {string} modelOutput
   * @param {string|null} [canary]
   * @param {string|null} [systemPrompt]
   * @returns {Promise<import("./index.js").OutputResult>}
   */
  async screenOutput(modelOutput, canary = null, systemPrompt = null) {
    const body = { model_output: String(modelOutput ?? "") };
    if (canary !== null && canary !== undefined) {
      body.canary = String(canary);
    }
    if (systemPrompt !== null && systemPrompt !== undefined) {
      body.system_prompt = String(systemPrompt);
    }
    const data = await this._request("POST", "/v1/screen/output", body);
    return {
      allowed: Boolean(data.allowed),
      risk: Number(data.risk ?? 0),
      reasons: Array.isArray(data.reasons) ? data.reasons.map(String) : [],
      text: String(data.text ?? ""),
      // Whether this verdict *would* block under enforce mode (true even in
      // shadow mode, where allowed stays true). Defaults to false when absent.
      wouldBlock: Boolean(data.would_block),
      // Gateway mode that produced this verdict; defaults to "enforce".
      mode: String(data.mode ?? "enforce"),
    };
  }

  /**
   * High-level helper implementing the full three-step flow:
   *   1. screen input; if blocked, return the refusal (model is NOT called).
   *   2. otherwise invoke `callModel(hardenedSystemPrompt)` to get model output.
   *   3. screen output and return the safe text.
   *
   * @param {object} args
   * @param {string} args.userInput
   * @param {(systemPrompt: string) => (string | Promise<string>)} args.callModel
   *        Business callback. Receives the system prompt to use (the value of
   *        `args.systemPrompt`, which should be your hardened prompt); when
   *        `args.systemPrompt` is omitted it falls back to the sanitized input
   *        from screening. Must return the raw model output string.
   * @param {string|null} [args.untrustedContext]
   * @param {string|null} [args.canary]
   * @param {string|null} [args.systemPrompt]  hardened system prompt to pass to callModel
   * @returns {Promise<import("./index.js").GuardResult>}
   */
  async guard(args = {}) {
    const {
      userInput,
      callModel,
      untrustedContext = null,
      canary = null,
      systemPrompt = null,
    } = args;

    if (typeof callModel !== "function") {
      throw new GuardError("guard() requires a callModel function", {
        kind: "network",
      });
    }

    const input = await this.screenInput(userInput, untrustedContext);
    if (!input.allowed) {
      // Blocked: return the refusal verbatim; the model is never called.
      return {
        allowed: false,
        text: input.refusal ?? "",
        stage: "input",
        input,
        output: null,
      };
    }

    // Allowed: run the business model with the hardened system prompt. When the
    // caller did not supply a hardened prompt, fall back to the sanitized input
    // from screening (aligns with the Python/Go SDKs) rather than an empty
    // string, so the model still receives the cleaned content.
    const modelOutput = await callModel(systemPrompt ?? input.sanitized);

    const output = await this.screenOutput(
      String(modelOutput ?? ""),
      canary,
      systemPrompt
    );
    return {
      allowed: output.allowed,
      text: output.text,
      stage: "output",
      input,
      output,
    };
  }
}

export default Client;
