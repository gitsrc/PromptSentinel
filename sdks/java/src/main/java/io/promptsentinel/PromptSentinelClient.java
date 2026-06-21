package io.promptsentinel;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.promptsentinel.models.BuildResult;
import io.promptsentinel.models.GuardResult;
import io.promptsentinel.models.HealthResult;
import io.promptsentinel.models.InputResult;
import io.promptsentinel.models.OutputResult;
import io.promptsentinel.models.VersionResult;

import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Official Java client for the PromptSentinel prompt-safety guard service.
 *
 * <p>Built on {@link java.net.http.HttpClient} (JDK 11+) and Jackson. Instances
 * are immutable and thread-safe; create one and share it.
 *
 * <h2>Three-step integration</h2>
 * <ol>
 *   <li><b>Build (deploy-time, once):</b> {@link #buildSystemPrompt(String)} to
 *       obtain a hardened system prompt and a {@code canary}; persist the canary.</li>
 *   <li><b>Per request:</b> {@link #screenInput(String, String)} — if not allowed,
 *       return {@code refusal()} and do not call the model; otherwise call your LLM
 *       with the hardened system prompt.</li>
 *   <li><b>Before returning:</b> {@link #screenOutput(String, String, String)} —
 *       return {@code text()}.</li>
 * </ol>
 *
 * <p>Or use {@link #guard} to run all three steps in one call.
 *
 * <h2>Robustness</h2>
 * Network errors, timeouts and non-2xx responses (notably 401) raise a typed
 * {@link PromptSentinelException}. Retries with exponential backoff apply only to
 * transient failures: connection errors, timeouts, HTTP 429, and HTTP 5xx.
 *
 * <p>This client never logs prompt or response bodies.
 */
public final class PromptSentinelClient {

    /** Default base URL of a locally running service. */
    public static final String DEFAULT_BASE_URL = "http://localhost:8000";
    /** Default per-attempt request timeout. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    /** Default number of retries (total attempts = retries + 1). */
    public static final int DEFAULT_RETRIES = 2;
    /** Base backoff used for exponential backoff between retries. */
    private static final Duration BASE_BACKOFF = Duration.ofMillis(200);

    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private final URI baseUri;
    private final Duration timeout;
    private final int retries;
    private final String authToken;

    private PromptSentinelClient(Builder b) {
        this.baseUri = URI.create(stripTrailingSlash(b.baseUrl));
        this.timeout = b.timeout;
        this.retries = b.retries;
        this.authToken = b.token;
        this.mapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.httpClient = (b.httpClient != null)
                ? b.httpClient
                : HttpClient.newBuilder()
                        .connectTimeout(b.timeout)
                        .build();
    }

    /** @return a new builder with default settings. */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Convenience factory using all defaults and the given base URL.
     *
     * @param baseUrl service base URL (e.g. {@code http://localhost:8000})
     * @return a client
     */
    public static PromptSentinelClient create(String baseUrl) {
        return builder().baseUrl(baseUrl).build();
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /**
     * Build-step call: harden a base system prompt and mint a canary.
     *
     * @param basePrompt your raw system prompt (must not be {@code null})
     * @return the hardened prompt and canary; persist the canary
     * @throws PromptSentinelException on any transport, HTTP, or decode failure
     */
    public BuildResult buildSystemPrompt(String basePrompt) {
        Objects.requireNonNull(basePrompt, "basePrompt");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("base_prompt", basePrompt);
        return post("/v1/system-prompt/build", body, BuildResult.class);
    }

    /**
     * Screen a user input before it reaches the model.
     *
     * @param userInput        the end-user input (must not be {@code null})
     * @param untrustedContext optional untrusted context (RAG/tool output), may be {@code null}
     * @return the screening result; if not allowed, return {@code refusal()} and skip the model
     * @throws PromptSentinelException on any transport, HTTP, or decode failure
     */
    public InputResult screenInput(String userInput, String untrustedContext) {
        Objects.requireNonNull(userInput, "userInput");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("user_input", userInput);
        // Always send the key; null serializes to JSON null, matching the optional field.
        body.put("untrusted_context", untrustedContext);
        return post("/v1/screen/input", body, InputResult.class);
    }

    /**
     * Screen a user input with no untrusted context.
     *
     * @param userInput the end-user input (must not be {@code null})
     * @return the screening result
     * @throws PromptSentinelException on any transport, HTTP, or decode failure
     */
    public InputResult screenInput(String userInput) {
        return screenInput(userInput, null);
    }

    /**
     * Screen a model output before returning it to the caller.
     *
     * @param modelOutput  the raw model output (must not be {@code null})
     * @param canary       the canary from {@link #buildSystemPrompt}, or {@code null} to skip leak detection
     * @param systemPrompt the system prompt used, or {@code null} (treated as empty)
     * @return the screening result; always return {@code text()}
     * @throws PromptSentinelException on any transport, HTTP, or decode failure
     */
    public OutputResult screenOutput(String modelOutput, String canary, String systemPrompt) {
        Objects.requireNonNull(modelOutput, "modelOutput");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model_output", modelOutput);
        body.put("canary", canary);
        body.put("system_prompt", systemPrompt == null ? "" : systemPrompt);
        return post("/v1/screen/output", body, OutputResult.class);
    }

    /**
     * Screen a model output with a canary and no system prompt.
     *
     * @param modelOutput the raw model output (must not be {@code null})
     * @param canary      the canary from {@link #buildSystemPrompt}, or {@code null}
     * @return the screening result; always return {@code text()}
     * @throws PromptSentinelException on any transport, HTTP, or decode failure
     */
    public OutputResult screenOutput(String modelOutput, String canary) {
        return screenOutput(modelOutput, canary, "");
    }

    /**
     * High-level helper that runs the full three-step safe flow:
     * <ol>
     *   <li>screen the input; if blocked, return the refusal and do not call the model;</li>
     *   <li>otherwise invoke {@code model} with {@code hardenedSystemPrompt};</li>
     *   <li>screen the model output and return the safe text.</li>
     * </ol>
     *
     * @param userInput            the end-user input (must not be {@code null})
     * @param untrustedContext     optional untrusted context, may be {@code null}
     * @param hardenedSystemPrompt the hardened system prompt (passed to the callback); may be {@code null}
     * @param canary               the canary for output leak detection; may be {@code null}
     * @param model                callback that invokes your LLM and returns its raw output
     * @return a {@link GuardResult}; {@code text()} is always safe to return to the caller
     * @throws PromptSentinelException if a screening request fails, or wrapping a model-callback failure
     */
    public GuardResult guard(String userInput,
                             String untrustedContext,
                             String hardenedSystemPrompt,
                             String canary,
                             ModelInvocation model) {
        Objects.requireNonNull(userInput, "userInput");
        Objects.requireNonNull(model, "model");

        InputResult input = screenInput(userInput, untrustedContext);
        if (!input.allowed()) {
            // Return the refusal verbatim; the model is never called.
            return new GuardResult(input.refusal(), true, input, null);
        }

        // When the caller does not supply a hardened system prompt, fall back to the
        // sanitized input from screening (aligns with the Python/Go SDKs). Passing the
        // raw/null value would forward unsanitized text to the model.
        String promptForModel = (hardenedSystemPrompt == null || hardenedSystemPrompt.isEmpty())
                ? input.sanitized()
                : hardenedSystemPrompt;

        final String rawOutput;
        try {
            rawOutput = model.invoke(promptForModel);
        } catch (PromptSentinelException e) {
            throw e;
        } catch (Exception e) {
            // Do not embed model output in the message (leak-safe).
            throw new PromptSentinelException(
                    PromptSentinelException.Kind.CONNECTION, -1,
                    "model invocation callback failed", e);
        }
        Objects.requireNonNull(rawOutput, "model callback returned null output");

        OutputResult output = screenOutput(rawOutput, canary, promptForModel);
        return new GuardResult(output.text(), false, input, output);
    }

    /**
     * Liveness/health probe.
     *
     * @return parsed {@code /health} payload
     * @throws PromptSentinelException on any transport, HTTP, or decode failure
     */
    public HealthResult health() {
        return get("/health", HealthResult.class);
    }

    /**
     * Service version and scanner availability.
     *
     * @return parsed {@code /version} payload
     * @throws PromptSentinelException on any transport, HTTP, or decode failure
     */
    public VersionResult version() {
        return get("/version", VersionResult.class);
    }

    // ------------------------------------------------------------------
    // HTTP plumbing
    // ------------------------------------------------------------------

    private <T> T get(String path, Class<T> type) {
        HttpRequest.Builder rb = baseRequest(path).GET();
        return send(rb, type);
    }

    private <T> T post(String path, Object body, Class<T> type) {
        String json;
        try {
            json = mapper.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            throw new PromptSentinelException(
                    PromptSentinelException.Kind.INVALID_ARGUMENT, -1,
                    "failed to serialize request body", e);
        }
        HttpRequest.Builder rb = baseRequest(path)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8));
        return send(rb, type);
    }

    private HttpRequest.Builder baseRequest(String path) {
        HttpRequest.Builder rb = HttpRequest.newBuilder()
                .uri(baseUri.resolve(path))
                .timeout(timeout)
                .header("Accept", "application/json")
                .header("User-Agent", "promptsentinel-java/1.0.0");
        if (authToken != null && !authToken.isEmpty()) {
            rb.header("Authorization", "Bearer " + authToken);
        }
        return rb;
    }

    private <T> T send(HttpRequest.Builder rb, Class<T> type) {
        int attempts = retries + 1;
        PromptSentinelException last = null;

        for (int attempt = 0; attempt < attempts; attempt++) {
            if (attempt > 0) {
                sleepBackoff(attempt);
            }
            // A fresh request object per attempt (HttpRequest is single-use-safe but build anew to be explicit).
            HttpRequest request = rb.copy().build();
            HttpResponse<String> response;
            try {
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            } catch (HttpTimeoutException e) {
                // HttpConnectTimeoutException is a subtype of HttpTimeoutException
                // and is therefore covered here as well.
                last = new PromptSentinelException(
                        PromptSentinelException.Kind.TIMEOUT, -1, "request timed out", e);
                continue; // retryable
            } catch (ConnectException e) {
                last = new PromptSentinelException(
                        PromptSentinelException.Kind.CONNECTION, -1, "connection failed", e);
                continue; // retryable
            } catch (IOException e) {
                last = new PromptSentinelException(
                        PromptSentinelException.Kind.CONNECTION, -1, "I/O error during request", e);
                continue; // retryable
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new PromptSentinelException(
                        PromptSentinelException.Kind.CONNECTION, -1, "request interrupted", e);
            }

            int status = response.statusCode();
            if (status >= 200 && status < 300) {
                return decode(response.body(), type);
            }

            if (status == 401) {
                // Auth failures are not retryable and must be clearly typed.
                throw new PromptSentinelException(
                        PromptSentinelException.Kind.UNAUTHORIZED, 401,
                        "unauthorized: missing or invalid bearer token");
            }

            if (status == 429 || (status >= 500 && status <= 599)) {
                last = new PromptSentinelException(
                        PromptSentinelException.Kind.HTTP_STATUS, status,
                        "retryable server status " + status);
                continue; // retryable
            }

            // Other 4xx: not retryable.
            throw new PromptSentinelException(
                    PromptSentinelException.Kind.HTTP_STATUS, status,
                    "unexpected HTTP status " + status);
        }

        // Exhausted retries.
        if (last != null) {
            throw last;
        }
        throw new PromptSentinelException(
                PromptSentinelException.Kind.CONNECTION, -1, "request failed with no response");
    }

    private <T> T decode(String body, Class<T> type) {
        try {
            return mapper.readValue(body, type);
        } catch (JsonProcessingException e) {
            throw new PromptSentinelException(
                    PromptSentinelException.Kind.DECODE, -1,
                    "failed to decode response as " + type.getSimpleName(), e);
        }
    }

    private void sleepBackoff(int attempt) {
        // Exponential backoff: base * 2^(attempt-1). attempt is 1-based for sleeps.
        long millis = BASE_BACKOFF.toMillis() * (1L << (attempt - 1));
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PromptSentinelException(
                    PromptSentinelException.Kind.CONNECTION, -1, "interrupted during backoff", e);
        }
    }

    private static String stripTrailingSlash(String url) {
        if (url == null || url.isEmpty()) {
            return DEFAULT_BASE_URL;
        }
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    // ------------------------------------------------------------------
    // Builder
    // ------------------------------------------------------------------

    /** Fluent builder for {@link PromptSentinelClient}. */
    public static final class Builder {
        private String baseUrl = DEFAULT_BASE_URL;
        private Duration timeout = DEFAULT_TIMEOUT;
        private int retries = DEFAULT_RETRIES;
        private String token = null;
        private HttpClient httpClient = null;

        private Builder() {
        }

        /**
         * @param baseUrl service base URL; default {@value PromptSentinelClient#DEFAULT_BASE_URL}
         * @return this
         */
        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        /**
         * @param timeout per-attempt request timeout; default 30s
         * @return this
         */
        public Builder timeout(Duration timeout) {
            this.timeout = Objects.requireNonNull(timeout, "timeout");
            return this;
        }

        /**
         * @param retries number of retries on transient failures; default 2 (must be {@code >= 0})
         * @return this
         */
        public Builder retries(int retries) {
            if (retries < 0) {
                throw new IllegalArgumentException("retries must be >= 0");
            }
            this.retries = retries;
            return this;
        }

        /**
         * @param token optional bearer token; sent as {@code Authorization: Bearer <token>}
         * @return this
         */
        public Builder token(String token) {
            this.token = token;
            return this;
        }

        /**
         * Inject a custom {@link HttpClient} (primarily for testing / custom TLS / proxy).
         *
         * @param httpClient the client to use; if {@code null}, one is created from the timeout
         * @return this
         */
        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        /** @return the built, immutable client. */
        public PromptSentinelClient build() {
            return new PromptSentinelClient(this);
        }
    }
}
