package io.promptsentinel;

/**
 * Typed error raised by {@link PromptSentinelClient} for every failure mode:
 * timeouts, connection errors, and non-2xx HTTP responses (notably 401).
 *
 * <p>The exception deliberately carries the {@link Kind} and (when applicable)
 * the HTTP {@code statusCode}, so callers can branch without string matching.
 * Request/response bodies are <strong>never</strong> embedded in the message to
 * avoid leaking prompts or credentials into logs.
 */
public class PromptSentinelException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Coarse classification of the failure, suitable for {@code switch}/branching. */
    public enum Kind {
        /** Connection refused, DNS failure, TLS error, or other transport-level failure. */
        CONNECTION,
        /** Request exceeded the configured per-attempt timeout. */
        TIMEOUT,
        /** Missing or invalid bearer token (HTTP 401). */
        UNAUTHORIZED,
        /** Server returned 4xx (other than 401) or 5xx. */
        HTTP_STATUS,
        /** Response body could not be decoded as the expected JSON shape. */
        DECODE,
        /** Caller supplied invalid arguments before any request was made. */
        INVALID_ARGUMENT
    }

    private final Kind kind;
    private final int statusCode;

    public PromptSentinelException(Kind kind, int statusCode, String message) {
        super(message);
        this.kind = kind;
        this.statusCode = statusCode;
    }

    public PromptSentinelException(Kind kind, int statusCode, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
        this.statusCode = statusCode;
    }

    /** @return the failure classification. */
    public Kind kind() {
        return kind;
    }

    /**
     * @return the HTTP status code for {@link Kind#HTTP_STATUS} and
     *         {@link Kind#UNAUTHORIZED} failures, or {@code -1} when no HTTP
     *         response was received (connection/timeout/decode/argument errors).
     */
    public int statusCode() {
        return statusCode;
    }

    /** @return {@code true} when the failure was an HTTP 401 Unauthorized. */
    public boolean isUnauthorized() {
        return kind == Kind.UNAUTHORIZED;
    }
}
