package io.promptsentinel.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;

/**
 * Result of {@code POST /v1/screen/input}.
 *
 * <p>When {@link #allowed()} is {@code false}, the business layer must return
 * {@link #refusal()} directly and <strong>must not</strong> call the model.
 * When allowed, drive the model with the hardened system prompt and the
 * (possibly sanitized) input.
 *
 * @param allowed    whether the input passed screening
 * @param risk       risk score in {@code [0.0, 1.0]}
 * @param reasons    machine-readable reason codes (never {@code null})
 * @param sanitized  the input after sanitization (safe to forward when allowed)
 * @param refusal    the refusal text to return when blocked; {@code null} when allowed
 * @param wouldBlock whether this input would be blocked under enforce mode (informational
 *                   in shadow/monitor mode); defaults to {@code false}
 * @param mode       the screening mode in effect (e.g. {@code "enforce"}, {@code "shadow"});
 *                   defaults to {@code "enforce"}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record InputResult(
        @JsonProperty("allowed") boolean allowed,
        @JsonProperty("risk") double risk,
        @JsonProperty("reasons") List<String> reasons,
        @JsonProperty("sanitized") String sanitized,
        @JsonProperty("refusal") String refusal,
        @JsonProperty("would_block") boolean wouldBlock,
        @JsonProperty("mode") String mode) {

    @JsonCreator
    public InputResult {
        // Defensive copy + null-safety: reasons is always a non-null immutable list.
        reasons = (reasons == null)
                ? Collections.emptyList()
                : Collections.unmodifiableList(List.copyOf(reasons));
        // Safe default when the server omits mode (older deployments).
        mode = (mode == null) ? "enforce" : mode;
    }
}
