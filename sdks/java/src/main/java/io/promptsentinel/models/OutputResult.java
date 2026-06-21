package io.promptsentinel.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;

/**
 * Result of {@code POST /v1/screen/output}.
 *
 * <p>{@link #text()} is always the value the business layer should return to the
 * end user: either the released model output (when {@link #allowed()} is
 * {@code true}) or the refusal text (when blocked, e.g. a canary leak was
 * detected). Just return {@code text()}.
 *
 * @param allowed    whether the output passed screening
 * @param risk       risk score in {@code [0.0, 1.0]}
 * @param reasons    machine-readable reason codes (never {@code null})
 * @param text       the safe text to return to the caller
 * @param wouldBlock whether this output would be blocked under enforce mode (informational
 *                   in shadow/monitor mode); defaults to {@code false}
 * @param mode       the screening mode in effect (e.g. {@code "enforce"}, {@code "shadow"});
 *                   defaults to {@code "enforce"}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OutputResult(
        @JsonProperty("allowed") boolean allowed,
        @JsonProperty("risk") double risk,
        @JsonProperty("reasons") List<String> reasons,
        @JsonProperty("text") String text,
        @JsonProperty("would_block") boolean wouldBlock,
        @JsonProperty("mode") String mode) {

    @JsonCreator
    public OutputResult {
        reasons = (reasons == null)
                ? Collections.emptyList()
                : Collections.unmodifiableList(List.copyOf(reasons));
        // Safe default when the server omits mode (older deployments).
        mode = (mode == null) ? "enforce" : mode;
    }
}
