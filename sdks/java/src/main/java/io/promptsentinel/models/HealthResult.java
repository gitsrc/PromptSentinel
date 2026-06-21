package io.promptsentinel.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Result of {@code GET /health}.
 *
 * @param status         service status (e.g. {@code "ok"})
 * @param team           configured team name
 * @param agent          configured agent name
 * @param llmGuard       whether the optional LLM-guard scanner is available
 * @param llmJudge       whether the optional LLM-judge scanner is available
 * @param protectedTerms number of configured protected terms
 * @param mode           the screening mode in effect (e.g. {@code "enforce"}, {@code "shadow"})
 * @param mlClassifier   whether the optional ML injection classifier is available
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record HealthResult(
        @JsonProperty("status") String status,
        @JsonProperty("team") String team,
        @JsonProperty("agent") String agent,
        @JsonProperty("llm_guard") boolean llmGuard,
        @JsonProperty("llm_judge") boolean llmJudge,
        @JsonProperty("protected_terms") int protectedTerms,
        @JsonProperty("mode") String mode,
        @JsonProperty("ml_classifier") boolean mlClassifier) {
}
