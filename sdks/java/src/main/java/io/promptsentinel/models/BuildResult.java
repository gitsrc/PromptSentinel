package io.promptsentinel.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Result of {@code POST /v1/system-prompt/build}.
 *
 * <p>This is the build-step (deploy-time) output: a hardened system prompt to
 * drive your model with, plus a unique {@code canary} sentinel. <strong>Store
 * the canary</strong> and pass it to {@code screenOutput} on every request so
 * verbatim system-prompt leaks can be detected.
 *
 * @param hardenedSystemPrompt the hardened system prompt to send to your LLM
 * @param canary               the unique sentinel embedded in the prompt; keep it
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BuildResult(
        @JsonProperty("hardened_system_prompt") String hardenedSystemPrompt,
        @JsonProperty("canary") String canary) {
}
