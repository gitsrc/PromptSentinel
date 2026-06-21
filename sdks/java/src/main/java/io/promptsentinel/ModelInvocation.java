package io.promptsentinel;

/**
 * Functional callback that invokes your business LLM.
 *
 * <p>Used by {@link PromptSentinelClient#guard}. The single argument is the
 * <em>hardened system prompt</em> you passed into the guard call (so you have it
 * at the point of model invocation); the return value is the raw model output
 * string, which the guard will then screen before returning to the caller.
 *
 * <p>Implementations may throw a checked {@link Exception}; the guard wraps any
 * such failure so callers can handle model and screening errors uniformly.
 */
@FunctionalInterface
public interface ModelInvocation {

    /**
     * @param hardenedSystemPrompt the hardened system prompt to drive the model with
     * @return the raw model output to be screened
     * @throws Exception if the model call fails
     */
    String invoke(String hardenedSystemPrompt) throws Exception;
}
