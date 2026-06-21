package io.promptsentinel.models;

/**
 * Outcome of the high-level {@code guard(...)} three-step flow.
 *
 * <p>Exactly one logical path is taken:
 * <ul>
 *   <li>If input screening blocked the request, {@link #blockedAtInput()} is
 *       {@code true}, {@link #text()} holds the input refusal, the model was
 *       <strong>not</strong> called, and {@link #outputResult()} is {@code null}.</li>
 *   <li>Otherwise the model was called and the output screened; {@link #text()}
 *       holds the safe output (released text or output refusal).</li>
 * </ul>
 *
 * <p>In all cases, {@link #text()} is the value to return to the end user.
 *
 * @param text           the safe text to return to the caller
 * @param blockedAtInput {@code true} if the flow stopped at input screening
 * @param inputResult    the input screening result (never {@code null})
 * @param outputResult   the output screening result, or {@code null} if blocked at input
 */
public record GuardResult(
        String text,
        boolean blockedAtInput,
        InputResult inputResult,
        OutputResult outputResult) {

    /** @return {@code true} if the model was invoked (i.e. input screening passed). */
    public boolean modelInvoked() {
        return !blockedAtInput;
    }
}
