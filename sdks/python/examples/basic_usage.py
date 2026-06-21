# -*- coding: utf-8 -*-
"""End-to-end usage demo against a *real* PromptSentinel service.

This connects to a running service (default http://localhost:8000). It is not
run by the test suite; it documents the canonical three-step integration.

Run:
    python examples/basic_usage.py

If your service is configured with `server.auth_token`, pass it:
    PROMPTSENTINEL_TOKEN=... python examples/basic_usage.py
"""
from __future__ import annotations

import os

from promptsentinel import Client, GuardError


def my_llm(hardened_system_prompt: str, user_input: str) -> str:
    """Stand-in for your real model call.

    In production this is where you'd call OpenAI / Anthropic / a local model,
    passing the hardened system prompt and the user input. Here we just echo.
    """
    return "The weather looks sunny today."


def main() -> None:
    token = os.environ.get("PROMPTSENTINEL_TOKEN") or None
    base_url = os.environ.get("PROMPTSENTINEL_URL", "http://localhost:8000")

    # The Client owns an HTTP connection pool; close it when done.
    with Client(base_url=base_url, token=token, timeout=10.0, retries=2) as client:
        # --- Step 1: build-time (run once at deploy) ---------------------
        # Build a hardened system prompt and a canary. Persist the canary
        # (e.g. in config/secrets) so you can detect leakage on output.
        built = client.build_system_prompt("You are a helpful weather assistant.")
        hardened = built.hardened_system_prompt
        canary = built.canary
        print("[build] canary stored, hardened prompt length =", len(hardened))

        user_input = "What is the weather like today?"
        # `untrusted_context` is optional: pass retrieved docs / tool output /
        # any third-party text you don't fully trust so it gets screened too.
        untrusted_context = None

        # --- Option A: do the three steps manually -----------------------
        screened = client.screen_input(user_input, untrusted_context)
        if not screened.allowed:
            # Blocked: return the refusal, never call the model.
            print("[input] blocked:", screened.refusal)
            return

        model_output = my_llm(hardened, user_input)

        out = client.screen_output(model_output, canary=canary, system_prompt=hardened)
        # `out.text` is always safe to return directly to the end user.
        print("[output] allowed =", out.allowed, "| text =", out.text)

        # --- Option B: same flow via the guard() helper ------------------
        # The callback receives the hardened system prompt (since we pass it),
        # and must return the model output string. guard() handles input
        # screening, the skip-on-block, and output screening for you.
        try:
            result = client.guard(
                user_input=user_input,
                untrusted_context=untrusted_context,
                canary=canary,
                hardened_system_prompt=hardened,
                call_model=lambda hp: my_llm(hp, user_input),
            )
        except GuardError as exc:
            # The model callback raised; the screening pipeline did not.
            print("[guard] model call failed:", exc)
            return

        print("[guard] allowed =", result.allowed, "| text =", result.text)


if __name__ == "__main__":
    main()
