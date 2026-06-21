# -*- coding: utf-8 -*-
"""PromptSentinel Python SDK.

A typed, production-ready client for the PromptSentinel self-hosted LLM
prompt-security service.

Quick start::

    from promptsentinel import Client

    client = Client(base_url="http://localhost:8000")
    built = client.build_system_prompt("You are a helpful assistant.")

    result = client.guard(
        user_input="What is the weather?",
        call_model=lambda hardened: my_llm(hardened, "What is the weather?"),
        canary=built.canary,
        hardened_system_prompt=built.hardened_system_prompt,
    )
    print(result.text)
"""
from __future__ import annotations

from .client import (
    APIError,
    AuthError,
    Client,
    GuardError,
    PromptSentinelError,
    TransportError,
)
from .models import BuildResult, HealthResult, InputResult, OutputResult

__version__ = "1.0.0"

__all__ = [
    "Client",
    "BuildResult",
    "HealthResult",
    "InputResult",
    "OutputResult",
    "PromptSentinelError",
    "TransportError",
    "APIError",
    "AuthError",
    "GuardError",
    "__version__",
]
