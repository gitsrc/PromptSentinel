# -*- coding: utf-8 -*-
"""Typed result objects returned by the PromptSentinel client.

These mirror the HTTP contract one-to-one. They are plain ``@dataclass``
instances (not raw dicts) so callers get attribute access, type hints and
``repr`` for free.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class BuildResult:
    """Result of ``POST /v1/system-prompt/build``.

    Attributes:
        hardened_system_prompt: The hardened system prompt to feed your LLM.
        canary: A secret marker embedded in the prompt. Persist it so you can
            pass it to :meth:`Client.screen_output` and detect leakage.
    """

    hardened_system_prompt: str
    canary: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BuildResult":
        return cls(
            hardened_system_prompt=str(data.get("hardened_system_prompt", "")),
            canary=str(data.get("canary", "")),
        )


@dataclass(frozen=True)
class InputResult:
    """Result of ``POST /v1/screen/input``.

    Attributes:
        allowed: ``False`` means you should return ``refusal`` and NOT call
            your model.
        risk: Probabilistic risk score in ``[0.0, 1.0]``.
        reasons: Human-readable detector reasons (may be empty).
        sanitized: A cleaned version of the input (safe to forward).
        refusal: Refusal text to return when ``allowed`` is ``False``;
            ``None`` when allowed.
        would_block: Whether the service *would* block this input under an
            enforcing policy. In shadow/monitor mode ``allowed`` may be
            ``True`` while ``would_block`` is ``True``. Defaults to ``False``
            (safe) when the server omits it.
        mode: The screening policy mode in effect (e.g. ``"enforce"`` or
            ``"shadow"``). Defaults to ``"enforce"`` when the server omits it.
    """

    allowed: bool
    risk: float
    reasons: List[str] = field(default_factory=list)
    sanitized: str = ""
    refusal: Optional[str] = None
    would_block: bool = False
    mode: str = "enforce"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InputResult":
        reasons = data.get("reasons") or []
        mode = data.get("mode")
        return cls(
            allowed=bool(data.get("allowed", False)),
            risk=float(data.get("risk", 0.0)),
            reasons=[str(r) for r in reasons],
            sanitized=str(data.get("sanitized", "")),
            refusal=(None if data.get("refusal") is None else str(data.get("refusal"))),
            would_block=bool(data.get("would_block", False)),
            mode=("enforce" if mode is None else str(mode)),
        )


@dataclass(frozen=True)
class OutputResult:
    """Result of ``POST /v1/screen/output``.

    Attributes:
        allowed: Whether the model output passed screening.
        risk: Probabilistic risk score in ``[0.0, 1.0]``.
        reasons: Human-readable detector reasons (may be empty).
        text: The text to return to the end user. Already either the
            passed-through original or a refusal message, so you can return it
            directly regardless of ``allowed``.
        would_block: Whether the service *would* block this output under an
            enforcing policy. In shadow/monitor mode ``allowed`` may be
            ``True`` while ``would_block`` is ``True``. Defaults to ``False``
            (safe) when the server omits it.
        mode: The screening policy mode in effect (e.g. ``"enforce"`` or
            ``"shadow"``). Defaults to ``"enforce"`` when the server omits it.
    """

    allowed: bool
    risk: float
    reasons: List[str] = field(default_factory=list)
    text: str = ""
    would_block: bool = False
    mode: str = "enforce"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OutputResult":
        reasons = data.get("reasons") or []
        mode = data.get("mode")
        return cls(
            allowed=bool(data.get("allowed", False)),
            risk=float(data.get("risk", 0.0)),
            reasons=[str(r) for r in reasons],
            text=str(data.get("text", "")),
            would_block=bool(data.get("would_block", False)),
            mode=("enforce" if mode is None else str(mode)),
        )


@dataclass(frozen=True)
class HealthResult:
    """Result of ``GET /health``.

    Attributes:
        status: The service health status (e.g. ``"ok"``). Defaults to ``""``
            when the server omits it.
        mode: The screening policy mode in effect (e.g. ``"enforce"`` or
            ``"shadow"``). Defaults to ``"enforce"`` when the server omits it.
        ml_classifier: Whether the ML classifier backend is loaded and
            available. Defaults to ``False`` (safe) when the server omits it.
    """

    status: str = ""
    mode: str = "enforce"
    ml_classifier: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HealthResult":
        mode = data.get("mode")
        return cls(
            status=str(data.get("status", "")),
            mode=("enforce" if mode is None else str(mode)),
            ml_classifier=bool(data.get("ml_classifier", False)),
        )
