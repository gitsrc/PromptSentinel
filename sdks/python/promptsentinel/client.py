# -*- coding: utf-8 -*-
"""Synchronous PromptSentinel client.

Wraps the PromptSentinel HTTP contract with typed results, an optional bearer
token, timeouts, and bounded exponential-backoff retries for transient
failures (network errors, 5xx, 429). Authentication failures (401) and other
4xx are raised immediately as typed errors.

Privacy: this module never logs prompt or response bodies, nor the bearer
token.
"""
from __future__ import annotations

import time
from typing import Callable, Optional

import httpx

from .models import BuildResult, HealthResult, InputResult, OutputResult

__all__ = [
    "Client",
    "PromptSentinelError",
    "TransportError",
    "APIError",
    "AuthError",
    "GuardError",
]

_DEFAULT_BASE_URL = "http://localhost:8000"
_DEFAULT_TIMEOUT = 10.0
_DEFAULT_RETRIES = 2
_BACKOFF_BASE = 0.2  # seconds; doubled each attempt
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


class PromptSentinelError(Exception):
    """Base class for all errors raised by this SDK."""


class TransportError(PromptSentinelError):
    """A network-level failure: timeout, connection refused, DNS, etc.

    Raised after retries are exhausted.
    """


class APIError(PromptSentinelError):
    """The service returned a non-2xx HTTP status.

    Attributes:
        status_code: The HTTP status code.
        detail: A short, body-derived detail string (never the full prompt).
    """

    def __init__(self, status_code: int, detail: str = "") -> None:
        self.status_code = status_code
        self.detail = detail
        msg = "PromptSentinel API error: HTTP {0}".format(status_code)
        if detail:
            msg = "{0} ({1})".format(msg, detail)
        super().__init__(msg)


class AuthError(APIError):
    """HTTP 401: missing or invalid bearer token."""

    def __init__(self, detail: str = "unauthorized") -> None:
        super().__init__(401, detail)


class GuardError(PromptSentinelError):
    """The business model callback inside :meth:`Client.guard` failed.

    Wraps the original exception in ``__cause__`` so the screening pipeline
    surfaces a single, distinguishable failure type.
    """


def _detail_from_response(resp: "httpx.Response") -> str:
    """Extract a short detail string without leaking large bodies."""
    try:
        data = resp.json()
        if isinstance(data, dict) and "detail" in data:
            return str(data["detail"])[:200]
    except Exception:  # noqa: BLE001 - body may be non-JSON
        pass
    return resp.text[:200] if resp.text else ""


class Client:
    """Synchronous PromptSentinel client.

    Args:
        base_url: Service base URL. Defaults to ``http://localhost:8000``.
        token: Optional bearer token. Sent as ``Authorization: Bearer
            <token>`` on every ``/v1`` request when set.
        timeout: Per-request timeout in seconds.
        retries: Number of *additional* attempts for transient failures
            (network errors, 5xx, 429). ``retries=2`` means up to 3 attempts.
        transport: Optional ``httpx`` transport (handy for tests/mocking).
    """

    def __init__(
        self,
        base_url: str = _DEFAULT_BASE_URL,
        token: Optional[str] = None,
        timeout: float = _DEFAULT_TIMEOUT,
        retries: int = _DEFAULT_RETRIES,
        transport: Optional["httpx.BaseTransport"] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout = timeout
        self.retries = max(0, int(retries))
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer {0}".format(token)
        self._http = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            headers=headers,
            transport=transport,
        )

    # -- context manager support ------------------------------------------
    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._http.close()

    # -- low-level request with retries -----------------------------------
    def _request(self, method: str, path: str, json_body: Optional[dict] = None) -> dict:
        attempts = self.retries + 1
        last_exc: Optional[Exception] = None
        for attempt in range(attempts):
            try:
                resp = self._http.request(method, path, json=json_body)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt < attempts - 1:
                    self._sleep_backoff(attempt)
                    continue
                raise TransportError(
                    "request to {0} failed after {1} attempt(s)".format(path, attempts)
                ) from exc

            if resp.status_code in _RETRY_STATUS and attempt < attempts - 1:
                self._sleep_backoff(attempt)
                continue

            if resp.status_code == 401:
                raise AuthError(_detail_from_response(resp) or "unauthorized")
            if resp.status_code >= 400:
                raise APIError(resp.status_code, _detail_from_response(resp))

            try:
                data = resp.json()
            except Exception as exc:  # noqa: BLE001
                raise APIError(resp.status_code, "invalid JSON response") from exc
            if not isinstance(data, dict):
                raise APIError(resp.status_code, "unexpected response shape")
            return data

        # Unreachable in practice; defensive for static analysis.
        raise TransportError("request to {0} failed".format(path)) from last_exc

    @staticmethod
    def _sleep_backoff(attempt: int) -> None:
        time.sleep(_BACKOFF_BASE * (2 ** attempt))

    # -- typed endpoints ---------------------------------------------------
    def health(self) -> HealthResult:
        """Fetch service health, including screening ``mode`` and whether the
        ML classifier backend is loaded (``ml_classifier``).

        This hits the unauthenticated ``GET /health`` endpoint.
        """
        data = self._request("GET", "/health")
        return HealthResult.from_dict(data)

    def build_system_prompt(self, base_prompt: str) -> BuildResult:
        """Build a hardened system prompt and a canary (deploy-time, once).

        Persist the returned ``canary`` so you can pass it to
        :meth:`screen_output` to detect leakage.
        """
        data = self._request(
            "POST", "/v1/system-prompt/build", {"base_prompt": base_prompt}
        )
        return BuildResult.from_dict(data)

    def screen_input(
        self, user_input: str, untrusted_context: Optional[str] = None
    ) -> InputResult:
        """Screen user input before calling your model.

        If ``result.allowed`` is ``False``, return ``result.refusal`` and do
        NOT call your model.
        """
        body = {"user_input": user_input}
        if untrusted_context is not None:
            body["untrusted_context"] = untrusted_context
        data = self._request("POST", "/v1/screen/input", body)
        return InputResult.from_dict(data)

    def screen_output(
        self,
        model_output: str,
        canary: Optional[str] = None,
        system_prompt: Optional[str] = None,
    ) -> OutputResult:
        """Screen model output before returning it to the user.

        ``result.text`` is always safe to return directly (either the
        passed-through original or a refusal message).
        """
        body = {"model_output": model_output}
        if canary is not None:
            body["canary"] = canary
        if system_prompt is not None:
            body["system_prompt"] = system_prompt
        data = self._request("POST", "/v1/screen/output", body)
        return OutputResult.from_dict(data)

    # -- high-level orchestration -----------------------------------------
    def guard(
        self,
        user_input: str,
        call_model: Callable[[str], str],
        untrusted_context: Optional[str] = None,
        canary: Optional[str] = None,
        hardened_system_prompt: Optional[str] = None,
    ) -> OutputResult:
        """Run the full three-step protection flow.

        1. Screen ``user_input``. If blocked, return an :class:`OutputResult`
           carrying the refusal text (the model is never called).
        2. Otherwise invoke ``call_model``. The callback receives the
           ``hardened_system_prompt`` if provided, else the (sanitized) input,
           and must return the model output as a string.
        3. Screen the model output and return the resulting
           :class:`OutputResult`; ``result.text`` is safe to return directly.

        Args:
            user_input: The raw end-user input.
            call_model: ``(hardened_or_context: str) -> str``. Your model call.
            untrusted_context: Optional retrieved/3rd-party context to screen.
            canary: The canary from :meth:`build_system_prompt`, for leak
                detection on the output.
            hardened_system_prompt: Optional hardened prompt; passed to
                ``call_model`` when set, otherwise the sanitized input is.

        Raises:
            GuardError: if ``call_model`` raises.
        """
        screened = self.screen_input(user_input, untrusted_context)
        if not screened.allowed:
            refusal = screened.refusal or ""
            return OutputResult(
                allowed=False,
                risk=screened.risk,
                reasons=list(screened.reasons),
                text=refusal,
            )

        # When no hardened system prompt is supplied, fall back to the
        # sanitized input from screen_input (never the raw input) so the
        # model only ever sees cleaned text. This matches the Go SDK.
        callback_arg = (
            hardened_system_prompt
            if hardened_system_prompt is not None
            else screened.sanitized
        )
        try:
            model_output = call_model(callback_arg)
        except Exception as exc:  # noqa: BLE001 - wrap any callback failure
            raise GuardError("business model callback failed") from exc

        return self.screen_output(
            model_output, canary=canary, system_prompt=hardened_system_prompt
        )
