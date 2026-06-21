# -*- coding: utf-8 -*-
"""Anthropic Messages 兼容的极简大模型客户端。

针对 `.llmenv` 中的 base_url(本仓库默认 MiniMax 的 /anthropic 端点)发起
`POST {base_url}/v1/messages` 请求,使用 `x-api-key` + `anthropic-version` 头。
响应 content 是块列表,可能包含 thinking 块;本客户端只提取 type=="text" 的块文本。

实现说明:
  * 这是**第三方**(MiniMax)经由 Anthropic 线缆格式的端点,模型名取自 .llmenv
    (如 MiniMax-M2.7-highspeed),而非真正的 Anthropic 模型 ID。
  * 优先用 httpx;缺失时回退到标准库 urllib,保证工具在最小依赖下也能跑。
  * 仅用于开发/测试工具与可选的 LLM-judge;不进入默认运行时检测路径。
"""
from __future__ import annotations

import json
from typing import List, Optional

from .env import LLMConfig, load_llm_config


class LLMError(RuntimeError):
    """LLM 调用失败(网络、鉴权、格式等)。"""


class LLMClient:
    def __init__(self, config: Optional[LLMConfig] = None, timeout: float = 60.0):
        self.config = config or load_llm_config()
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return self.config.configured

    def _endpoint(self) -> str:
        return self.config.base_url.rstrip("/") + "/v1/messages"

    def _headers(self) -> dict:
        return {
            "content-type": "application/json",
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
        }

    def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 2048,
    ) -> str:
        """单轮补全:发送一个 user 消息,返回拼接后的文本(跳过 thinking 块)。

        注意:目标模型可能是 thinking 模型——max_tokens 需留足空间给 thinking + text,
        否则可能全部消耗在 thinking 上、返回空文本(stop_reason=max_tokens)。
        """
        if not self.available:
            raise LLMError("未配置大模型(.llmenv 缺失或不完整)")
        payload = self._post(self._body(prompt, system, max_tokens))
        return self._extract_text(payload)

    def _body(self, prompt: str, system: Optional[str], max_tokens: int) -> dict:
        body = {
            "model": self.config.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            body["system"] = system
        return body

    def probe(self, max_tokens: int = 512) -> dict:
        """连通性探测:返回 {ok, text, stop_reason, usage}。
        ok=True 表示端点返回了结构良好的 Messages 响应(即便 text 因 thinking 截断为空)。
        """
        payload = self._post(self._body("Reply with the single word: pong", None, max_tokens))
        return {
            "ok": "content" in payload and isinstance(payload.get("content"), list),
            "text": self._extract_text(payload),
            "stop_reason": payload.get("stop_reason"),
            "usage": payload.get("usage", {}),
        }

    # ------------------------------------------------------------------
    def _post(self, body: dict) -> dict:
        data = json.dumps(body).encode("utf-8")
        try:
            import httpx  # noqa: WPS433

            resp = httpx.post(
                self._endpoint(), headers=self._headers(), content=data, timeout=self.timeout
            )
            if resp.status_code != 200:
                raise LLMError("HTTP {0}: {1}".format(resp.status_code, resp.text[:300]))
            return resp.json()
        except ImportError:
            return self._post_urllib(data)

    def _post_urllib(self, data: bytes) -> dict:
        import urllib.error
        import urllib.request

        req = urllib.request.Request(
            self._endpoint(), data=data, headers=self._headers(), method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:  # pragma: no cover - 网络路径
            detail = exc.read().decode("utf-8", "ignore")[:300]
            raise LLMError("HTTP {0}: {1}".format(exc.code, detail)) from exc
        except Exception as exc:  # pragma: no cover - 网络路径
            raise LLMError(str(exc)) from exc

    @staticmethod
    def _extract_text(payload: dict) -> str:
        blocks = payload.get("content", []) or []
        parts: List[str] = []
        for block in blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
        return "".join(parts).strip()


def ping() -> int:
    """连通性自检:端点返回结构良好的 Messages 响应即 0,否则 1。

    供 `python -m app.llm.client --ping` 用。注意:目标可能是 thinking 模型,
    text 可能因 thinking 截断为空——这不影响连通性判定(ok 看响应结构)。
    """
    client = LLMClient()
    if not client.available:
        print("[ping] .llmenv 未配置,跳过实时调用")
        return 1
    try:
        info = client.probe()
        print("[ping] model={0} ok={1} stop={2} reply={3!r}".format(
            client.config.model, info["ok"], info.get("stop_reason"), info["text"][:80]))
        return 0 if info["ok"] else 1
    except LLMError as exc:
        print("[ping] 失败: {0}".format(exc))
        return 1


if __name__ == "__main__":  # pragma: no cover
    import sys

    if "--ping" in sys.argv:
        sys.exit(ping())
    print("用法: python -m app.llm.client --ping")
