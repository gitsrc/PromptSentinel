# -*- coding: utf-8 -*-
"""`.llmenv` 加载器。

从当前工作目录向上逐级查找 `.llmenv`(KEY=VALUE 文本),解析为 LLMConfig。
也支持显式路径或同名环境变量覆盖。仅用于开发/测试工具,不写入日志。
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class LLMConfig:
    provider: str = ""
    api_key: str = ""
    base_url: str = ""
    model: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.api_key and self.base_url and self.model)


def _find_llmenv(start: Optional[str] = None, max_levels: int = 8) -> Optional[str]:
    """从 start(默认 cwd)向上查找 .llmenv 文件路径。"""
    cur = os.path.abspath(start or os.getcwd())
    for _ in range(max_levels):
        candidate = os.path.join(cur, ".llmenv")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return None


def _parse(path: str) -> dict:
    data = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()
    return data


def load_llm_config(path: Optional[str] = None) -> LLMConfig:
    """加载 .llmenv → LLMConfig。环境变量 LLM_* 优先于文件。

    找不到文件且无环境变量时返回空 LLMConfig(configured=False);调用方应据此跳过实时部分。
    """
    data: dict = {}
    resolved = path or os.environ.get("SENTINEL_LLMENV") or _find_llmenv()
    if resolved and os.path.isfile(resolved):
        data = _parse(resolved)

    def pick(key: str) -> str:
        return os.environ.get(key, data.get(key, ""))

    return LLMConfig(
        provider=pick("LLM_PROVIDER"),
        api_key=pick("LLM_API_KEY"),
        base_url=pick("LLM_BASE_URL"),
        model=pick("LLM_MODEL_NAME"),
    )
