# -*- coding: utf-8 -*-
"""可选的大模型工具(开发/测试用,以及可选的 LLM-judge 运行时扫描器)。

`load_llm_config` 读取仓库内 `.llmenv`;`LLMClient` 是一个 Anthropic Messages 兼容
的极简客户端,指向 .llmenv 中配置的 base_url(本仓库默认 MiniMax 的 /anthropic 端点)。

红线提醒:用 .llmenv(外部端点)做**红队、评测、demo**是允许的;但若把 LLM-judge 作为
运行时检测路径指向外部 API,会把待检测文本发往外部,**破坏「数据不出域」**——默认关闭。
"""
from .env import LLMConfig, load_llm_config
from .client import LLMClient, LLMError

__all__ = ["LLMConfig", "load_llm_config", "LLMClient", "LLMError"]
