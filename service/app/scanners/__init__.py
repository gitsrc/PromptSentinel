# -*- coding: utf-8 -*-
"""可选增强扫描器(本地 ML 适配器 + 可选 LLM-judge)。

确定性规则(canary / 受保护标识符 / 注入短语)是安全基线,始终在引擎里;本子包提供
**可选**的语义增强层,缺失或关闭时优雅降级,不影响确定性规则与服务可用性。
"""
from .base import ScanOutcome, Scanner
from .ml_adapter import LLMGuardAdapter
from .llm_judge import LLMJudgeScanner

__all__ = ["ScanOutcome", "Scanner", "LLMGuardAdapter", "LLMJudgeScanner"]
