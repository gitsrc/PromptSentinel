# -*- coding: utf-8 -*-
"""本地 ML 适配器(LLM Guard / Llama Prompt Guard 2),可选增强、优雅降级。

封装 LLM Guard 的输入(PromptInjection)与输出(Sensitive)扫描器。未安装 llm-guard 时
`available=False`,确定性规则照常工作、服务可离线运行。所有扫描器异常都被吞掉。

数据不出域:LLM Guard 在本地推理,模型权重一次下载后离线;不外发 prompt/response。
"""
from __future__ import annotations

from typing import List, Tuple


class LLMGuardAdapter:
    def __init__(self, threshold: float = 0.5):
        self.input_scanners: list = []
        self.output_scanners: list = []
        self.available = False
        try:
            from llm_guard.input_scanners import PromptInjection
            from llm_guard.input_scanners.prompt_injection import MatchType

            self.input_scanners = [PromptInjection(threshold=threshold, match_type=MatchType.FULL)]
            try:
                from llm_guard.output_scanners import Sensitive

                self.output_scanners = [Sensitive()]
            except Exception:
                self.output_scanners = []
            self.available = True
        except Exception:
            # llm-guard 未安装或加载失败 → 静默降级。
            self.available = False

    def scan_input(self, text: str) -> Tuple[bool, float, List[str]]:
        if not self.input_scanners:
            return False, 0.0, []
        flagged, worst, names = False, 0.0, []
        for scanner in self.input_scanners:
            try:
                _, ok, risk = scanner.scan(text)
                worst = max(worst, float(risk))
                if not ok:
                    flagged = True
                    names.append(type(scanner).__name__)
            except Exception:
                continue
        return flagged, worst, names

    def scan_output(self, prompt: str, text: str) -> Tuple[bool, float, List[str]]:
        if not self.output_scanners:
            return False, 0.0, []
        flagged, worst, names = False, 0.0, []
        for scanner in self.output_scanners:
            try:
                _, ok, risk = scanner.scan(prompt, text)
                worst = max(worst, float(risk))
                if not ok:
                    flagged = True
                    names.append(type(scanner).__name__)
            except Exception:
                continue
        return flagged, worst, names

    @classmethod
    def disabled(cls) -> "LLMGuardAdapter":
        """构造一个始终不可用的适配器(use_llm_guard=false 时用)。"""
        obj = cls.__new__(cls)
        obj.input_scanners = []
        obj.output_scanners = []
        obj.available = False
        return obj
