# -*- coding: utf-8 -*-
"""扫描器协议与结果对象。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class ScanOutcome:
    """单个扫描器的判定结果。"""

    flagged: bool = False
    risk: float = 0.0
    names: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.names is None:
            self.names = []


class Scanner:
    """扫描器协议(鸭子类型即可):至少暴露 available 与 scan_input/scan_output。

    约定:任何扫描器异常都应被自身吞掉并返回未命中(flagged=False),绝不让服务崩。
    """

    available: bool = False

    def scan_input(self, text: str) -> Tuple[bool, float, List[str]]:  # pragma: no cover - 协议
        return False, 0.0, []

    def scan_output(self, prompt: str, text: str) -> Tuple[bool, float, List[str]]:  # pragma: no cover
        return False, 0.0, []
