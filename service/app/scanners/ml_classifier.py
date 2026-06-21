# -*- coding: utf-8 -*-
"""业界基准级 ML 注入分类器(可选增强,本地推理、数据不出域)。

默认模型:ProtectAI/deberta-v3-base-prompt-injection-v2(Apache-2.0,可自托管,CPU 可跑)。
这是把 ② 输入注入检测从"确定性正则基线"提升到"业界基准水平"的关键层 —— 正则抓不到的
语义改写/角色扮演越狱,由它的语义召回兜住。

可用性:transformers/torch 缺失或模型下载失败 → available=False,引擎降级回确定性规则,不崩。
数据不出域:本地推理,模型权重一次性下载后离线;不外发 prompt。

诚实边界:
  * 该模型以英文为主,对**中文良性**文本(含"忽略/指令"等词)可能误报(FPR)——
    故提供 `lang_guard`:对疑似中文文本不单独用 ML 触发(交回中文确定性规则),降低误报。
  * 检测仍是概率性的;越权/外泄须架构层兜底。
"""
from __future__ import annotations

import os
import re
from typing import List, Optional, Tuple

DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
_CJK = re.compile(r"[一-鿿]")


def _looks_chinese(text: str) -> bool:
    """粗判:CJK 字符占比 > 20% 视为中文为主。"""
    if not text:
        return False
    cjk = len(_CJK.findall(text))
    return cjk / max(1, len(text)) > 0.2


class MLInjectionScanner:
    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        threshold: float = 0.5,
        max_length: int = 512,
        lang_guard: bool = True,
        quantize: bool = False,
    ):
        # 注意:quantize 默认 False —— 实测 torch 动态量化会令 deberta-v3 精度崩塌
        # (gandalf recall 1.00→0.01),且 CPU 上几乎不省时;故不推荐对本模型量化。
        self.available = False
        self.quantized = False
        self.threshold = threshold
        self.max_length = max_length
        self.lang_guard = lang_guard
        self.model_name = model_name
        self._tok = None
        self._mdl = None
        self._torch = None
        self._inj_idx = 1
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            import torch

            try:  # 用满 CPU 核,降低单条推理延迟
                torch.set_num_threads(max(1, os.cpu_count() or 4))
            except Exception:
                pass
            self._torch = torch
            self._tok = AutoTokenizer.from_pretrained(model_name)
            self._mdl = AutoModelForSequenceClassification.from_pretrained(model_name)
            self._mdl.eval()
            # 成本优化:动态 int8 量化(仅 Linear 层)。CPU 推理更快、内存更小,精度损失极小。
            if quantize:
                try:
                    self._mdl = torch.quantization.quantize_dynamic(
                        self._mdl, {torch.nn.Linear}, dtype=torch.qint8)
                    self.quantized = True
                except Exception:
                    self.quantized = False
            idx = [i for i, lab in self._mdl.config.id2label.items() if "INJ" in str(lab).upper()]
            self._inj_idx = idx[0] if idx else 1
            self.available = True
        except Exception:
            self.available = False

    # ------------------------------------------------------------------
    def _score_one(self, text: str) -> float:
        torch = self._torch
        with torch.no_grad():
            enc = self._tok(text, return_tensors="pt", truncation=True, max_length=self.max_length)
            probs = torch.nn.functional.softmax(self._mdl(**enc).logits, dim=-1)[0]
        return float(probs[self._inj_idx])

    def score(self, text: str) -> float:
        """返回 P(injection)∈[0,1];不可用或异常时 0.0。"""
        if not self.available or not text:
            return 0.0
        try:
            return self._score_one(text)
        except Exception:
            return 0.0

    def score_batch(self, texts: List[str], batch_size: int = 16) -> List[float]:
        """批量打分(评测用,显著快于逐条)。"""
        if not self.available:
            return [0.0] * len(texts)
        torch = self._torch
        out: List[float] = []
        try:
            for i in range(0, len(texts), batch_size):
                chunk = [t or " " for t in texts[i:i + batch_size]]
                with torch.no_grad():
                    enc = self._tok(chunk, return_tensors="pt", truncation=True,
                                    max_length=self.max_length, padding=True)
                    probs = torch.nn.functional.softmax(self._mdl(**enc).logits, dim=-1)
                out.extend(float(p[self._inj_idx]) for p in probs)
            return out
        except Exception:
            return [0.0] * len(texts)

    def scan_input(self, text: str) -> Tuple[bool, float, List[str]]:
        """与其它扫描器同构:返回 (flagged, risk, names)。

        lang_guard:中文为主的文本不单独由 ML 触发拦截(避免英文模型误报),
        但仍返回风险分供观测;中文攻击交由中文确定性规则负责。
        """
        risk = self.score(text)
        if self.lang_guard and _looks_chinese(text):
            return False, risk, []
        flagged = risk >= self.threshold
        return flagged, risk, (["ml_classifier"] if flagged else [])

    @classmethod
    def disabled(cls) -> "MLInjectionScanner":
        obj = cls.__new__(cls)
        obj.available = False
        obj.quantized = False
        obj.threshold = 0.5
        obj.max_length = 512
        obj.lang_guard = True
        obj.model_name = DEFAULT_MODEL
        obj._tok = obj._mdl = obj._torch = None
        obj._inj_idx = 1
        return obj
