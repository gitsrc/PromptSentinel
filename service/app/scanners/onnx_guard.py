# -*- coding: utf-8 -*-
"""低成本多语种 ML 注入检测(Llama Prompt Guard 2 22M · ONNX)。

相比 deberta(184M / torch / ~150ms):仅 **22M**、onnxruntime、**~17ms(快 ~6×)**、
**多语种**(含中文,且中文良性不误报 → 无需 lang_guard)。英文 in-the-wild 召回更高
(0.893 vs 0.75)。模型镜像 ungated(gravitee-io 社区重传)。

诚实边界:中文注入的**语义召回弱**(Prompt Guard 2 对中文"指令覆盖/套取"类基本不报,
业界普遍缺口),中文仍主要靠确定性规则。
可用性:onnxruntime/transformers 缺失或下载失败 → available=False,引擎降级回规则。
数据不出域:本地 onnxruntime 推理,权重一次下载后离线。
"""
from __future__ import annotations

import glob
import json
import os
from typing import List, Tuple

DEFAULT_REPO = "gravitee-io/Llama-Prompt-Guard-2-22M-onnx"


class OnnxPromptGuardScanner:
    def __init__(self, model_repo: str = DEFAULT_REPO, threshold: float = 0.5,
                 max_length: int = 512, quantized: bool = False, lang_guard: bool = False):
        self.available = False
        self.quantized = quantized
        self.threshold = threshold
        self.max_length = max_length
        self.lang_guard = lang_guard           # PG2 中文良性安全,默认不需要 lang_guard
        self.model_name = model_repo
        self._tok = None
        self._sess = None
        self._np = None
        self._inj_idx = 1
        try:
            import numpy as np
            import onnxruntime as ort
            from huggingface_hub import snapshot_download
            from transformers import AutoTokenizer

            self._np = np
            local = snapshot_download(model_repo)
            files = sorted(glob.glob(os.path.join(local, "**", "*.onnx"), recursive=True))
            pick = [f for f in files if ("quant" in os.path.basename(f).lower()) == quantized] or files
            self._tok = AutoTokenizer.from_pretrained(local)
            self._sess = ort.InferenceSession(pick[0], providers=["CPUExecutionProvider"])
            cfg = json.load(open(os.path.join(local, "config.json")))
            idx = [int(i) for i, lab in cfg.get("id2label", {}).items()
                   if "MAL" in str(lab).upper() or "INJ" in str(lab).upper()]
            self._inj_idx = idx[0] if idx else 1
            self.available = True
        except Exception:
            self.available = False

    def score(self, text: str) -> float:
        if not self.available or not text:
            return 0.0
        try:
            np = self._np
            enc = self._tok(text, return_tensors="np", truncation=True, max_length=self.max_length)
            feeds = {i.name: enc[i.name].astype(np.int64) for i in self._sess.get_inputs() if i.name in enc}
            logits = self._sess.run(None, feeds)[0][0]
            e = np.exp(logits - logits.max())
            return float((e / e.sum())[self._inj_idx])
        except Exception:
            return 0.0

    def score_batch(self, texts: List[str], batch_size: int = 32) -> List[float]:
        return [self.score(t) for t in texts]

    def scan_input(self, text: str) -> Tuple[bool, float, List[str]]:
        risk = self.score(text)
        flagged = risk >= self.threshold
        return flagged, risk, (["prompt_guard2"] if flagged else [])

    @classmethod
    def disabled(cls) -> "OnnxPromptGuardScanner":
        obj = cls.__new__(cls)
        obj.available = False
        obj.quantized = False
        obj.threshold = 0.5
        obj.max_length = 512
        obj.lang_guard = False
        obj.model_name = DEFAULT_REPO
        obj._tok = obj._sess = obj._np = None
        obj._inj_idx = 1
        return obj
