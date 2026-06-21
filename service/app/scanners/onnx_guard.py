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
import logging
import os
from typing import List, Tuple

logger = logging.getLogger("promptsentinel")

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
            # 离线可复现:运行时绝不联网,只用预下载进镜像/缓存的权重。
            # 缺权重时由下方 except 捕获并降级(available=False),不静默触网。
            local = snapshot_download(model_repo, local_files_only=True)
            files = sorted(glob.glob(os.path.join(local, "**", "*.onnx"), recursive=True))
            pick = [f for f in files if ("quant" in os.path.basename(f).lower()) == quantized] or files
            if not pick:
                raise FileNotFoundError(f"no .onnx weights under {local}")
            self._tok = AutoTokenizer.from_pretrained(local, local_files_only=True)
            # 容器 cpus 配额下消除线程超订/争用:把 onnxruntime 线程池钉到单线程,
            # 由编排层(并发请求/进程)而非 ORT 内部线程做并行,避免上下文切换抖动。
            so = ort.SessionOptions()
            so.intra_op_num_threads = 1
            so.inter_op_num_threads = 1
            self._sess = ort.InferenceSession(
                pick[0], sess_options=so, providers=["CPUExecutionProvider"]
            )
            with open(os.path.join(local, "config.json")) as fh:
                cfg = json.load(fh)
            idx = [int(i) for i, lab in cfg.get("id2label", {}).items()
                   if "MAL" in str(lab).upper() or "INJ" in str(lab).upper()]
            self._inj_idx = idx[0] if idx else 1
            self.available = True
        except Exception as exc:
            # 清晰日志:加载失败的原因可见,便于排障;available=False 由 /ready 兜底降级。
            self.available = False
            logger.warning(
                "OnnxPromptGuardScanner unavailable (repo=%s, offline): %s: %s",
                model_repo, type(exc).__name__, exc,
            )

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
