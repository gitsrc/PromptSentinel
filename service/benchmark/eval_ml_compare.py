# -*- coding: utf-8 -*-
"""regex 基线 vs ML 分类器 vs hybrid —— 量化"效果"与"成本"。

效果:在业界数据集上 recall(攻击拦截)/ FPR(良性误拦)。
成本:ML 单条推理延迟(批量 & 单条)、常驻内存(RSS)。
ML = ProtectAI/deberta-v3-base-prompt-injection-v2(本地、Apache-2.0)。
hybrid = 确定性规则命中 OR ML 命中。中文文本 lang_guard:ML 不单独触发,交回中文规则。

高效:每条样本 ML 只推理一次(缓存分数),适度抽样以控成本。
用法:python -m benchmark.eval_ml_compare [--out f.json] [--threshold 0.5] [--gandalf 400] [--itw 200]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time

os.environ.setdefault("HF_HUB_DOWNLOAD_TIMEOUT", "120")

from app.config import load_config
from app.engine import SentinelGuard
from app.scanners.ml_classifier import MLInjectionScanner, _looks_chinese

_HERE = os.path.dirname(__file__)
_DEEPSET = os.path.join(_HERE, "datasets", "deepset_prompt_injections.jsonl")


def _rss_mb() -> float:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024, 1)
    except Exception:
        pass
    return 0.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--gandalf", type=int, default=400)
    ap.add_argument("--itw", type=int, default=200)
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    thr = args.threshold

    t0 = time.time()
    ml = MLInjectionScanner(threshold=thr)
    load_s = round(time.time() - t0, 1)
    rss_after_load = _rss_mb()
    print("ML loaded in %.1fs  available=%s  RSS=%sMB" % (load_s, ml.available, rss_after_load))
    regex_guard = SentinelGuard(protected_terms=load_config().protected_terms)  # ML off

    # 缓存:对一组文本各跑一次 ml + regex
    timing = {"ml_items": 0, "ml_seconds": 0.0}

    def predict(texts):
        t = time.time()
        scores = ml.score_batch(texts)
        timing["ml_seconds"] += time.time() - t
        timing["ml_items"] += len(texts)
        mlp = [(0.0 if _looks_chinese(tx) else s) >= thr for tx, s in zip(texts, scores)]
        rgx = [not regex_guard.screen_input(tx).allowed for tx in texts]
        hyb = [a or b for a, b in zip(rgx, mlp)]
        return rgx, mlp, hyb

    def recall(flags):
        return round(sum(flags) / len(flags), 4) if flags else None

    from datasets import load_dataset

    ds = [json.loads(line) for line in open(_DEEPSET, encoding="utf-8")]
    deep_atk = [r["text"] for r in ds if r["split"] == "test" and r["label"] == 1]
    deep_legit = [r["text"] for r in ds if r["label"] == 0]

    gd = load_dataset("Lakera/gandalf_ignore_instructions")
    gand = [r["text"] for sp in gd for r in gd[sp]]
    random.Random(42).shuffle(gand)
    gand = gand[: args.gandalf]

    itw = load_dataset("TrustAIRLab/in-the-wild-jailbreak-prompts", "jailbreak_2023_12_25")
    itw_rows = [r["prompt"] for r in itw["train"] if r.get("prompt")]
    random.Random(42).shuffle(itw_rows)
    itw_rows = itw_rows[: args.itw]

    from redteam.corpus import CORPUS
    zh_benign = [c["text"] for c in CORPUS if c["label"] == "benign"]

    report = {"model": ml.model_name, "threshold": thr, "attack_sets": {}, "fpr_sets": {}, "cost": {}}

    print("\n=== RECALL(攻击拦截率)===")
    for name, texts in [("gandalf 套取(主线)", gand), ("in-the-wild 越狱", itw_rows), ("deepset 攻击(参照)", deep_atk)]:
        rgx, mlp, hyb = predict(texts)
        report["attack_sets"][name] = {"n": len(texts), "regex": recall(rgx), "ml": recall(mlp), "hybrid": recall(hyb)}
        print("  %-22s n=%-4d regex=%.3f  ml=%.3f  hybrid=%.3f" % (name, len(texts), recall(rgx), recall(mlp), recall(hyb)))

    print("\n=== FPR(良性误拦率)===")
    for name, texts in [("deepset 良性(en/de)", deep_legit), ("自家中文良性", zh_benign)]:
        rgx, mlp, hyb = predict(texts)
        report["fpr_sets"][name] = {"n": len(texts), "regex": recall(rgx), "ml": recall(mlp), "hybrid": recall(hyb)}
        print("  %-22s n=%-4d regex=%.3f  ml=%.3f  hybrid=%.3f" % (name, len(texts), recall(rgx), recall(mlp), recall(hyb)))

    # 成本:批量平均 + 单条 p50
    single = []
    for tx in (gand[:30] or ["test"]):
        t = time.time()
        ml.score(tx)
        single.append((time.time() - t) * 1000.0)
    single.sort()
    report["cost"] = {
        "model_load_s": load_s,
        "rss_mb": _rss_mb(),
        "ml_ms_per_item_batched": round(timing["ml_seconds"] / max(1, timing["ml_items"]) * 1000.0, 2),
        "ml_ms_per_item_single_p50": round(single[len(single) // 2], 2),
        "regex_ms_per_item": "<0.1(亚毫秒,纯正则)",
    }
    print("\n=== 成本 ===")
    print("  模型加载 %.1fs | 常驻内存 %sMB | ML 批量 %.1fms/条 | ML 单条 p50 %.1fms/条 | regex <0.1ms/条"
          % (load_s, report["cost"]["rss_mb"], report["cost"]["ml_ms_per_item_batched"], report["cost"]["ml_ms_per_item_single_p50"]))

    if args.out:
        json.dump(report, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("-> wrote", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
