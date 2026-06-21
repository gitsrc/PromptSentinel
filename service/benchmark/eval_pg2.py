# -*- coding: utf-8 -*-
"""PG2(prompt_guard_onnx)后端在公开集 + 中文语料上的 regex/pg2/hybrid 效果 × 成本。

落盘 benchmark/pg2_compare.json,为文档/门户中 PG2 的数字(gandalf/in-the-wild/中文/延迟)
提供**可复现来源**。用法:python -m benchmark.eval_pg2 [--gandalf 1000] [--itw 300]
"""
from __future__ import annotations

import argparse
import json
import os
import time

os.environ.setdefault("HF_HUB_DOWNLOAD_TIMEOUT", "120")

from app.config import load_config
from app.engine import SentinelGuard
from app.scanners.ml_classifier import _looks_chinese
from app.scanners.onnx_guard import OnnxPromptGuardScanner
from benchmark.eval_dataset import load_rows
from redteam.corpus import CORPUS

_HERE = os.path.dirname(__file__)
_DEEPSET = os.path.join(_HERE, "datasets", "deepset_prompt_injections.jsonl")


def _rss():
    try:
        for line in open("/proc/self/status"):
            if line.startswith("VmRSS:"):
                return round(int(line.split()[1]) / 1024, 0)
    except Exception:
        pass
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gandalf", type=int, default=1000)
    ap.add_argument("--itw", type=int, default=300)
    ap.add_argument("--out", default=os.path.join(_HERE, "pg2_compare.json"))
    args = ap.parse_args()

    t0 = time.time()
    pg2 = OnnxPromptGuardScanner(threshold=0.5)
    load_s = round(time.time() - t0, 1)
    rgx = SentinelGuard(protected_terms=load_config().protected_terms)  # 纯规则
    print("PG2 available=%s load=%.1fs" % (pg2.available, load_s))

    def R(t):
        return not rgx.screen_input(t).allowed

    def P(t):
        return pg2.score(t) >= 0.5

    deep = [json.loads(l) for l in open(_DEEPSET, encoding="utf-8")]
    sets = {
        "gandalf 套取(主线)": ([r["text"] for r in load_rows("gandalf")][: args.gandalf], None),
        "in-the-wild 越狱": ([r["text"] for r in load_rows("inthewild")][: args.itw], None),
        "deepset 注入(参照)": ([r["text"] for r in deep if r["split"] == "test" and r["label"] == 1],
                            [r["text"] for r in deep if r["label"] == 0]),
        "中文 attack(corpus)": ([c["text"] for c in CORPUS if c["label"] == "attack" and _looks_chinese(c["text"])],
                              [c["text"] for c in CORPUS if c["label"] == "benign"]),
    }
    rep = {"backend": "prompt_guard_onnx", "model": pg2.model_name, "available": pg2.available,
           "threshold": 0.5, "sets": {}}
    for name, (atk, ben) in sets.items():
        ra = [R(t) for t in atk]
        pa = [P(t) for t in atk]
        row = {"n": len(atk),
               "regex": round(sum(ra) / len(atk), 3),
               "pg2": round(sum(pa) / len(atk), 3),
               "hybrid": round(sum(1 for r, p in zip(ra, pa) if r or p) / len(atk), 3)}
        if ben:
            rb = [R(t) for t in ben]
            pb = [P(t) for t in ben]
            row["n_benign"] = len(ben)
            row["fpr_hybrid"] = round(sum(1 for r, p in zip(rb, pb) if r or p) / len(ben), 3)
        rep["sets"][name] = row
        print(" ", name, row)

    lat = []
    for t in [r["text"] for r in load_rows("gandalf")][:40]:
        s = time.time()
        pg2.score(t)
        lat.append((time.time() - s) * 1000)
    lat.sort()
    rep["cost"] = {"model_load_s": load_s, "rss_mb": _rss(),
                   "pg2_ms_p50": round(lat[len(lat) // 2], 1),
                   "pg2_ms_p95": round(lat[int(len(lat) * 0.95)], 1)}
    print("  cost", rep["cost"])
    json.dump(rep, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("-> wrote", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
