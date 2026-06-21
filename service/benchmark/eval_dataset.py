# -*- coding: utf-8 -*-
"""统一的公开数据集评测 —— 按防线映射,支持 regex / ml / hybrid 三种模式。

业界数据集(一等公民,首次用 datasets 下载并缓存到 benchmark/datasets/*.jsonl):
  deepset    deepset/prompt-injections           ② 通用注入(参照,有良性→可测 FPR)
  gandalf    Lakera/gandalf_ignore_instructions  ② 系统提示/密钥套取(主线,全攻击)
  inthewild  TrustAIRLab/in-the-wild-jailbreak    ② 真实越狱(全攻击,抽样)
  pii        ai4privacy/pii-masking-200k          ④ 输出 PII(全含 PII,抽样)

模式:regex(零成本基线)/ ml(纯 deberta 分类器)/ hybrid(规则+ML 级联,生产推荐)。
用法:
  python -m benchmark.eval_dataset --dataset all --mode regex
  python -m benchmark.eval_dataset --dataset gandalf --mode hybrid --out r.json
  python -m benchmark.eval_dataset --dataset deepset --split test --mode ml

诚实原则:指标在公开集/holdout 上报告;规则只在 train/挖掘集上调。受控指标 ≠ 真实对抗上限。
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time
from itertools import islice
from typing import List, Optional

os.environ.setdefault("HF_HUB_DOWNLOAD_TIMEOUT", "120")

from app.config import load_config
from app.engine import build_guard_from_config

_HERE = os.path.dirname(__file__)
_CACHE = os.path.join(_HERE, "datasets")
_FILES = {"deepset": "deepset_prompt_injections.jsonl"}

DATASETS = {
    "deepset": {"hf": "deepset/prompt-injections", "surface": "input",
                "line": "② 通用注入(参照)", "all_attack": False},
    "gandalf": {"hf": "Lakera/gandalf_ignore_instructions", "surface": "input",
                "line": "② 系统提示/密钥套取(主线)", "text_field": "text", "all_attack": True},
    "inthewild": {"hf": "TrustAIRLab/in-the-wild-jailbreak-prompts", "config": "jailbreak_2023_12_25",
                  "surface": "input", "line": "② 真实越狱", "text_field": "prompt", "all_attack": True, "cap": 300},
    "pii": {"hf": "ai4privacy/pii-masking-200k", "surface": "output",
            "line": "④ 输出 PII", "text_field": "source_text", "all_attack": True, "cap": 200},
}


def _path(name: str) -> str:
    return os.path.join(_CACHE, _FILES.get(name, name + ".jsonl"))


def _ensure(name: str) -> None:
    """首次下载并缓存为统一 jsonl:{text, label, split}。label 1=攻击/阳性,0=良性。"""
    p = _path(name)
    if os.path.exists(p):
        return
    os.makedirs(_CACHE, exist_ok=True)
    spec = DATASETS[name]
    from datasets import load_dataset
    rows: List[dict] = []
    if name == "deepset":
        ds = load_dataset(spec["hf"])
        for sp in ds:
            for r in ds[sp]:
                rows.append({"text": r["text"], "label": int(r["label"]), "split": sp})
    elif name == "gandalf":
        ds = load_dataset(spec["hf"])
        for sp in ds:
            for r in ds[sp]:
                rows.append({"text": r[spec["text_field"]], "label": 1, "split": "all"})
    elif name == "inthewild":
        ds = load_dataset(spec["hf"], spec["config"])
        items = [r[spec["text_field"]] for r in ds["train"] if r.get(spec["text_field"])]
        random.Random(42).shuffle(items)
        for t in items[: spec["cap"]]:
            rows.append({"text": t, "label": 1, "split": "sample"})
    elif name == "pii":
        ds = load_dataset(spec["hf"], split="train", streaming=True)
        for r in islice(ds, spec["cap"]):
            t = r.get(spec["text_field"]) or r.get("unmasked_text") or r.get("text")
            if t:
                rows.append({"text": t, "label": 1, "split": "sample"})
    with open(p, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def load_rows(name: str, split: Optional[str] = None) -> List[dict]:
    _ensure(name)
    rows = [json.loads(line) for line in open(_path(name), encoding="utf-8")]
    if split:
        rows = [r for r in rows if r.get("split") == split]
    return rows


def make_guard(mode: str):
    """按模式构建引擎:regex(ML off)/ ml(只 ML)/ hybrid(规则+ML 级联)。"""
    cfg = load_config()
    sc = dict(cfg.scanners)
    if mode == "regex":
        sc["use_ml_classifier"] = False
    elif mode == "ml":
        sc["injection_heuristic"] = False
        sc["protected_identifier"] = False
        sc["use_ml_classifier"] = True
        sc["ml_cascade"] = False
    elif mode == "hybrid":
        sc["use_ml_classifier"] = True
    else:
        raise SystemExit("mode 必须是 regex|ml|hybrid")
    cfg.scanners = sc
    return build_guard_from_config(cfg)


def _pct(vals, p):
    s = sorted(vals)
    return round(s[min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1))))], 3) if s else 0.0


def evaluate(name: str, split: Optional[str], guard) -> dict:
    rows = load_rows(name, split)
    surface = DATASETS[name]["surface"]
    tp = fp = tn = fn = 0
    lat = []
    for r in rows:
        t0 = time.perf_counter()
        res = guard.screen_input(r["text"]) if surface == "input" else guard.screen_output(r["text"])
        lat.append((time.perf_counter() - t0) * 1000.0)
        attack = r["label"] == 1
        blocked = not res.allowed
        if attack and blocked:
            tp += 1
        elif attack and not blocked:
            fn += 1
        elif (not attack) and blocked:
            fp += 1
        else:
            tn += 1
    return {
        "dataset": name, "line": DATASETS[name]["line"], "split": split or "all",
        "surface": surface, "n": len(rows),
        "recall": round(tp / (tp + fn), 4) if (tp + fn) else None,
        "fpr": round(fp / (fp + tn), 4) if (fp + tn) else None,
        "confusion": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "latency_ms": {"p50": _pct(lat, 50), "p95": _pct(lat, 95)},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="all", help="all 或 deepset|gandalf|inthewild|pii")
    ap.add_argument("--mode", default="regex", help="regex|ml|hybrid")
    ap.add_argument("--split", default="", help="可选;deepset 默认 test(holdout)")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    names = list(DATASETS) if args.dataset == "all" else [args.dataset]
    guard = make_guard(args.mode)  # ML 仅加载一次
    results = []
    print("=== 公开数据集评测 mode=%s ===" % args.mode)
    for name in names:
        split = args.split or ("test" if name == "deepset" else None)
        res = evaluate(name, split, guard)
        results.append(res)
        rec = "%.3f" % res["recall"] if res["recall"] is not None else " n/a "
        fpr = "%.3f" % res["fpr"] if res["fpr"] is not None else " n/a "
        print("  %-10s %-22s n=%-4d recall=%s fpr=%s p50=%.2fms"
              % (name, res["line"], res["n"], rec, fpr, res["latency_ms"]["p50"]))
    if args.out:
        json.dump({"mode": args.mode, "results": results}, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("-> wrote", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
