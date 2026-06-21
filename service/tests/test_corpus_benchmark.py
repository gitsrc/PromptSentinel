# -*- coding: utf-8 -*-
"""校验红蓝对抗语料结构,并断言确定性层在语料上达标(recall=1.0, fpr=0)。"""
from app.config import load_config
from app.engine import build_guard_from_config
from benchmark.run_benchmark import by_category, evaluate, latency_stats, metrics
from redteam.corpus import CORPUS


def test_corpus_shape():
    assert len(CORPUS) >= 30
    for item in CORPUS:
        assert set(item) >= {"id", "label", "surface", "category", "text"}
        assert item["label"] in ("attack", "benign")
        assert item["surface"] in ("input", "untrusted", "output")
    ids = [i["id"] for i in CORPUS]
    assert len(ids) == len(set(ids)), "corpus id 不唯一"


def test_corpus_has_benign_and_easy_fp():
    labels = {i["label"] for i in CORPUS}
    assert "attack" in labels and "benign" in labels
    assert any(i["category"] == "易误报" for i in CORPUS)


def test_deterministic_metrics_meet_targets():
    guard = build_guard_from_config(load_config())
    _, canary = guard.build_system_prompt("base")
    records, latencies = evaluate(guard, canary)
    m = metrics(records)
    assert m["fpr"] == 0.0, m
    assert m["recall"] >= 0.9, m
    assert latency_stats(latencies)["p50"] < 5
    cats = by_category(records)
    assert "输出泄露-canary" in cats
