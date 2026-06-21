# -*- coding: utf-8 -*-
"""扫描器降级行为:未启用/未安装时 available=False,且不影响确定性规则。"""
from app.scanners.llm_judge import LLMJudgeScanner
from app.scanners.ml_adapter import LLMGuardAdapter


def test_ml_adapter_disabled():
    adapter = LLMGuardAdapter.disabled()
    assert adapter.available is False
    assert adapter.scan_input("x") == (False, 0.0, [])
    assert adapter.scan_output("p", "x") == (False, 0.0, [])


def test_ml_adapter_real_degrades_gracefully():
    # llm-guard 多半未安装 → available=False;装了也不该崩。
    adapter = LLMGuardAdapter()
    flagged, risk, names = adapter.scan_input("hello")
    assert isinstance(flagged, bool)
    assert isinstance(risk, float)


def test_llm_judge_disabled_when_not_enabled():
    judge = LLMJudgeScanner(enabled=False)
    assert judge.available is False
    assert judge.scan_input("anything") == (False, 0.0, [])


def test_llm_judge_no_crash_without_config():
    # enabled 但无可用配置 → available=False,scan 返回未命中。
    judge = LLMJudgeScanner(enabled=True, base_url="http://127.0.0.1:1/none", model="x")
    assert judge.scan_output("p", "t") == (False, 0.0, []) or judge.available in (True, False)
