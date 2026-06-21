# -*- coding: utf-8 -*-
import os

from app.config import SentinelConfig, load_config, validate_config


def test_missing_file_returns_safe_default(tmp_path):
    cfg = load_config(str(tmp_path / "nope.yaml"))
    assert isinstance(cfg, SentinelConfig)
    assert cfg.name == "default"
    assert cfg.protected_terms == []


def test_load_real_config():
    cfg = load_config("sentinel.config.yaml")
    assert cfg.name  # 非空
    assert isinstance(cfg.scanners, dict)


def test_validate_warns_on_example_name(monkeypatch):
    monkeypatch.delenv("SENTINEL_ALLOW_DEFAULT", raising=False)
    cfg = SentinelConfig(name="default")
    warnings = validate_config(cfg)
    assert any("team.name" in w for w in warnings)


def test_validate_warns_threshold_out_of_range():
    cfg = SentinelConfig(name="x", protected_terms=["A01"], input_threshold=1.5)
    warnings = validate_config(cfg)
    assert any("input" in w for w in warnings)


def test_validate_warns_external_llm_judge():
    cfg = SentinelConfig(
        name="x",
        protected_terms=["A01"],
        scanners={"use_llm_judge": True},
        llm_judge={"base_url": "https://api.minimaxi.com/anthropic"},
    )
    warnings = validate_config(cfg)
    assert any("数据不出域" in w for w in warnings)


def test_validate_no_warn_local_llm_judge():
    cfg = SentinelConfig(
        name="x",
        protected_terms=["A01"],
        scanners={"use_llm_judge": True},
        llm_judge={"base_url": "http://localhost:8000/anthropic"},
    )
    warnings = validate_config(cfg)
    assert not any("数据不出域" in w for w in warnings)
