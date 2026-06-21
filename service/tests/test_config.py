# -*- coding: utf-8 -*-
import os

from app.config import (
    SentinelConfig,
    is_trusted_proxy,
    load_config,
    parse_trusted_proxies,
    validate_config,
)


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


def test_trusted_proxies_empty_default_trusts_nobody():
    # 默认空 ⇒ 不信任任何 XFF;任何直连 host 都判 False。
    nets = parse_trusted_proxies("")
    assert nets == []
    assert is_trusted_proxy("10.0.0.1", nets) is False
    assert is_trusted_proxy(None, parse_trusted_proxies(None)) is False


def test_trusted_proxies_ip_and_cidr():
    nets = parse_trusted_proxies("10.0.0.5, 192.168.0.0/24")
    # 精确 IP(/32)命中
    assert is_trusted_proxy("10.0.0.5", nets) is True
    assert is_trusted_proxy("10.0.0.6", nets) is False
    # CIDR 命中
    assert is_trusted_proxy("192.168.0.42", nets) is True
    assert is_trusted_proxy("192.168.1.42", nets) is False
    # 非法/缺失对端 ⇒ False
    assert is_trusted_proxy("not-an-ip", nets) is False
    assert is_trusted_proxy(None, nets) is False


def test_trusted_proxies_skips_invalid_entries():
    # 非法条目跳过,不影响合法条目。
    nets = parse_trusted_proxies("garbage, 127.0.0.1, , 999.1.1.1")
    assert is_trusted_proxy("127.0.0.1", nets) is True
    assert len(nets) == 1
