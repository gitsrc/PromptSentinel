# -*- coding: utf-8 -*-
"""配置加载与校验。

各团队**唯一要改**的文件是 sentinel.config.yaml;本模块把它读成 SentinelConfig
dataclass,并在缺文件时返回安全默认值(服务仍可启动、确定性规则仍工作)。

环境变量:
  SENTINEL_CONFIG        配置文件路径(默认 sentinel.config.yaml)
  SENTINEL_ALLOW_DEFAULT 设为非空时,validate_config 不再对示例 team.name 告警
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .patterns import REFUSAL

DEFAULT_PATH = os.environ.get("SENTINEL_CONFIG", "sentinel.config.yaml")


@dataclass
class SentinelConfig:
    """单团队的防护配置。"""

    name: str = "default"
    agent: str = "PromptSentinel Agent"
    protected_terms: List[str] = field(default_factory=list)
    protected_patterns: List[str] = field(default_factory=list)
    refusal_message: str = REFUSAL
    input_threshold: float = 0.5
    untrusted_threshold: float = 0.35
    scanners: Dict[str, bool] = field(default_factory=dict)
    llm_judge: Dict[str, object] = field(default_factory=dict)
    ml_classifier: Dict[str, object] = field(default_factory=dict)
    server: Dict[str, object] = field(default_factory=dict)


def load_config(path: Optional[str] = None) -> SentinelConfig:
    """读取 YAML 配置;文件不存在时返回安全默认(SentinelConfig())。

    yaml 未安装会抛 RuntimeError——服务依赖 pyyaml,这是显式失败而非静默降级。
    """
    path = path or DEFAULT_PATH
    try:
        import yaml  # noqa: WPS433 (局部导入,缺失时给出清晰错误)
    except Exception as exc:  # pragma: no cover - 依赖缺失路径
        raise RuntimeError("需要 pyyaml(pip install pyyaml)") from exc

    if not os.path.exists(path):
        return SentinelConfig()

    with open(path, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    team = raw.get("team", {}) or {}
    thresholds = raw.get("thresholds", {}) or {}
    refusal = raw.get("refusal_message", REFUSAL)

    return SentinelConfig(
        name=team.get("name", "default"),
        agent=team.get("agent", "PromptSentinel Agent"),
        protected_terms=list(raw.get("protected_terms", []) or []),
        protected_patterns=list(raw.get("protected_patterns", []) or []),
        refusal_message=(refusal or REFUSAL).strip(),
        input_threshold=float(thresholds.get("input", 0.5)),
        untrusted_threshold=float(thresholds.get("untrusted", 0.35)),
        scanners=dict(raw.get("scanners", {}) or {}),
        llm_judge=dict(raw.get("llm_judge", {}) or {}),
        ml_classifier=dict(raw.get("ml_classifier", {}) or {}),
        server=dict(raw.get("server", {}) or {}),
    )


def validate_config(cfg: SentinelConfig) -> List[str]:
    """返回非致命告警列表(不阻断启动,提示接入质量问题)。"""
    warnings: List[str] = []

    if cfg.name in ("default", "wind-ops") and not os.environ.get("SENTINEL_ALLOW_DEFAULT"):
        warnings.append("team.name 仍是示例值,请改成你团队的名字(设 SENTINEL_ALLOW_DEFAULT=1 可忽略)")
    if not cfg.protected_terms:
        warnings.append("protected_terms 为空——未配置受保护标识符,输出端只能靠默认正则")
    if not (0.0 <= cfg.input_threshold <= 1.0):
        warnings.append("thresholds.input 不在 0~1 之间")
    if not (0.0 <= cfg.untrusted_threshold <= 1.0):
        warnings.append("thresholds.untrusted 不在 0~1 之间")
    if cfg.scanners.get("canary") is False:
        warnings.append("canary 已关闭,将无法检测系统提示词逐字泄露")
    if cfg.scanners.get("use_llm_judge"):
        base_url = str(cfg.llm_judge.get("base_url", ""))
        if base_url and not _is_local_endpoint(base_url):
            warnings.append(
                "use_llm_judge=true 且 llm_judge.base_url 指向外部地址——"
                "这会把待检测文本发往外部,破坏「数据不出域」红线,请确认该端点为自托管"
            )
    mode = str(cfg.server.get("mode", "enforce")).lower()
    if mode not in ("enforce", "shadow"):
        warnings.append(
            "server.mode 取值非法(应为 enforce/shadow),已回退 enforce——"
            "若本意是影子灰度(shadow),请修正拼写,否则会真实拦截造成误拦"
        )
    return warnings


def enforce_config(cfg: SentinelConfig) -> None:
    """致命配置校验:严格模式(SENTINEL_STRICT=1 或 SENTINEL_ENV=prod)下,不合法即阻断启动(fail-fast)。"""
    if os.environ.get("SENTINEL_STRICT") != "1" and os.environ.get("SENTINEL_ENV") != "prod":
        return
    fatal: List[str] = []
    if not (0.0 <= cfg.input_threshold <= 1.0):
        fatal.append("thresholds.input 越界(应 0~1)")
    if not (0.0 <= cfg.untrusted_threshold <= 1.0):
        fatal.append("thresholds.untrusted 越界(应 0~1)")
    if str(cfg.server.get("mode", "enforce")).lower() not in ("enforce", "shadow"):
        fatal.append("server.mode 非法(应 enforce/shadow)")
    token = os.environ.get("SENTINEL_AUTH_TOKEN") or str(cfg.server.get("auth_token", "") or "")
    if not token:
        fatal.append("鉴权未配置(严格模式要求 auth_token 或 SENTINEL_AUTH_TOKEN)")
    if fatal:
        raise SystemExit("[FATAL] 严格模式配置校验失败: " + "; ".join(fatal))


def _is_local_endpoint(url: str) -> bool:
    """粗略判断端点是否为本地/内网(用于破域告警,不作安全保证)。"""
    lowered = url.lower()
    for token in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal"):
        if token in lowered:
            return True
    return False
