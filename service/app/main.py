# -*- coding: utf-8 -*-
"""PromptSentinel FastAPI 服务 —— 安检门的 HTTP 入口。

端点(路径通用,语义稳定):
  GET  /health                     健康检查 + 团队/扫描器可用性
  GET  /version                    版本与能力
  POST /v1/system-prompt/build     构建期加固 + 种 canary
  POST /v1/screen/input            输入检测
  POST /v1/screen/output           输出检测

生产化:
  * 启动时 load_config 构建全局 guard。
  * 结构化日志**绝不记录** prompt/response 正文与凭证,只记 reasons/risk/耗时。
  * 可选服务级 bearer 鉴权(server.auth_token;默认空=不校验)。
  * 业务端零 Python 依赖——任何语言 HTTP 一调即用。
"""
from __future__ import annotations

import copy
import json
import logging
import math
import os
import random
import time
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from . import __version__
from .config import enforce_config, load_config, validate_config
from .engine import build_guard_from_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s promptsentinel %(message)s")
logger = logging.getLogger("promptsentinel")

CFG = load_config()
for _warning in validate_config(CFG):
    logger.warning("config: %s", _warning)
enforce_config(CFG)   # 严格模式(SENTINEL_STRICT=1 / SENTINEL_ENV=prod)下致命配置阻断启动

guard = build_guard_from_config(CFG)
# 启动期可观测:配置开启 ML 但运行时不可用(依赖缺失/权重下载失败)→ 显式告警,避免静默降级。
if CFG.scanners.get("use_ml_classifier") and not guard.ml.available:
    logger.warning(
        "config: use_ml_classifier=true 但 ML 分类器未就绪(依赖缺失/权重下载失败),已降级回确定性规则")
_AUTH_TOKEN = os.environ.get("SENTINEL_AUTH_TOKEN") or str(CFG.server.get("auth_token", "") or "")

# 公开数据集实时评测(数据集随镜像打包在 benchmark/datasets/)。
_DS_DIR = os.path.join(os.path.dirname(__file__), "..", "benchmark", "datasets")
_DATASETS = {
    "gandalf": ("gandalf.jsonl", "input", "② 系统提示/密钥套取(主线)"),
    "inthewild": ("inthewild.jsonl", "input", "② 真实越狱"),
    "pii": ("pii.jsonl", "output", "④ 输出 PII"),
    "deepset": ("deepset_prompt_injections.jsonl", "input", "② 通用注入(参照)"),
    "safeguard": ("safeguard.jsonl", "input", "② 注入检测(含良性·测 FPR)"),
    "chinese_inject": ("chinese_inject.jsonl", "input", "② 中文目标劫持(thu-coai)"),
    "adversarial": ("adversarial.jsonl", "input", "⑤ 对抗变体(编码/间隔/后缀)"),
    "business_benign": ("business_benign.jsonl", "input", "② 业务良性(测真实 FPR)"),
}

# 数据集权威性元信息(供前端审计弹窗展示)。
_DS_META = {
    "gandalf": {"hf": "Lakera/gandalf_ignore_instructions", "license": "MIT", "paper": "arxiv:2501.07927",
                "source": "Lakera(AI 安全公司)· Gandalf 提示注入游戏的真实玩家攻击",
                "url": "https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions"},
    "inthewild": {"hf": "TrustAIRLab/in-the-wild-jailbreak-prompts", "license": "MIT", "paper": "arxiv:2308.03825",
                  "source": "CISPA/TrustAIRLab · 论文《Do Anything Now》(ACM CCS 2024)· 野外真实越狱",
                  "url": "https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts"},
    "pii": {"hf": "ai4privacy/pii-masking-200k", "license": "见上游", "paper": "",
            "source": "ai4privacy · 业界常用 PII 脱敏 200k 数据集",
            "url": "https://huggingface.co/datasets/ai4privacy/pii-masking-200k"},
    "deepset": {"hf": "deepset/prompt-injections", "license": "Apache-2.0", "paper": "",
                "source": "deepset(Haystack 母公司)· 提示注入二分类",
                "url": "https://huggingface.co/datasets/deepset/prompt-injections"},
    "safeguard": {"hf": "xTRam1/safe-guard-prompt-injection", "license": "见上游", "paper": "arxiv:2402.13064",
                  "source": "safe-guard · 注入检测(含大量良性样本,补 FPR)",
                  "url": "https://huggingface.co/datasets/xTRam1/safe-guard-prompt-injection"},
    "chinese_inject": {"hf": "thu-coai/Safety-Prompts", "license": "Apache-2.0", "paper": "arxiv:2304.10436",
                       "source": "清华 thu-coai · 中文注入(Goal_Hijacking 全取 + Prompt_Leaking 按套取动作精筛;Role_Play 多为内容安全已剔除,威胁模型对齐)",
                       "url": "https://huggingface.co/datasets/thu-coai/Safety-Prompts"},
    "adversarial": {"hf": "(本地构造)", "license": "—", "paper": "arxiv:2307.15043",
                    "source": "对抗变体集:对已知攻击施加 leetspeak / 字符间隔 / base64 / GCG 风格后缀,测对抗鲁棒性",
                    "url": ""},
    "business_benign": {"hf": "(本地构造)", "license": "—", "paper": "",
                        "source": "业务良性集:中英文正常业务请求(查询/操作/技术问答),测贴近线上流量的真实 FPR;生产应替换为你自己的真实流量",
                        "url": ""},
}


def _build_regex_guard():
    """与当前配置同源,但强制关闭 ML —— 作为零成本 regex 基线对照。"""
    rc = copy.copy(CFG)
    rc.scanners = dict(CFG.scanners)
    rc.scanners["use_ml_classifier"] = False
    return build_guard_from_config(rc)


_regex_guard = _build_regex_guard()


def _wilson(k: int, n: int, z: float = 1.96):
    """二项比例 Wilson 95% 置信区间 —— 给 recall/FPR 标注抽样不确定性。"""
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def _metrics(tp: int, fp: int, tn: int, fnn: int, lat: list) -> dict:
    """完整指标:recall/precision/F1/FPR + 95% 置信区间 + 延迟 + 混淆矩阵。"""
    rec = tp / (tp + fnn) if (tp + fnn) else None
    # 无良性样本(纯攻击集)时 precision/F1 不可测——分母里没有 FP/TN,prec 会恒等于 1,
    # 是"分母里没有良性"的数学假象而非真实精确率,故置 None,只报 recall + CI。
    has_benign = (fp + tn) > 0
    prec = tp / (tp + fp) if (has_benign and (tp + fp)) else None
    f1 = 2 * prec * rec / (prec + rec) if (prec and rec) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    lat = sorted(lat)
    return {
        "recall": round(rec, 4) if rec is not None else None,
        "recall_ci": _wilson(tp, tp + fnn),
        "precision": round(prec, 4) if prec is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "fpr": round(fpr, 4) if fpr is not None else None,
        "fpr_ci": _wilson(fp, fp + tn),
        "p50_ms": round(lat[len(lat) // 2], 3) if lat else 0.0,
        "confusion": {"TP": tp, "FP": fp, "TN": tn, "FN": fnn},
    }

app = FastAPI(title="PromptSentinel Service · {0}".format(CFG.name), version=__version__)

# 生产级:进程内速率限制(防滥用 / DoS)+ 安全响应头。生产应再叠加网关/nginx 层限流与 TLS。
import secrets as _secrets
import threading as _threading
from collections import deque as _deque
from fastapi.responses import JSONResponse as _JSONResponse

_RATE_BUCKETS = {}
_RATE_LOCK = _threading.Lock()
_RATE_PER_MIN = int(os.environ.get("SENTINEL_RATE_PER_MIN", "240"))
_RATE_MAX_KEYS = int(os.environ.get("SENTINEL_RATE_MAX_KEYS", "20000"))  # 限流字典键上限,防伪造海量 IP 的内存泄漏 DoS
_MAX_BODY_BYTES = int(os.environ.get("SENTINEL_MAX_BODY_BYTES", str(512 * 1024)))  # 请求体硬上限 512KB
_METRICS_LOCK = _threading.Lock()
_BENCH_SEM = _threading.BoundedSemaphore(1)  # benchmark 端点串行,防并发 full 评测饿死线程池


def _client_ip(request) -> str:
    # 反代/LB 后取真实客户端 IP(需上游为可信代理才有意义);否则用直连 IP。
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"


@app.middleware("http")
async def _guardrails(request, call_next):
    # 请求体硬上限:解析前按 Content-Length 拒绝,防超大 body 放大内存/CPU。
    clen = request.headers.get("content-length")
    if clen and clen.isdigit() and int(clen) > _MAX_BODY_BYTES:
        return _JSONResponse({"detail": "payload too large"}, status_code=413)
    ip = _client_ip(request)
    now = time.time()
    with _RATE_LOCK:
        dq = _RATE_BUCKETS.setdefault(ip, _deque())
        while dq and dq[0] < now - 60:
            dq.popleft()
        limited = len(dq) >= _RATE_PER_MIN
        if not limited:
            dq.append(now)
        # GC:键数超上限时清掉所有空闲(空桶或最后活动 >60s 前)的桶,防无界增长。
        if len(_RATE_BUCKETS) > _RATE_MAX_KEYS:
            for k in [k for k, v in list(_RATE_BUCKETS.items()) if not v or v[-1] < now - 60]:
                _RATE_BUCKETS.pop(k, None)
    if limited:
        return _JSONResponse({"detail": "rate limited"}, status_code=429)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# --- pydantic 请求模型 ---
class BuildReq(BaseModel):
    base_prompt: str


class InputReq(BaseModel):
    user_input: str
    untrusted_context: Optional[str] = None


class OutputReq(BaseModel):
    model_output: str
    canary: Optional[str] = None
    system_prompt: Optional[str] = ""


def _auth(authorization: Optional[str] = Header(default=None)) -> None:
    """可选 bearer 鉴权;未配置 auth_token 时直接放行。"""
    if not _AUTH_TOKEN:
        return
    expected = "Bearer {0}".format(_AUTH_TOKEN)
    if not authorization or not _secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="unauthorized")


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "team": CFG.name,
        "agent": CFG.agent,
        "mode": guard.mode,
        "ml_classifier": guard.ml.available,
        "llm_guard": guard.lg.available,
        "llm_judge": guard.judge.available,
        "protected_terms": len(guard.terms),
    }


@app.get("/version")
def version() -> dict:
    return {
        "service": "promptsentinel",
        "version": __version__,
        "scanners": {
            "injection_heuristic": guard._on("injection_heuristic"),
            "protected_identifier": guard._on("protected_identifier"),
            "canary": guard._on("canary"),
            "pii_output": guard._on("pii_output"),
            "ml_classifier": guard.ml.available,
            "llm_guard": guard.lg.available,
            "llm_judge": guard.judge.available,
        },
    }


@app.get("/v1/benchmark")
def benchmark_datasets(n: int = 100, dataset: Optional[str] = None, full: bool = False, _: None = Depends(_auth)) -> dict:
    """实时把公开数据集逐条过引擎,现场算完整指标(recall/precision/F1/FPR + 95% 置信区间)。
    full=true 跑全量(非抽样);dataset 指定单集(供前端分步进度)。
    串行执行(BoundedSemaphore=1):评测是重操作,并发会饿死线程池、拖垮线上 /v1/screen 主链路。"""
    if not _BENCH_SEM.acquire(blocking=False):
        raise HTTPException(status_code=503, detail="benchmark busy, retry later")
    try:
        return _benchmark_impl(n, dataset, full)
    finally:
        _BENCH_SEM.release()


def _benchmark_impl(n: int, dataset: Optional[str], full: bool) -> dict:
    result = {}
    items = {dataset: _DATASETS[dataset]} if (dataset and dataset in _DATASETS) else _DATASETS
    for name, (fn, surface, line) in items.items():
        path = os.path.join(_DS_DIR, fn)
        if not os.path.exists(path):
            continue
        rows = [json.loads(x) for x in open(path, encoding="utf-8")]
        random.Random(42).shuffle(rows)
        if not full:
            rows = rows[: max(10, min(n, len(rows)))]

        def _run(g):
            tp = fp = tn = fnn = 0
            lat = []
            for r in rows:
                started = time.perf_counter()
                res = (g.screen_input(r["text"], _apply_mode=False) if surface == "input"
                       else g.screen_output(r["text"], _apply_mode=False))
                lat.append((time.perf_counter() - started) * 1000.0)
                atk = r.get("label") == 1
                blk = not res.allowed
                if atk and blk:
                    tp += 1
                elif atk and not blk:
                    fnn += 1
                elif (not atk) and blk:
                    fp += 1
                else:
                    tn += 1
            return _metrics(tp, fp, tn, fnn, lat)

        result[name] = {
            "line": line, "surface": surface, "n": len(rows),
            "regex": _run(_regex_guard), "current": _run(guard),
        }
    return {"datasets": result, "ml_enabled": guard.ml.available, "full": full}


@app.get("/v1/datasets")
def datasets_info(samples: int = 4, _: None = Depends(_auth)) -> dict:
    """返回各公开数据集的权威性元信息 + 真实样本(供前端审计弹窗,证明数据真实可溯源)。"""
    out = {}
    for name, (fn, surface, line) in _DATASETS.items():
        path = os.path.join(_DS_DIR, fn)
        rows = [json.loads(x) for x in open(path, encoding="utf-8")] if os.path.exists(path) else []
        atk = sum(1 for r in rows if r.get("label") == 1)
        meta = dict(_DS_META.get(name, {}))
        meta.update({"line": line, "surface": surface, "total": len(rows), "attacks": atk, "benign": len(rows) - atk,
                     "samples": [{"label": r.get("label"), "text": (r.get("text") or "")[:300]}
                                 for r in rows[: max(1, min(samples, 8))]]})
        out[name] = meta
    return {"datasets": out}


@app.post("/v1/system-prompt/build")
def build_endpoint(req: BuildReq, _: None = Depends(_auth)) -> dict:
    hardened, canary = guard.build_system_prompt(req.base_prompt)
    logger.info("build canary=%s len=%d", canary, len(hardened))
    return {"hardened_system_prompt": hardened, "canary": canary}


@app.post("/v1/screen/input")
def screen_input_endpoint(req: InputReq, _: None = Depends(_auth)) -> dict:
    started = time.perf_counter()
    result = guard.screen_input(req.user_input, req.untrusted_context)
    _log("input", result, started)
    return {
        "allowed": result.allowed,
        "risk": result.risk,
        "reasons": result.reasons,
        "sanitized": result.sanitized,
        "refusal": None if result.allowed else guard.refusal,
        "would_block": result.would_block,
        "mode": guard.mode,
    }


@app.post("/v1/screen/output")
def screen_output_endpoint(req: OutputReq, _: None = Depends(_auth)) -> dict:
    started = time.perf_counter()
    result = guard.screen_output(req.model_output, req.canary, req.system_prompt or "")
    _log("output", result, started)
    return {
        "allowed": result.allowed,
        "risk": result.risk,
        "reasons": result.reasons,
        "text": result.sanitized,
        "would_block": result.would_block,
        "mode": guard.mode,
    }


_METRICS = {
    "req": {"input": 0, "output": 0},
    "blocked": {"input": 0, "output": 0},
    "would_block": 0,
    "lat_sum_ms": 0.0,
    "lat_count": 0,
    "lat_buckets": {1: 0, 5: 0, 25: 0, 50: 0, 100: 0},   # 累积 le 桶(ms)
}


def _log(stage: str, result, started: float) -> None:
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    # Prometheus 指标累积(进程内计数器,/metrics 暴露;不含任何正文)。
    with _METRICS_LOCK:
        _METRICS["req"][stage] = _METRICS["req"].get(stage, 0) + 1
        if not result.allowed:
            _METRICS["blocked"][stage] = _METRICS["blocked"].get(stage, 0) + 1
        if getattr(result, "would_block", False):
            _METRICS["would_block"] += 1
        _METRICS["lat_sum_ms"] += elapsed_ms
        _METRICS["lat_count"] += 1
        for b in (1, 5, 25, 50, 100):
            if elapsed_ms <= b:
                _METRICS["lat_buckets"][b] += 1
    # 不记录任何正文/凭证,只记判定元数据。
    logger.info(
        "screen stage=%s allowed=%s risk=%.3f reasons=%s ms=%.3f",
        stage,
        result.allowed,
        result.risk,
        ",".join(result.reasons) or "-",
        elapsed_ms,
    )


@app.get("/metrics")
def metrics():
    """Prometheus 文本格式指标(零依赖手写,可接 Prometheus/Grafana/告警)。"""
    from fastapi.responses import PlainTextResponse

    m = _METRICS
    md = guard.mode
    out = ["# TYPE promptsentinel_requests_total counter"]
    for stg, n in m["req"].items():
        out.append('promptsentinel_requests_total{stage="%s",mode="%s"} %d' % (stg, md, n))
    out.append("# TYPE promptsentinel_blocked_total counter")
    for stg, n in m["blocked"].items():
        out.append('promptsentinel_blocked_total{stage="%s",mode="%s"} %d' % (stg, md, n))
    out.append("# HELP promptsentinel_would_block_total 影子模式下本会拦截的累计(仅 mode=shadow 有意义)")
    out.append("# TYPE promptsentinel_would_block_total counter")
    out.append('promptsentinel_would_block_total{mode="%s"} %d' % (md, m["would_block"]))
    out.append("# TYPE promptsentinel_latency_ms histogram")
    for b in (1, 5, 25, 50, 100):
        out.append('promptsentinel_latency_ms_bucket{le="%d"} %d' % (b, m["lat_buckets"][b]))
    out.append('promptsentinel_latency_ms_bucket{le="+Inf"} %d' % m["lat_count"])
    out.append("promptsentinel_latency_ms_sum %.3f" % m["lat_sum_ms"])
    out.append("promptsentinel_latency_ms_count %d" % m["lat_count"])
    out.append("# TYPE promptsentinel_ml_available gauge")
    out.append("promptsentinel_ml_available %d" % (1 if guard.ml.available else 0))
    out.append('promptsentinel_mode{mode="%s"} 1' % guard.mode)
    return PlainTextResponse("\n".join(out) + "\n")
