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
from .config import (
    enforce_config,
    is_trusted_proxy,
    load_config,
    parse_trusted_proxies,
    validate_config,
)
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
# 可信代理网段(逗号分隔 IP/CIDR;默认空)。仅当直连对端落在此集合内,才采信 X-Forwarded-For
# 首段作为限流客户端 IP;否则一律用直连 host —— 默认空即彻底杜绝伪造 XFF 绕过限流。
_TRUSTED_PROXIES = parse_trusted_proxies(os.environ.get("SENTINEL_TRUSTED_PROXIES", ""))
_METRICS_LOCK = _threading.Lock()
_BENCH_SEM = _threading.BoundedSemaphore(1)  # benchmark 端点串行,防并发 full 评测饿死线程池


def _client_ip(request) -> str:
    # 限流键取真实客户端 IP。X-Forwarded-For 可被任意客户端伪造,故仅当直连对端
    # (request.client.host)本身属可信代理集时才采信 XFF 首段;否则一律用直连 host。
    # _TRUSTED_PROXIES 默认空 ⇒ 永远只用直连 IP(安全默认,杜绝伪造 XFF 绕过限流)。
    direct = request.client.host if request.client else None
    if is_trusted_proxy(direct, _TRUSTED_PROXIES):
        xff = request.headers.get("x-forwarded-for")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first
    return direct or "?"


@app.middleware("http")
async def _guardrails(request, call_next):
    # 请求体硬上限,双层防护:
    #  1) 有 Content-Length 时,解析前先按头部拒绝(零成本,避免读入超大 body)。
    #  2) chunked / 无 Content-Length 的请求会绕过上面的头部检查 —— 实际读取后再按
    #     真实字节数判长度(len(raw) > 上限 → 413),杜绝 chunked 跳过 413。
    #     在中间件里读取会把 body 缓存到 request 上,下游处理器复用同一份,不会二次阻塞。
    clen = request.headers.get("content-length")
    if clen and clen.isdigit() and int(clen) > _MAX_BODY_BYTES:
        _record_rejected("oversize")
        return _JSONResponse({"detail": "payload too large"}, status_code=413)
    if request.method in ("POST", "PUT", "PATCH"):
        raw = await request.body()
        if len(raw) > _MAX_BODY_BYTES:
            _record_rejected("oversize")
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
        _record_rejected("ratelimit")
        return _JSONResponse({"detail": "rate limited"}, status_code=429)
    try:
        resp = await call_next(request)
    except Exception:
        # 下游处理器抛出未捕获异常 → 计 server_error,并继续向上抛(交给 FastAPI/Starlette 出 500)。
        _record_rejected("error")
        raise
    # 处理器自身返回 5xx(如 HTTPException(status_code>=500))也计入 server_error。
    if resp.status_code >= 500:
        _record_rejected("error")
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


@app.get("/ready")
def ready():
    """就绪探针(K8s readiness):配置要求 ML 但运行时不可用 → 503,避免静默降级被当成健康。

    与 /health(存活/能力概览,恒 200)分工不同:/ready 反映"是否满足配置承诺的能力"。
    当 use_ml_classifier=true 而 guard.ml.available=False(依赖缺失/权重下载失败)时,
    返回 503 {ready:false,reason:"ml_unavailable"},让编排器把本实例摘出流量。"""
    if CFG.scanners.get("use_ml_classifier") and not guard.ml.available:
        return _JSONResponse(
            {"ready": False, "reason": "ml_unavailable"}, status_code=503
        )
    return {"ready": True}


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


# 模块加载时间戳 —— 进程启动近似(uptime 基准)。time.time() 取墙钟,前端不依赖 Date.now。
_STARTED_AT = time.time()
# 暴露给 /metrics 的构建信息:版本固定,mode 取引擎运行模式(enforce/shadow)。
_BUILD_VERSION = __version__
_BUILD_MODE = guard.mode

_METRICS = {
    "req": {"input": 0, "output": 0},
    "blocked": {"input": 0, "output": 0},
    "would_block": 0,
    "lat_sum_ms": 0.0,
    "lat_count": 0,
    "lat_buckets": {1: 0, 5: 0, 25: 0, 50: 0, 100: 0},   # 累积 le 桶(ms)
    # 运维最关心「拦的都是什么」:按 reason 全名累计(result.reasons 里逐条;含 stage 前缀)。
    "by_reason": {},
    # 「哪一层在出力」:把 reason 映射到决策来源桶(regex/heuristic、ml、deobf、canary、protected_id、pii)。
    "by_scanner": {"regex": 0, "ml": 0, "deobf": 0, "canary": 0, "protected_id": 0, "pii": 0},
    # 中间件层拒绝计数:限流(429)/超大(413)/服务端错误(5xx)。
    "rejected": {"ratelimit": 0, "oversize": 0, "error": 0},
}


def _scanner_bucket(reason: str):
    """把单条 reason 全名映射到决策来源桶。无法归类(如 llm_judge)返回 None,不计入分桶。

    映射(reason 去掉 stage 前缀后看类型):
      *injection_heuristic(deobfuscated) → deobf(去混淆命中,先于 regex 判断,更具体)
      *injection_heuristic               → regex(确定性短语正则/启发式)
      *ml_classifier / *llm_guard        → ml(机器学习分类器)
      *system_prompt_leak(canary)        → canary(canary 逐字泄露)
      *protected_identifier(...)         → protected_id(受保护词表/标识符)
      *pii_fallback(...) / *pii(...)     → pii(输出 PII/密钥)
    """
    tail = reason.split(":", 1)[1] if ":" in reason else reason
    cat = tail.split("(", 1)[0]
    if "deobfuscated" in reason:
        return "deobf"
    if cat == "injection_heuristic":
        return "regex"
    if cat in ("ml_classifier", "llm_guard"):
        return "ml"
    if cat == "system_prompt_leak":
        return "canary"
    if cat == "protected_identifier":
        return "protected_id"
    if cat in ("pii_fallback", "pii"):
        return "pii"
    return None


def _record_rejected(reason: str) -> None:
    """中间件层拒绝累计(线程安全)。reason ∈ {ratelimit, oversize, error}。"""
    with _METRICS_LOCK:
        _METRICS["rejected"][reason] = _METRICS["rejected"].get(reason, 0) + 1


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
        # by_reason / by_scanner:仅在实际命中(被拦或 shadow 本会拦)时累计 —— reasons 即命中项。
        # reasons 非空就累计(放行但 reasons 为空的良性请求不污染分类计数)。
        for r in (result.reasons or []):
            _METRICS["by_reason"][r] = _METRICS["by_reason"].get(r, 0) + 1
            bucket = _scanner_bucket(r)
            if bucket:
                _METRICS["by_scanner"][bucket] = _METRICS["by_scanner"].get(bucket, 0) + 1
    # 不记录任何正文/凭证,只记判定元数据。
    logger.info(
        "screen stage=%s allowed=%s risk=%.3f reasons=%s ms=%.3f",
        stage,
        result.allowed,
        result.risk,
        ",".join(result.reasons) or "-",
        elapsed_ms,
    )


def _esc_label(v: str) -> str:
    """Prometheus 标签值转义:反斜杠、双引号、换行(reason 含括号无需转义,但可能含上述字符)。"""
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


@app.get("/metrics")
def metrics():
    """Prometheus 文本格式指标(零依赖手写,可接 Prometheus/Grafana/告警)。"""
    from fastapi.responses import PlainTextResponse

    md = guard.mode
    # 锁内快照,避免边读边写产生不一致(by_reason 字典在 _log 里并发增长)。
    with _METRICS_LOCK:
        m = copy.deepcopy(_METRICS)
    ml_ok = bool(guard.ml.available)
    # 配置要求 ML 但运行时不可用 → degraded(静默降级的显式告警面)。
    ml_degraded = 1 if (CFG.scanners.get("use_ml_classifier") and not ml_ok) else 0
    out = ["# TYPE promptsentinel_requests_total counter"]
    for stg, n in m["req"].items():
        out.append('promptsentinel_requests_total{stage="%s",mode="%s"} %d' % (stg, md, n))
    out.append("# TYPE promptsentinel_blocked_total counter")
    for stg, n in m["blocked"].items():
        out.append('promptsentinel_blocked_total{stage="%s",mode="%s"} %d' % (stg, md, n))
    out.append("# HELP promptsentinel_would_block_total 影子模式下本会拦截的累计(仅 mode=shadow 有意义)")
    out.append("# TYPE promptsentinel_would_block_total counter")
    out.append('promptsentinel_would_block_total{mode="%s"} %d' % (md, m["would_block"]))
    # 拦的都是什么:按 reason 全名累计(运维定位「在拦哪类攻击」)。
    out.append("# HELP promptsentinel_blocked_by_reason_total 按命中 reason 全名累计的命中数")
    out.append("# TYPE promptsentinel_blocked_by_reason_total counter")
    for reason in sorted(m["by_reason"]):
        out.append('promptsentinel_blocked_by_reason_total{reason="%s"} %d'
                    % (_esc_label(reason), m["by_reason"][reason]))
    # 哪一层在出力:按决策来源桶累计。
    out.append("# HELP promptsentinel_decision_by_scanner_total 按决策来源(扫描器层)累计的命中数")
    out.append("# TYPE promptsentinel_decision_by_scanner_total counter")
    for scanner in ("regex", "ml", "deobf", "canary", "protected_id", "pii"):
        out.append('promptsentinel_decision_by_scanner_total{scanner="%s"} %d'
                    % (scanner, m["by_scanner"].get(scanner, 0)))
    # 中间件层拒绝:限流/超大/服务端错误。
    out.append("# HELP promptsentinel_rejected_total 中间件层拒绝累计(ratelimit/oversize/error)")
    out.append("# TYPE promptsentinel_rejected_total counter")
    for reason in ("ratelimit", "oversize", "error"):
        out.append('promptsentinel_rejected_total{reason="%s"} %d'
                    % (reason, m["rejected"].get(reason, 0)))
    out.append("# TYPE promptsentinel_latency_ms histogram")
    for b in (1, 5, 25, 50, 100):
        out.append('promptsentinel_latency_ms_bucket{le="%d"} %d' % (b, m["lat_buckets"][b]))
    out.append('promptsentinel_latency_ms_bucket{le="+Inf"} %d' % m["lat_count"])
    out.append("promptsentinel_latency_ms_sum %.3f" % m["lat_sum_ms"])
    out.append("promptsentinel_latency_ms_count %d" % m["lat_count"])
    out.append("# TYPE promptsentinel_ml_available gauge")
    out.append("promptsentinel_ml_available %d" % (1 if ml_ok else 0))
    out.append("# HELP promptsentinel_ml_degraded 配置要求 ML 但运行时不可用(静默降级)= 1")
    out.append("# TYPE promptsentinel_ml_degraded gauge")
    out.append("promptsentinel_ml_degraded %d" % ml_degraded)
    out.append("# HELP promptsentinel_uptime_seconds 进程运行时长(秒,模块加载起算)")
    out.append("# TYPE promptsentinel_uptime_seconds gauge")
    out.append("promptsentinel_uptime_seconds %.1f" % (time.time() - _STARTED_AT))
    out.append("# HELP promptsentinel_build_info 构建信息(version/mode 作标签,值恒 1)")
    out.append("# TYPE promptsentinel_build_info gauge")
    out.append('promptsentinel_build_info{version="%s",mode="%s"} 1'
               % (_esc_label(_BUILD_VERSION), _esc_label(md)))
    out.append('promptsentinel_mode{mode="%s"} 1' % guard.mode)
    return PlainTextResponse("\n".join(out) + "\n")
