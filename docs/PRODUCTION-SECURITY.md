# 生产级安全部署 Checklist

> PromptSentinel 是大模型前的提示词安检门。本文是把它**安全地部署到生产**的清单。
> 原则:纵深防御、fail-closed、数据不出域、最小权限。

## 1. 部署架构

```
用户/Agent ──TLS──▶ 网关(限流/WAF/TLS) ──▶ Guard 安检门(内网) ──▶ 你的 LLM 应用
                                              │ 数据不出域:本地推理
```
- **Guard 不对外暴露**:docker-compose 中 guard 仅 `expose`(容器内网),不绑宿主机端口。
- **门户**(若用)仅监听 `127.0.0.1`,远程经 SSH 转发。

## 2. 安全 Checklist(上线前逐项确认)

| 项 | 措施 | 状态 |
|---|---|---|
| **鉴权** | `server.auth_token` 必填,所有 `/v1` 端点需 `Bearer` | ⬜ 生产必填 |
| **速率限制** | 内置 240/min/IP(GC + 键上限 + 真实 IP/XFF);**仅单 worker 有效**,多副本/多 worker 必须下沉网关/Redis | ✅ 单机兜底 + ⬜ 网关(多副本必须) |
| **TLS** | 网关层终止 TLS | ⬜ 网关 |
| **网络隔离** | guard 不对外、只内网可达 | ✅ compose 默认 |
| **资源保护** | 输入 20000 字符上限(防 ReDoS/OOM/成本);容器 `mem_limit:2g`/`cpus:2` | ✅ 引擎 + ✅ compose limits |
| **可观测性** | Prometheus `/metrics`(请求/拦截/would_block/延迟直方图/ml/mode) | ✅ 可接 Grafana/告警 |
| **性能基线** | regex p99<0.4ms·单线程万级 QPS;hybrid p99 34ms·230 QPS/worker | ✅ 实测 |
| **fail-closed** | 引擎异常 → 拦截 + 拒绝话术,绝不静默放行 | ✅ 内置 |
| **数据不出域** | 全本地推理;`use_llm_judge` 默认关(开且指外部会破域,selfcheck 告警) | ✅ |
| **安全响应头** | `X-Content-Type-Options/X-Frame-Options/Referrer-Policy` | ✅ middleware |
| **不记录正文** | 日志/遥测只记 reasons/risk/耗时,绝不记 prompt/response | ✅ |
| **配置自检** | `make selfcheck` 通过(团队名/受保护项/破域告警) | ⬜ 部署前跑 |
| **回归门禁** | `make benchmark-gate` 通过(召回/FPR 不退化) | ✅ CI + ⬜ 发布前 |

## 3. 安全防护能力矩阵

| 防线 | 能力 | 实测 |
|---|---|---|
| ① 构建期加固 | 安全层声明 + canary 哨兵 | — |
| ② 输入注入 | 中英文注入/越狱/套取 regex + 业界 ML(PG2)+ **去混淆归一化** | 主线 hybrid 98%、中文 96.7% |
| ②对抗鲁棒性 | leetspeak/字符间隔/base64 **归一化复查** | leetspeak 0→58%、spaced 0→32%、base64 100% |
| ③ 输出 canary | 逐字泄露检测 | ≈100% 构造性 |
| ④ 输出标识符/PII | 受保护标识符 + 凭证/PII 正则 | 标识符 100%、PII 41.5% |
| 资源 | 输入长度上限 + 限流 | 30KB 输入不崩溃 |

## 4. 高保障档 vs 零成本档

- **零成本档**(默认):仅确定性规则,主线 78%、亚毫秒、零依赖。成本敏感/高并发。
- **高保障档**:`use_ml_classifier: true`(默认 PG2,容器已预装权重),主线 98%、~25ms。
  - 容器启用:`WITH_ML=true`(compose 已配)。`/health` 的 `ml_classifier:true` 确认生效。

## 5. 已知局限(诚实,生产前须知)

- **对抗鲁棒性**:归一化把 leetspeak/间隔从 0% 拉到 58%/32%,但**未达 100%**(对抗本质难);Unicode 同形字、嵌套编码仍可绕过。建议叠加输入归一化网关 + 人审高风险。
- **中文 ML 缺口**:中文注入靠 regex(96.7%),ML 对中文弱;随新表达演进需持续补(有 benchmark + 门禁守护)。
- **输出 PII**:正则 41.5%,姓名/地址需开 `use_llm_guard`(NER)。
- **抽样波动**:页面默认抽样,决策用 `full=true` 或看置信区间(详见 BENCHMARK-METHODOLOGY)。
- **检测是概率性的**:提示词层 + 检测层会被绕过;越权/数据外泄须由**架构层硬边界**(最小权限/只读 RLS/egress 控制/HITL)兜底。

## 6. 上线流程

```bash
make selfcheck        # 配置自检(团队名/受保护项/破域告警)
make benchmark-gate   # 回归门禁(召回/FPR 不退化)
make test smoke       # 单测 + 冒烟
docker compose up -d --build   # 起全栈(127.0.0.1:18080)
curl .../health       # 确认 ml_classifier/团队/扫描器状态
```
