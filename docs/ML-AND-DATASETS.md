# ML 检测层 + 业界数据集评测(第一阶段:输入防护 ② + 系统提示词保护 ①③④)

> 目标:用业界知名评测数据集,把"提示词注入检测"与"系统提示词防泄露"提到业界基准水平,**成本可控**。
> 全部数字为本机 CPU 实测(2026-06-20),可一键复现:`make eval-regex` / `make eval-hybrid` / `make eval-cost`。

## 1. 数据集套件(按防线映射,一等公民)

统一适配器在 `service/benchmark/eval_dataset.py`(`DATASETS` 注册表),首次自动从 HuggingFace 下载并缓存到 `service/benchmark/datasets/*.jsonl`。

| 键 | 数据集(来源) | 防线 | 规模 | 标签 | 许可 |
|---|---|---|---|---|---|
| `gandalf` | Lakera/gandalf_ignore_instructions | **② 系统提示/密钥套取(主线)** | 1000(全量) | 全攻击 | 见上游 |
| `inthewild` | TrustAIRLab/in-the-wild-jailbreak-prompts | ② 真实越狱 | 300(抽样/1405) | 全攻击 | 见上游 |
| `pii` | ai4privacy/pii-masking-200k | ④ 输出 PII | 200(抽样/209k) | 全含 PII | 见上游 |
| `deepset` | deepset/prompt-injections | ② 通用注入(参照·非主线) | 116(test holdout) | 注入/良性 | 见上游 |

> 越狱类含有害内容,仅用于评测检测器,须遵守各自许可。

## 2. 检测层与三档模式

- **regex**:确定性短语/正则 + 受保护标识符(零依赖、亚毫秒、零成本)。
- **ml**:可选两种本地后端(`ml_classifier.backend`,均本地推理、数据不出域):
  - **`prompt_guard_onnx`(默认推荐)**:Llama Prompt Guard 2 22M ONNX —— **多语种**、~17ms、~22M;中文良性不误报。
  - **`deberta`**:ProtectAI deberta-v3-base —— 英文最高召回(主线 100%)但更重(~150ms / ~1.8GB / 184M)。
- **hybrid**(生产推荐):规则 + ML **级联** —— regex 命中即短路、跳过 ML(省成本);中文走 `lang_guard`(英文模型对中文易误报,交回中文规则)。

ML 为可选增强:`scanners.use_ml_classifier=true` + `pip install -r requirements-ml.txt`(transformers+torch,首启下载 ~370MB)。

## 3. 实测结果(recall / FPR)

| 数据集 | 防线 | regex | ml | **hybrid** | FPR |
|---|---|---|---|---|---|
| **gandalf(套取主线)** | ② | 78.0% | 97.4% | **98.1%** | n/a(全攻击) |
| in-the-wild 越狱 | ② | 69.7% | 89.3% | **92.0%** | n/a |
| ai4privacy PII | ④ 输出 | **41.5%** | —* | **41.5%** | 0% |
| deepset(参照) | ② | 23.3% | 13.3% | **26.7%** | 0%(regex) |

\* ML(注入分类器)不检测**输出 PII**;④ 输出 PII 靠确定性正则(凭证/IP/SSN/MAC/IMEI,41.5%)+ 可选 NER(use_llm_guard)。

> 注:`ml`/`hybrid` 列为**默认后端 Prompt Guard 2** 口径(来源 `benchmark/pg2_compare.json`、`eval_hybrid.json`,`make eval-hybrid` 复现);deberta 档(主线 100%、deepset 更高)对比见 §5。

要点:
- **主线(系统提示词套取)hybrid 98.1%**(PG2,regex 仅 78%);deberta 档可达 100% —— 第一阶段核心达标。
- 真实越狱 hybrid 92.0%(PG2 比 deberta 88.7% 更高)。
- FPR 在主线/中文为 0;deepset en/de 叠加 ML 约 +1pp。

## 4. 成本(实测,CPU)

| 项 | regex | ml · PG2(默认) | ml · deberta(可选) |
|---|---|---|---|
| 单条延迟 p50 | <0.1ms | ~25ms | ~150ms |
| 常驻内存 | ~0 | ~1.0GB | ~1.8GB |
| 权重大小 | 0 | ~22M(预装进镜像) | ~184M / 下载 ~370MB |

**级联省成本(实证)**:hybrid 在 gandalf 主线 **p50 仅 0.09ms** —— 因为 78% 攻击被 regex 短路、根本不调 ML;只有 regex 漏的才付 ML 延迟(PG2 ~25ms / deberta ~150ms)。

**量化结论(诚实负面结果)**:torch 动态量化令 deberta-v3 **精度崩塌(recall 1.0→0.01)且几乎不省时**,已弃用(`quantize` 默认 false);`optimum`/ONNX 依赖在本环境装不上。降本靠**级联 + lang_guard + 线程调优 + 分档**。

## 5. 成本分档(按预算选档)

| 档 | 配置 | 主线召回 | 成本 | 适用 |
|---|---|---|---|---|
| **档0 · regex-only** | 默认(ML off) | 78% | <0.1ms / 0 内存 / 零依赖 | 成本敏感、高并发、离线、低价值 |
| **档1 · hybrid(默认 PG2)** | `use_ml_classifier: true` | **98.1%**(PG2)/ 100%(deberta) | 级联下主线 p50 0.09ms;漏网才付 **~25ms**(PG2)或 ~150ms(deberta) | 高保障 + 多语种 |

### ML 后端对比(hybrid 口径,实测)
| 后端 | gandalf 主线 | in-the-wild | 中文 | 单条延迟 | 大小 | 备注 |
|---|---|---|---|---|---|---|
| **prompt_guard_onnx(默认)** | 98.1% | **92.0%** | 100%(regex) | **~25ms** | 22M | 多语种;中文良性不误报;ungated ONNX |
| deberta | **100%** | 88.7% | 100%(regex) | ~150ms | 184M | 英文最高;deepset 参照更高;中文需 lang_guard |

> 数字来源:`benchmark/pg2_compare.json`(PG2)、`benchmark/ml_compare.json`(deberta)。中文注入语义召回:两个 ML 都≈0(业界普遍缺口),中文靠 regex(in-house/corpus 中文 100%);如需中文语义层,可开 `use_llm_judge`(.llmenv,破域/慢)。

## 6. 系统提示词保护(目标二)

- **① 加固写法**(构建期,零成本):安全层声明 + 种 canary。
- **③ canary 逃逸**(确定性,零成本):输出含 canary = 逐字泄露,近 100%(in-house benchmark 100%、e2e 验证)。
- **④ 受保护标识符**(确定性,零成本):输出含 Action ID/schema 等 = 改写复述(in-house 输出泄露-标识符 100%)。
- **④ 凭证 / PII**(确定性,零成本):私钥/AWS/GitHub/Slack/Google key、JWT、IP/SSN/MAC/IMEI、email/卡号全覆盖 ——
  在 ai4privacy 上 26.5%→**41.5%**、良性输出 **FPR 0**。姓名/地址/电话等自然语言 PII 需 NER:开 `use_llm_guard`(llm-guard 的 Presidio Sensitive,可选档、成本另计)。
- **输入侧套取**(gandalf):regex 78% → hybrid **100%**。

> ③ canary 是构造性确定控制,数据集层面测不了(逐字子串匹配≈100%);它和架构层才是系统提示词不泄露的硬保障,② 只是概率性前置过滤。

## 7. 推荐生产配置(高保障档)

```yaml
scanners:
  injection_heuristic: true
  protected_identifier: true
  canary: true
  pii_output: true
  use_ml_classifier: true      # 开启业界基准 ML
  ml_cascade: true             # 级联省成本
ml_classifier:
  backend: "prompt_guard_onnx"  # 默认:多语种 22M ONNX(~17ms);英文最高召回可改 "deberta"
  threshold: 0.5
  # backend=deberta 时另有 model/lang_guard/quantize 项,见 sentinel.config.yaml 注释
```
配合 `pip install -r requirements-ml.txt`(PG2 档仅需 onnxruntime+transformers,无需 torch)。
④ 输出 PII 若需覆盖姓名/电话/地址,再加 `use_llm_guard: true`(llm-guard)。

### 容器内启用高保障档(默认 PG2)

docker-compose 的 guard 服务已默认 `WITH_ML: "true"`(Dockerfile build-arg)——预装 `onnxruntime`+`transformers` 并把 PG2 权重**预下载进镜像**,且挂载 `portal/guard.demo.yaml`(开 `use_ml_classifier`)。`docker compose up -d --build` 起来后,`/health` 返回 `ml_classifier: true` 即表示 PG2 生效;为 `false` 表示依赖缺失/下载失败已降级回规则(启动日志有 WARN)。真实接入若要零成本档:改挂 `service/sentinel.config.yaml` 并把 build-arg 设回 `WITH_ML=false`(轻量镜像、仅确定性规则)。

## 8. 复现

```bash
make eval-regex     # 零成本基线(4 个公开集)
make eval-hybrid    # 规则+ML 级联(需 requirements-ml)
make eval-cost      # regex vs ML vs hybrid 的效果 × 成本(延迟/内存)
```

## 9. 诚实边界

受控数据集指标 ≠ 真实对抗上限;语义改写/对抗后缀仍可能绕过。提示词层 + 检测层是**概率性**的,越权/数据外泄须由**架构层硬边界**(最小权限、只读/RLS、egress、HITL)兜底。deberta 提升 ②输入;④输出 PII 与中文召回仍有提升空间(需对应 ML/NER)。
