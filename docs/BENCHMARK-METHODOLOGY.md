# Benchmark 方法学(生产级评估)

> 目标:可信、可复现、威胁模型对齐、能暴露真问题的提示词安全评测。
> 所有指标由**处理真实 `/v1/screen` 请求的同一 guard 实例**逐条现算(同源,非预录)。

## 1. 威胁模型(决定选什么数据集)

PromptSentinel 防的是 **提示词注入 / 系统提示词套取 / 越权**,**不是**内容安全 / 毒性 / 价值观。
选数据集的第一原则是**威胁模型对齐**,而非"越权威越好"——我们据此**剔除**过:
- JailbreakBench / AdvBench(诱导有害内容生成 = 内容安全,非注入)
- thu-coai 的 Prompt_Leaking(实为良性安全咨询,标签错配)、Role_Play(内容安全)

## 2. 数据集清单(9 集,全威胁模型对齐)

| 数据集 | 防线 | 来源 | 用途 |
|---|---|---|---|
| gandalf | ② 套取主线 | Lakera(MIT,arxiv:2501.07927) | 系统提示词套取 |
| in-the-wild | ② 越狱 | CISPA(CCS 2024,2308.03825) | 真实野外越狱 |
| deepset | ② 通用注入参照 | deepset(Apache) | 通用注入 + 良性 |
| safe-guard | ② 注入(含良性) | xTRam1(2402.13064) | 注入 + 1410 良性测 FPR |
| chinese_inject | ② 中文劫持 | 清华 thu-coai(精筛 Goal_Hijacking) | 中文目标劫持 |
| adversarial | ⑤ 对抗鲁棒性 | 本地构造 | leetspeak/间隔/base64/GCG 后缀 |
| business_benign | ② 业务良性 | 本地构造 | 中英文业务请求,测真实 FPR |
| pii | ④ 输出 PII | ai4privacy | 输出泄漏 |

## 3. 指标(完整)

每个数据集报告:**recall / precision / F1 / FPR + Wilson 95% 置信区间 + p50 延迟 + 混淆矩阵**。
- recall=攻击拦截率(↑好);precision=拦截中真攻击占比;F1=综合;FPR=良性误拦(↓好,仅含良性的集可测)。
- **置信区间**标注抽样不确定性(n 越大越窄)。
- regex 档(确定性基线)与 current 档(含 ML)同源对比。

## 4. 防过拟合 / 可复现

- **train/test holdout**:规则只在 train split 挖掘,test split(未参与)验证(safe-guard / 中文劫持增强均如此验证)。
- **seed 固定**:抽样确定、同 n 可复现。
- **全量选项**:`/v1/benchmark?full=true` 跑全集(非抽样),消除抽样波动。

## 5. CI 回归门禁

`make benchmark-gate`(= `python -m benchmark.gate`):regex 档**全量**跑,召回低于下限 / FPR 高于上限则 **exit 1**。已接入 `.github/workflows/ci.yml`,改规则导致退化即红。阈值见 `service/benchmark/gate.py` 的 `GATES`。

## 6. 私有集导入(生产必做)

公开集会被模型/检测器训练污染、且攻击者可针对性绕过。生产应导入**自己的**:
1. **真实流量良性集** → 替换 `business_benign.jsonl`(测你线上的真实 FPR)。
2. **私有红队集** → 新增 `benchmark/datasets/<name>.jsonl`(`{"text","label","split"}` 每行一条),并在 `service/app/main.py` 的 `_DATASETS` 注册一行。重建镜像即纳入评测/门禁。

## 7. 持续更新

攻击手法在演进,数据集需定期更新:
- 公开集:`make eval-regex` 触发 `_ensure` 重新拉取(或删缓存 jsonl 后重拉)。
- 每次评测结果持久化在 `bench_data` 卷(`/api/benchmark/history` 可查),带 `run_id`/时间戳,形成趋势。
- 建议季度更新公开集 + 持续补充私有红队样本(尤其 benchmark 暴露的漏报)。

## 8. 诚实局限(已知,生产前须知)

- **对抗鲁棒性**:输入归一化已把 leetspeak / 字符间隔(Tab/全角/零宽/双空格)/ base64 / Unicode 同形字从"完全绕过"拉到可观召回(leetspeak ~58%),且 untrusted 通道同样覆盖;但**未达 100%**——嵌套编码、真实 GCG 优化串仍可能绕过,需对抗训练持续补。
- **train/test 纪律**:确定性规则部分挖掘自 gandalf/chinese 等公开攻击模式,其"挖掘集"与"评估集"有重叠,**全集 recall 偏乐观**;泛化下界看有真 holdout 的 deepset-test(regex recall 仅 ~0.23)。生产应以**私有 holdout** 为准(见 §6)。
- **纯攻击集指标**:gandalf/inthewild/pii/chinese/adversarial 无良性样本,**precision/F1 不可测**(代码已置 None),只看 recall + CI;精确率/FPR 须在含良性的 safe-guard / business_benign 上量。
- **中文 ML 缺口**:中文注入靠 regex(ML 对中文弱),覆盖随表达演进需持续补。
- **抽样波动**:页面默认抽样有 ±2~6pp 波动,决策请用 `full=true` 或看置信区间。
- **本地构造集**:adversarial 变体与自家归一化同源(base64 偏高)、business_benign 仅 138 条手写——属**指示性、非权威**,真实 FPR/对抗须用接入方流量 + 第三方对抗基准(garak/PINT)复测。
- **输出 PII(④)**:高精度正则档 **~41.5%**(覆盖邮箱/卡号/密钥/GPS/电话/IBAN/日期等结构化项,零误报);姓名/地址等自然语言 PII 需 NER —— 可选 **NER 档**(构建 `WITH_LLM_GUARD=true` + 配置 `use_llm_guard:true`,Presidio)可达 ~80%,代价镜像 +1~2GB。指标为"文本含 PII 的检出率"。

## 9. 复现

```bash
make benchmark-gate     # 回归门禁(全量 regex 档)
# 门户 Benchmark 页 → "运行真实评测"(异步任务+进度+持久化历史+完整指标)
# "查看数据集" 弹窗 → 每个集的来源/许可/论文/真实样本
```
