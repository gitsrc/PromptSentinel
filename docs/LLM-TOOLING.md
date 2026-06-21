# PromptSentinel LLM 工具(开发 / 测试用)

PromptSentinel 自带一组**LLM 驱动的开发/测试工具**:连通性 ping、LLM 红队、实时端到端 demo。

> **重要边界**:本文所有 LLM 工具**仅用于开发 / 测试**,**不进入运行时检测路径**。默认运行时
> 检测由确定性规则承担(见 [ARCHITECTURE.md](./ARCHITECTURE.md)),零外部依赖、数据不出域。
> 唯一会在运行时调用大模型的是**可选、默认关闭**的 LLM-judge —— 它有破域红线,见
> [SECURITY-BOUNDARIES.md](./SECURITY-BOUNDARIES.md)。

事实锚点:`service/app/llm/env.py`(.llmenv 加载)、`service/app/llm/client.py`(客户端 + ping)、
`service/redteam/llm_redteam.py`(红队)、`service/app/e2e_demo.py`(确定性 e2e)。

---

## 一、`.llmenv` 用法

LLM 工具通过 `.llmenv`(`KEY=VALUE` 文本文件)读取模型端点。加载器从**当前工作目录向上逐级
查找** `.llmenv`(最多 8 层),也支持 `SENTINEL_LLMENV` 指定路径,或同名环境变量覆盖
(环境变量优先于文件)。

需要的键(`app/llm/env.py::LLMConfig`):

```ini
# .llmenv（不要提交到版本库;仅开发/测试工具读取,绝不写入日志)
LLM_PROVIDER=...
LLM_API_KEY=...
LLM_BASE_URL=...          # Anthropic Messages 兼容端点;默认仓库示例为 MiniMax 的 /anthropic
LLM_MODEL_NAME=...        # 如 MiniMax-M2.7-highspeed(注意:经 Anthropic 线缆格式的第三方端点)
```

四个键全部齐备时 `configured=True`;缺失或不完整时工具**优雅跳过**实时部分,不报错、不影响
确定性 benchmark。

客户端(`app/llm/client.py`)说明:
- 对 `POST {base_url}/v1/messages` 发请求,头 `x-api-key` + `anthropic-version`。
- 优先用 `httpx`,缺失时回退标准库 `urllib`,保证最小依赖下可跑。
- 目标可能是 **thinking 模型**:`max_tokens` 要留足空间给 thinking + text,否则可能 text 截断
  为空(`stop_reason=max_tokens`)——这不影响连通性判定。

---

## 二、连通性 ping

```bash
python -m app.llm.client --ping
```

- 行为:发一条 "Reply with the single word: pong" 探测,返回结构良好的 Messages 响应即视为
  连通(`ok` 看响应**结构**,不看 text 是否为空——thinking 模型可能截断 text)。
- 退出码:连通 `0`,失败 / `.llmenv` 未配置 `1`。
- 输出示例:`[ping] model=... ok=True stop=... reply='...'`。

---

## 三、LLM 驱动红队(≤ 40 轮)

```bash
python -m redteam.llm_redteam                 # 默认 6 轮、每轮 5 条
python -m redteam.llm_redteam --rounds 10     # 自定义轮数(硬上限 MAX_ROUNDS=40)
python -m redteam.llm_redteam --per-round 8
```

机制:让 `.llmenv` 配置的模型生成一批新颖的注入 / 越狱 / 套取提示词,逐条过
`SentinelGuard.screen_input`,记录哪些**绕过**了确定性层,写报告
`redteam/llm_redteam_report.json` 并给出候选规则建议。

- **轮数硬上限 40**(`MAX_ROUNDS`),`--rounds` 会被夹到 `[1, 40]`。
- 每轮一次模型调用,**消耗较大**,按需调整。
- 未配置 `.llmenv` 时**优雅跳过**(确定性 benchmark 不受影响)。
- 只接受模型返回的 JSON 字符串数组;解析失败(模型拒绝生成对抗内容)记为 `declined_rounds`,
  绝不把模型的拒绝 / 解释文本当成攻击污染报告。

**诚实边界**:这是「确定性层对 LLM 生成攻击的鲁棒性**探针**」,**不是**真实对抗能力证明。
一次真实运行的报告即为 `total=4, blocked=2, bypassed=2, block_rate=0.5`——存在直接绕过样本。
发现的绕过样本应转化为**新规则 / 启用 ML 层**,并始终以**架构层硬边界兜底**。若
`declined_rounds>0`,说明所配模型对对抗生成做了安全拒绝,应换用获授权的红队模型,或以静态
`redteam.corpus` benchmark 为准。

---

## 四、实时 / 确定性端到端 demo

### 确定性 e2e(不依赖任何大模型,可重复)

```bash
python -m app.e2e_demo
```

用一个「会泄露的假模型」(`mock_llm`)演示四道防线如何兜底:正常请求放行;直接注入被②拦;
改写复述泄露被④拦;间接注入被②拦;以及关键的「**②被绕过、模型逐字吐出系统提示词 → ③ canary
出口兜底**」。结尾打印边界声明:概率性防护可被语义改写绕过,越权 / 外泄仍须架构层硬边界兜底。

### 配套自检与 benchmark

```bash
SENTINEL_ALLOW_DEFAULT=1 python -m app.selfcheck          # 改完配置后跑:校验告警 + 拦截验证
python -m app.smoke_test                                  # 7 项契约冒烟(经 FastAPI TestClient)
SENTINEL_ALLOW_DEFAULT=1 python -m benchmark.run_benchmark # 在静态语料上度量 recall/fpr/延迟
```

这些都**不需要大模型**,纯确定性、可重复(真实指标见 [THREAT_MODEL.md](./THREAT_MODEL.md))。

---

## 五、再次强调:工具 vs 运行时

| 用途 | 是否调用大模型 | 是否在运行时检测路径 | 数据是否出域 |
|---|---|---|---|
| `--ping` / `llm_redteam` | 是(读 `.llmenv`) | **否**(仅开发/测试) | 取决于 `.llmenv` 端点(默认外部) |
| `e2e_demo` / `selfcheck` / `smoke_test` / benchmark | 否 | 否 | 否 |
| 默认运行时检测(①②③④确定性) | 否 | 是 | **否** |
| LLM-judge(可选,默认关闭) | 是 | 是(若开启) | 指向外部即**破域**,见 SECURITY-BOUNDARIES |

一句话:`.llmenv` 与上述 LLM 工具是**开发/测试脚手架**;生产运行时的安全基线是确定性的、本地的、
数据不出域的。
