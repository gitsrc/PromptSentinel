# PromptSentinel · 真实端到端 demo agent

一个**真实**(非 mock)的端到端示例:业务 Agent 通过 PromptSentinel 安检门保护一次
真实大模型调用。它把标准三步接入流程跑通,使用:

- **真实的 PromptSentinel HTTP 服务**(本机 `uvicorn` 起的 `app.main:app`),以及
- **真实的大模型**:`.llmenv` 里配置的 MiniMax(Anthropic-Messages 兼容端点),
  通过 service 的 `app.llm.client.LLMClient` 调用。

没有任何硬编码的模型回答 —— 终端里看到的模型输出都是当次真实请求返回的。

## 链路(每条请求都走这三步)

```
① 构建期(部署一次)  POST /v1/system-prompt/build
                     -> hardened_system_prompt + canary(把 canary 存好)
② 请求时             POST /v1/screen/input(user_input, untrusted_context?)
                     allowed=false -> 直接返回 refusal,绝不调用模型
                     allowed=true  -> 用 hardened_system_prompt 调真实大模型
③ 返回前             POST /v1/screen/output(model_output, canary)
                     -> 返回 result.text(放行原文,或被兜底替换的拒绝话术)
```

## 前置步骤(必须按顺序)

### 1. 起 PromptSentinel 服务(另开一个终端)

```bash
cd /home/corerman/ICODE/GitSrc/PromptSentinel/prompt-sentinel/service
pip install -r requirements.txt                       # 首次
uvicorn app.main:app --host 0.0.0.0 --port 8000
# 默认 sentinel.config.yaml 的 team.name 是示例值 "wind-ops",
# 若启动报告示例告警,可加 SENTINEL_ALLOW_DEFAULT=1。
```

验证服务可达:

```bash
curl http://localhost:8000/health
# -> {"status":"ok","team":"wind-ops","agent":"...","llm_guard":false,"llm_judge":false,"protected_terms":6}
```

> 可选鉴权:若 `sentinel.config.yaml` 的 `server.auth_token` 非空,则所有 `/v1` 请求
> 需带 `Authorization: Bearer <token>`,运行本脚本时加 `--token <token>`。默认为空=不校验。

### 2. 配置大模型(.llmenv)

本仓库已在 `/home/corerman/ICODE/GitSrc/PromptSentinel/.llmenv` 提供 MiniMax 配置:

```
LLM_PROVIDER=Anthropic_compatible
LLM_BASE_URL=https://api.minimaxi.com/anthropic
LLM_API_KEY=<your key>
LLM_MODEL_NAME=MiniMax-M2.7-highspeed
```

`agent.py` 默认显式指向该文件(设置 `SENTINEL_LLMENV`)。也可:
- 用环境变量 `SENTINEL_LLMENV=/path/to/.llmenv` 覆盖文件位置,或
- 直接导出 `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL_NAME`(环境变量优先级最高)。

### 3. 跑本脚本

```bash
python /home/corerman/ICODE/GitSrc/PromptSentinel/prompt-sentinel/examples/live-agent/agent.py
```

可选参数:

| 参数 | 默认 | 说明 |
|---|---|---|
| `--base-url` | `http://localhost:8000` | PromptSentinel 服务地址 |
| `--token`    | 无 | 仅当服务端配置了 `server.auth_token` 时需要 |
| `--max-tokens` | `2048` | 传给大模型。**MiniMax 是 thinking 模型**,token 太少会只产 thinking、text 为空,故需 ≥2048 |

脚本无需 `pip install`:它在运行时把
`../../sdks/python`(`promptsentinel` 包)与 `../../service`(为复用 `LLMClient`)
加入 `sys.path`。也可改用 `pip install -e ../../sdks/python`。

## 三个场景(都是真实调用)

1. **正常请求** —— 输入通过 ②,真实模型返回正常回答,输出通过 ③,原文返回。
2. **直接提示注入** —— `screen_input` 在 ② 拦下(`injection_heuristic`,risk≈0.9),
   直接返回 refusal,**模型从不被调用**。
3. **诱导泄露(出口兜底)** —— 输入本身不含受保护词,故通过 ② 并真实调模型;
   模型在回答里自然吐出受保护词 `schema`,被 ③④ 的确定性出口检测
   (`output:protected_identifier(term:schema)`,risk≈0.9)拦下,兜底替换为拒绝话术。

每一步都打印判定(allowed / risk / reasons)与耗时(ms)。

## 预期输出(示意,模型文本每次不同)

```
[健康检查] team=wind-ops ... protected_terms=6 llm_guard=False llm_judge=False
[大模型 ] model=MiniMax-M2.7-highspeed base_url=https://api.minimaxi.com/anthropic
[连通探测] ok=True stop=end_turn reply='pong'

[① build] 完成 (5.0 ms)  canary='PSENT-CANARY-xxxxxxxx'  hardened_len=513

场景 1:
[② screen_input ] allowed=True  risk=0.00 reasons=['-']
[   model call  ] 真实模型已返回 N chars (~4 s)
[③ screen_output] allowed=True  risk=0.00 reasons=['-']
>>> 最终返回给用户的文本: <真实模型回答>

场景 2:
[② screen_input ] allowed=False risk=0.90 reasons=['input:injection_heuristic']
   -> 已拦截,不调用模型,返回 refusal。

场景 3:
[② screen_input ] allowed=True  risk=0.00 reasons=['-']
[   model call  ] 真实模型已返回 N chars (含 "Schema")
[③ screen_output] allowed=False risk=0.90 reasons=['output:protected_identifier(term:schema)']
   -> 输出命中检测,已被兜底替换为拒绝话术。
```

> 注:`protected_terms` 与触发的具体词取决于 `service/sentinel.config.yaml`。
> 默认配置含 `A01..A05` 与 `schema`,故场景 3 用 `schema` 触发出口检测。
> 若你改了配置删掉 `schema`,场景 3 的输出可能放行 —— 这是真实行为,不是脚本造假。

## 故障与降级(脚本会友好处理,不伪造结果)

- **服务连不上**:打印起服务的命令并退出(exit 1)。
- **服务要鉴权(401)**:提示用 `--token` 传入(exit 2)。
- **`.llmenv` 未配 / 大模型探测失败**:打印原因并退出(exit 1),不会编造模型回答。
- **localhost 走了 HTTP 代理**:若本机设了 `http_proxy`/`https_proxy`,请把 localhost
  排除,例如运行前 `export no_proxy=localhost,127.0.0.1`,否则连不上本地服务。

## 边界声明(诚实标注)

- 本 demo 演示的是**纵深防御中的「提示词层 + 检测层」**。它是**概率性的、可被绕过的**:
  场景里的拦截是当次真实判定,**不代表**在任意对抗输入下都能拦住。
- 真正的硬边界 —— 最小权限、只读 / RLS、egress 管控、高危动作 HITL —— 必须由平台/架构层
  实现,**不能只靠本服务**。
- 输出侧的 canary 逃逸与受保护标识符检测是**确定性**的(逐字/包含匹配),是安全基线主力;
  注入启发式与可选的 ML / LLM-judge 增强是概率性的。
- 模型由第三方(MiniMax,经 Anthropic 线缆格式)提供,回答内容不受本 demo 控制;脚本只
  负责接入与安检,不对模型回答质量负责。
```
