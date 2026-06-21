# PromptSentinel Web Portal(前端示例 · 前后端工程)

一个**淡色科技感**的单页门户,围绕专业 + 方法论角度展示 PromptSentinel:

| 板块 | 内容 |
|---|---|
| **项目介绍** | 四道防线、三层纵深防御方法论、OWASP LLM Top 10 对齐、诚实边界 |
| **实时 Demo** | 构建期加固 + canary;输入检测;输出检测(canary/标识符/PII);四道防线随判定点亮 |
| **接入流程** | 三步流程图 + 五步上手 + 四语言 `guard()` 代码 + curl |
| **Benchmark** | 一键在**运行中的 Guard** 上回放红蓝对抗语料,现场算 recall/FPR/混淆矩阵/分类别/延迟 |
| **监控遥测** | 黄金信号面板:请求数/拦截率/延迟分位、放行vs拦截甜甜圈、reason 分类、判定时间线、近期事件 |

## 架构(前后端 example)

```
浏览器(纯 HTML/CSS/原生 JS,零构建)
   │  只调本 BFF 的 /api/*
   ▼
Web Portal BFF(FastAPI, app.py)
   │  服务端代理 + 遥测埋点(不记正文)
   ▼
PromptSentinel Guard 服务(/v1/*)
```

这是**推荐的服务端集成模式**的活样例:Guard 地址与凭证留在后端,浏览器不直连 Guard、无 CORS 暴露。
前端**零依赖、无构建步骤**(不需要 npm/webpack/vite),图表用手写 SVG —— 最大化可部署性。

## 运行

### 全栈(推荐,从仓库根)
```bash
cd prompt-sentinel
docker compose up -d --build
# 门户  http://localhost:18080
# Guard http://localhost:18000
```

### 本地开发(不走容器)
```bash
# 1) 先起 Guard(另一个终端)
cd service && uvicorn app.main:app --port 8000
# 2) 起门户 BFF
cd portal && pip install -r requirements.txt
GUARD_URL=http://localhost:8000 uvicorn app:app --port 8080
# 打开 http://localhost:8080
```

## API(BFF)

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 门户 + Guard 健康/版本 |
| GET | `/api/corpus` | 内置语料(供 Demo 快捷示例) |
| POST | `/api/build` | 代理:构建加固提示词 + canary |
| POST | `/api/screen/input` | 代理输入检测 + 遥测埋点 |
| POST | `/api/screen/output` | 代理输出检测 + 遥测埋点 |
| GET | `/api/benchmark` | 实时回放语料算指标 |
| POST | `/api/load` | 生成合成负载(populate 遥测) |
| GET | `/api/telemetry` | 聚合遥测(黄金信号) |
| POST | `/api/telemetry/reset` | 清空遥测 |

## 边界与说明

- 遥测为**进程内内存态**(重启即清),仅作示例;生产应导出到 **Prometheus / OpenTelemetry**,
  并对 **FPR(误报率)** 设告警(过度拦截往往比漏拦更常见)。
- BFF **绝不记录** prompt/response 正文与凭证,只记判定元数据(stage/allowed/risk/reasons/ms)。
- 与整个项目一致的诚实边界:提示词层 + 检测层是概率性的、可被绕过,不替代架构硬边界。
