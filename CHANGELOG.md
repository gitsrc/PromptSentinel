# Changelog

All notable changes to PromptSentinel are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

## [1.0.0] - 2026-06-19

首个公开版本 —— 准生产级 RC 的提示词安全网关 **PromptSentinel**(内部可信服务可用,公网/合规场景仍需真实环境验证)。

### Added
- **Guard 服务**(`service/`):FastAPI 安检门,四道防线引擎 `SentinelGuard`
  (① 构建期加固 + canary;② 输入注入检测;③ canary 逃逸;④ 受保护标识符 + PII)。
  端点:`/health`、`/version`、`/v1/system-prompt/build`、`/v1/screen/input`、`/v1/screen/output`。
- **模块化扫描器**:确定性规则(始终在)+ 可选本地 ML 适配器(llm-guard)+ 可选 LLM-judge
  运行时扫描器(默认关闭,破域告警),均优雅降级。
- **生产化加固**:fail-closed 检测、可选服务级 bearer 鉴权、不记录正文/凭证的结构化日志、
  Python 3.9+ 兼容、容器化(非 root + healthcheck)。
- **四语言客户端 SDK**(`sdks/`):Python(14 测试)、JavaScript/ESM(21 测试)、Go(17 测试)、
  Java(Maven,Java 17+),统一表面 + `guard()` 三步 helper + 单元测试 + example。
- **红蓝对抗与 benchmark**:静态语料(37 样本)+ LLM 驱动对抗红队(`.llmenv`,≤40 轮);
  确定性层实测 recall 1.0 / FPR 0 / p50 0.045ms。
- **大模型工具**(`service/app/llm/`):`.llmenv` 加载器 + Anthropic-Messages 兼容客户端,
  连通性 `--ping`;真实端到端 demo(`examples/live-agent/`)。
- **文档**:`docs/`(ARCHITECTURE / THREAT_MODEL / INTEGRATION / SECURITY-BOUNDARIES / LLM-TOOLING)、
  服务 README 与团队接入指南、CI workflow、Makefile、Apache-2.0 许可。

### Security & boundaries
- 默认运行时检测路径不外联;LLM-judge 指向外部 API 会破坏「数据不出域」,默认关闭并在自检告警。
- 全程诚实标注:提示词层概率性、不能根治,需 ML/LLM 增强 + 架构层硬边界兜底。
