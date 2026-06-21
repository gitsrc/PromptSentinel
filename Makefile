# PromptSentinel —— 常用任务。从仓库根运行,如 `make test`、`make bench`。
PY ?= python3

.DEFAULT_GOAL := help
.PHONY: help install test smoke selfcheck e2e bench redteam ping up down \
        eval-regex eval-hybrid eval-cost eval-pg2 benchmark-gate benchmark-perf \
        sdk-py-test sdk-js-test sdk-go-test sdk-java-test verify

help: ## 列出可用目标
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## 安装服务运行时依赖
	cd service && $(PY) -m pip install -r requirements.txt

test: ## 服务单元测试(pytest)
	cd service && $(PY) -m pytest -q

smoke: ## 7 项冒烟测试
	cd service && $(PY) -m app.smoke_test

selfcheck: ## 团队接入自检
	cd service && SENTINEL_ALLOW_DEFAULT=1 $(PY) -m app.selfcheck

e2e: ## 四道防线端到端演示(确定性)
	cd service && $(PY) -m app.e2e_demo

bench: ## 真实 benchmark → service/benchmark/results.json
	cd service && SENTINEL_ALLOW_DEFAULT=1 $(PY) -m benchmark.run_benchmark

redteam: ## LLM 驱动对抗红队(需 .llmenv;消耗较大)
	cd service && $(PY) -m redteam.llm_redteam

eval-regex: ## 公开数据集评测 · regex 零成本基线(deepset/gandalf/inthewild/pii)
	cd service && $(PY) -m benchmark.eval_dataset --dataset all --mode regex

eval-hybrid: ## 公开数据集评测 · hybrid(规则+ML 级联,需 requirements-ml + 首启下载模型)
	cd service && $(PY) -m benchmark.eval_dataset --dataset all --mode hybrid

eval-cost: ## regex vs ML vs hybrid 的效果 × 成本(延迟/内存)
	cd service && $(PY) -m benchmark.eval_ml_compare --gandalf 400 --itw 200

eval-pg2: ## 默认后端 Prompt Guard 2 的效果 × 成本(落盘 pg2_compare.json)
	cd service && $(PY) -m benchmark.eval_pg2

benchmark-gate: ## 回归门禁:公开集 regex 档召回/FPR 守下限(退化 exit 1,供 CI)
	cd service && $(PY) -m benchmark.gate

benchmark-perf: ## 性能压测:regex/hybrid 档吞吐与延迟分位(QPS/p50/p95/p99)
	cd service && $(PY) -m benchmark.perf --ml

ping: ## .llmenv 大模型连通性自检
	cd service && $(PY) -m app.llm.client --ping

up: ## docker compose 起全栈(127.0.0.1:18080,含 ML 镜像)
	docker compose up -d --build

down: ## docker compose 停全栈
	docker compose down

sdk-py-test: ## Python SDK 测试
	cd sdks/python && $(PY) -m pytest -q

sdk-js-test: ## JavaScript SDK 测试(node --test,离线)
	cd sdks/javascript && node --test

sdk-go-test: ## Go SDK 测试(离线)
	cd sdks/go && GOPROXY=off go test ./...

sdk-java-test: ## Java SDK 测试(需 JDK 17+ 与 Maven)
	cd sdks/java && mvn -q test

verify: test bench sdk-py-test sdk-js-test sdk-go-test ## 跑全部可在本机执行的验证
	@echo "VERIFY: service + benchmark + python/js/go SDK 全部通过(java 需 JDK 单独跑)"
