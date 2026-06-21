# PromptSentinel 服务镜像。确定性规则零 ML 依赖,镜像小、启动快、可离线。
FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SENTINEL_CONFIG=/app/sentinel.config.yaml \
    HF_HOME=/app/.hfcache

WORKDIR /app

# WITH_ML=true:预装 PG2 档 ML 依赖(onnxruntime+transformers,无需 torch)并把
# Llama Prompt Guard 2 22M 权重**预下载进镜像** —— 高保障档容器开箱即用、首请求不再联网。
# 默认 false → 零成本轻量镜像(仅确定性规则)。
ARG WITH_ML=false
ARG WITH_LLM_GUARD=false

COPY requirements.txt requirements-ml.txt requirements-pg2.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN if [ "$WITH_ML" = "true" ]; then \
      pip install --no-cache-dir -r requirements-pg2.txt && \
      python -c "import os; from huggingface_hub import snapshot_download; snapshot_download('gravitee-io/Llama-Prompt-Guard-2-22M-onnx', revision=(os.environ.get('PG2_REVISION') or None))" && \
      python -c "import glob,sys; sys.exit(0 if glob.glob('/app/.hfcache/**/*.onnx',recursive=True) else 1)"; \
    fi
# 可选 NER 档(WITH_LLM_GUARD=true):装 llm-guard(Presidio NER),输出 PII 覆盖姓名/地址(~80%)。镜像 +1~2GB。
# 默认 false → 走高精度正则档(53.5%、零依赖、亚毫秒);需高 PII 召回时构建本档并设 use_llm_guard:true。
RUN if [ "$WITH_LLM_GUARD" = "true" ]; then \
      pip install --no-cache-dir "llm-guard>=0.3.14" && \
      python -m spacy download en_core_web_lg && \
      python -c "from llm_guard.output_scanners import Sensitive; Sensitive(); print('llm-guard NER ready')"; \
    fi

COPY app ./app
COPY benchmark/datasets ./benchmark/datasets
COPY sentinel.config.yaml ./sentinel.config.yaml

# 非 root 运行(含 HF 权重缓存目录)。
RUN useradd --create-home --uid 10001 sentinel \
    && mkdir -p /app/.hfcache \
    && chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if 'ok' in urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2).read().decode() else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
