/* ============================================================================
   监控遥测 · 可观测控制台
   数据源 = BFF GET /api/telemetry(服务端拉 Guard /metrics 解析聚合)。
   契约见后端;全程仅判定元数据(reason/risk/scanner/延迟/计数),绝不含任何
   prompt/response 正文。zero-dep,沿用 PS.view / PS.$ / charts.js / CSS 变量。
   面板:① 总览卡片排 ② 拦截原因 Top-N ③ 决策来源分布 ④ 四道防线分解
        ⑤ 延迟分布直方图 ⑥ 影子模式看板 ⑦ 错误/限流 ⑧ 成本分析
   顶部:自动刷新(5s,可暂停)+「进程内累积、不含任何正文」标注。
   ========================================================================== */
const TELE_CSS = `
#view-telemetry .tele-toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:16px}
#view-telemetry .tele-toolbar .tt-left{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
#view-telemetry .tele-toolbar .tt-right{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
#view-telemetry .live-dot{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);font-weight:600}
#view-telemetry .live-dot i{width:8px;height:8px;border-radius:999px;background:var(--ok);box-shadow:0 0 0 0 rgba(15,157,107,.5);animation:telePulse 2s infinite}
#view-telemetry .live-dot.paused i{background:var(--faint);animation:none}
@keyframes telePulse{0%{box-shadow:0 0 0 0 rgba(15,157,107,.45)}70%{box-shadow:0 0 0 6px rgba(15,157,107,0)}100%{box-shadow:0 0 0 0 rgba(15,157,107,0)}}
#view-telemetry .priv-tag{font-size:11.5px;color:var(--muted);font-family:var(--mono)}
#view-telemetry .priv-tag b{color:var(--accent-ink)}
#view-telemetry .meta-pills{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:14px}
#view-telemetry .pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:999px;font-size:11.5px;font-weight:700;border:1px solid var(--line-2);background:var(--surface);color:var(--ink-2)}
#view-telemetry .pill.ok{background:var(--accent-soft);color:var(--accent-ink);border-color:transparent}
#view-telemetry .pill.warn{background:#fdf3e0;color:var(--warn);border-color:transparent}
#view-telemetry .pill.block{background:#fde8ec;color:var(--block);border-color:transparent}
#view-telemetry .pill.purple{background:#efeafb;color:var(--purple);border-color:transparent}
#view-telemetry .pill i.dotmini{width:7px;height:7px;border-radius:999px;background:currentColor;display:inline-block}
/* 横条形 */
.bars{display:flex;flex-direction:column;gap:7px}
.bar-row{display:grid;grid-template-columns:minmax(120px,1.4fr) 1fr 42px 46px;gap:9px;align-items:center}
.bar-lbl{color:var(--ink-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-track{height:13px;background:var(--surface-3);border-radius:999px;overflow:hidden}
.bar-fill{display:block;height:100%;border-radius:999px;transition:width .6s ease;opacity:.92}
.bar-num{text-align:right;font-weight:800;color:var(--ink)}
.bar-pct{text-align:right}
/* 直方图 */
.hg{display:grid;grid-template-columns:repeat(var(--hg-n,6),1fr);gap:8px;align-items:end;height:150px;padding:6px 0 0}
.hg-col{display:flex;flex-direction:column;align-items:center;gap:3px;height:100%;justify-content:flex-end}
.hg-bar-wrap{flex:1;width:100%;display:flex;align-items:flex-end;justify-content:center;min-height:0}
.hg-bar{display:block;width:72%;min-height:2px;border-radius:5px 5px 0 0;background:linear-gradient(180deg,var(--accent),var(--accent-ink));transition:height .6s ease}
.hg-x{line-height:1}.hg-c{line-height:1;color:var(--ink-2)}
/* 防线小卡 */
.stage-cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.stage-card{position:relative;border:1px solid var(--line);border-radius:var(--r);padding:13px 15px;background:linear-gradient(180deg,#fff,var(--surface-2));overflow:hidden}
.stage-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px}
.stage-card.s-build::before{background:var(--purple)}.stage-card.s-input::before{background:var(--accent)}.stage-card.s-output::before{background:var(--ok)}
.stage-card .sc-no{font-size:11px;font-weight:800;color:var(--faint);font-family:var(--mono)}
.stage-card .sc-name{font-size:14px;font-weight:800;color:var(--ink);margin-top:1px}
.stage-card .sc-desc{font-size:11px;color:var(--muted);margin-top:2px;margin-bottom:9px;min-height:28px}
.stage-card .sc-stat{display:flex;justify-content:space-between;align-items:baseline;gap:8px}
.stage-card .sc-req{font-size:21px;font-weight:800;font-family:var(--mono);color:var(--ink);letter-spacing:-.02em}
.stage-card .sc-req small{font-size:11px;color:var(--muted);font-weight:600}
.stage-card .sc-rate{font-size:12px;font-family:var(--mono);font-weight:700}
.stage-card .sc-meter{height:6px;background:var(--surface-3);border-radius:999px;overflow:hidden;margin-top:8px}
.stage-card .sc-meter>span{display:block;height:100%;border-radius:999px}
/* 错误卡 */
.err-cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.err-card{border:1px solid var(--line);border-radius:var(--r);padding:13px 15px;background:var(--surface);text-align:center}
.err-card .ec-v{font-size:24px;font-weight:800;font-family:var(--mono);color:var(--ink);letter-spacing:-.02em}
.err-card.hot .ec-v{color:var(--block)}
.err-card .ec-l{font-size:11.5px;color:var(--muted);font-weight:600;margin-top:3px}
.err-card .ec-code{font-size:10px;color:var(--faint);font-family:var(--mono);margin-top:2px}
/* 影子卡 */
#view-telemetry .shadow-box{background:#f6f2fe;border:1px solid #e0d6f7;border-radius:var(--r);padding:14px 16px}
#view-telemetry .shadow-box .sb-head{display:flex;align-items:center;gap:9px;margin-bottom:9px}
#view-telemetry .shadow-box .sb-big{font-size:30px;font-weight:800;font-family:var(--mono);color:var(--purple);letter-spacing:-.02em;line-height:1}
#view-telemetry .shadow-box .sb-cap{font-size:12px;color:var(--ink-2)}
#view-telemetry .shadow-box .sb-why{font-size:12.5px;color:var(--ink-2);line-height:1.6;margin-top:4px}
#view-telemetry .shadow-box .sb-why b{color:var(--purple)}
#view-telemetry .degraded{background:#fde8ec;border:1px solid #f5c6cf;border-radius:var(--r);padding:18px;text-align:center;color:var(--block);font-size:14px;font-weight:600}
#view-telemetry .degraded .dg-sub{font-size:12px;color:var(--muted);font-weight:500;margin-top:6px;font-family:var(--mono);word-break:break-all}
/* 成本 */
#tele-cost-host .cost-cards{display:grid;grid-template-columns:1fr 1fr;gap:14px}
#tele-cost-host .cost-card{position:relative;border:1px solid var(--line);border-radius:var(--r);padding:15px 17px;background:linear-gradient(180deg,#fff,var(--surface-2));overflow:hidden}
#tele-cost-host .cost-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;opacity:.85}
#tele-cost-host .cost-card.ok::before{background:var(--ok)}
#tele-cost-host .cost-card.purple::before{background:var(--purple)}
#tele-cost-host .cost-tier{font-size:15px;font-weight:800;color:var(--ink);letter-spacing:-.01em}
#tele-cost-host .cost-card.ok .cost-tier{color:var(--ok)}
#tele-cost-host .cost-card.purple .cost-tier{color:var(--purple)}
#tele-cost-host .cost-sub{font-size:11.5px;color:var(--faint);font-family:var(--mono);margin-top:2px;margin-bottom:11px}
#tele-cost-host .cost-metrics{display:flex;gap:18px;margin-bottom:10px}
#tele-cost-host .cost-metrics .cm-v{display:block;font-size:19px;font-weight:800;color:var(--ink);letter-spacing:-.02em}
#tele-cost-host .cost-metrics .cm-v small{font-size:11px;color:var(--muted);font-weight:600}
#tele-cost-host .cost-metrics .cm-l{display:block;font-size:10.5px;color:var(--muted);font-weight:600;margin-top:1px}
#tele-cost-host .cost-now{font-size:12.5px;color:var(--ink-2);padding:7px 0;border-top:1px dashed var(--line-2);margin-bottom:7px}
#tele-cost-host .cost-now b{color:var(--accent-ink)}
#tele-cost-host .cost-why{font-size:12px;color:var(--muted);line-height:1.55}
#tele-cost-host .cost-why b{color:var(--ink-2);font-weight:700}
#tele-cost-host .cost-tbl{margin-top:8px}
#tele-cost-host .cost-tbl td:first-child{color:var(--ink-2);font-weight:600}
#tele-cost-host .cost-tip{margin-top:14px;background:var(--accent-soft);border:1px solid var(--line-2);border-radius:var(--r);padding:11px 14px;font-size:12.5px;color:var(--ink-2);line-height:1.6}
#tele-cost-host .cost-tip b{color:var(--accent-ink)}
@media(max-width:760px){#tele-cost-host .cost-cards,.stage-cards,.err-cards{grid-template-columns:1fr}.bar-row{grid-template-columns:minmax(90px,1fr) 1fr 38px 42px}}
`;

PS.view("telemetry", {
  render() {
    this.ensureStyle();
    this.ensureLayout();
    if (!this._init) {
      this._init = true;
      const pauseBtn = PS.$("#telePause");
      if (pauseBtn) pauseBtn.addEventListener("click", () => this.togglePause());
      const loadBtn = PS.$("#teleLoad");
      if (loadBtn) loadBtn.addEventListener("click", () => this.load());
      const resetBtn = PS.$("#teleReset");
      if (resetBtn) resetBtn.addEventListener("click", () => this.reset());
    }
    this.refresh();
    clearInterval(this._timer);
    this._timer = setInterval(() => {
      if (!this._paused && PS.$("#view-telemetry").classList.contains("active")) this.refresh();
    }, 5000);
  },

  ensureStyle() {
    if (!document.getElementById("tele-console-style")) {
      const s = document.createElement("style");
      s.id = "tele-console-style"; s.textContent = TELE_CSS;
      document.head.appendChild(s);
    }
  },

  /* 用结构化控制台骨架替换静态 HTML(仅一次),沿用 .panel / .grid 等既有样式。 */
  ensureLayout() {
    const view = PS.$("#view-telemetry");
    if (PS.$("#tele-console")) return;
    // 移除旧的静态 KPI/charts/reasons/events 区块(保留 section-head),改为统一控制台容器。
    PS.$$("#view-telemetry .grid, #view-telemetry .row.spread").forEach(n => n.remove());
    const host = PS.el(`<div id="tele-console"></div>`);
    host.innerHTML =
      `<div class="tele-toolbar">
         <div class="tt-left">
           <button class="btn sm" id="telePause">⏸ 暂停刷新</button>
           <button class="btn sm" id="teleLoad">⚡ 注入合成负载</button>
           <button class="btn sm ghost" id="teleReset">清空遥测</button>
         </div>
         <div class="tt-right">
           <span class="live-dot" id="teleLive"><i></i><span id="teleLiveTxt">自动刷新 · 5s</span></span>
           <span class="priv-tag" id="teleUptime"></span>
         </div>
       </div>
       <div class="priv-tag" style="margin-bottom:14px">🔒 指标为 <b>Guard 进程内累积</b>(跨门户重启稳定)· 仅判定元数据(reason / 风险 / 扫描器 / 延迟 / 计数)· <b>绝不含任何 prompt / response 正文</b></div>
       <div class="meta-pills" id="tele-meta"></div>
       <div class="grid cols-4" id="tele-kpis"></div>
       <div id="tele-degraded" style="display:none"></div>

       <div class="grid cols-2" style="margin-top:18px;align-items:start">
         <div class="panel"><div class="panel-head"><span class="card-title">🎯 拦截原因 Top-N</span><span class="small muted">拦的都是什么</span></div><div class="panel-body" id="tele-reasons"></div></div>
         <div class="panel"><div class="panel-head"><span class="card-title">🛡 决策来源分布</span><span class="small muted">纵深防御·哪层在出力</span></div><div class="panel-body" id="tele-scanners"></div></div>
       </div>

       <div class="panel" style="margin-top:18px"><div class="panel-head"><span class="card-title">🧱 四道防线分解</span><span class="small muted">build → input → output</span></div><div class="panel-body" id="tele-stages"></div></div>

       <div class="grid cols-2" style="margin-top:18px;align-items:start">
         <div class="panel"><div class="panel-head"><span class="card-title">⏱ 检测延迟分布</span><span class="small muted" id="tele-lat-note"></span></div><div class="panel-body" id="tele-latency"></div></div>
         <div class="panel" id="tele-shadow-panel"><div class="panel-head"><span class="card-title">🟣 影子模式看板</span><span class="small muted">灰度上线</span></div><div class="panel-body" id="tele-shadow"></div></div>
       </div>

       <div class="panel" style="margin-top:18px"><div class="panel-head"><span class="card-title">🚦 错误 / 限流</span><span class="small muted">中间件层拒绝</span></div><div class="panel-body" id="tele-errors"></div></div>`;
    view.appendChild(host);
  },

  togglePause() {
    this._paused = !this._paused;
    const btn = PS.$("#telePause"), live = PS.$("#teleLive"), txt = PS.$("#teleLiveTxt");
    if (this._paused) { btn.textContent = "▶ 继续刷新"; live.classList.add("paused"); txt.textContent = "已暂停"; }
    else { btn.textContent = "⏸ 暂停刷新"; live.classList.remove("paused"); txt.textContent = "自动刷新 · 5s"; this.refresh(); }
  },

  async refresh() {
    let d;
    try { d = await PS.api("/telemetry"); }
    catch (e) { this.renderDegraded("门户无法连接(网络错误)"); return; }
    if (!d || d.available === false) { this.renderDegraded((d && d.error) || "Guard /metrics 不可达"); return; }
    this.renderConsole(d);
  },

  renderDegraded(msg) {
    const dg = PS.$("#tele-degraded");
    ["tele-kpis", "tele-meta"].forEach(id => { const n = PS.$("#" + id); if (n) n.innerHTML = ""; });
    if (dg) {
      dg.style.display = "";
      dg.innerHTML = `<div class="degraded">⚠️ 遥测暂不可用 —— Guard /metrics 拉取失败<div class="dg-sub">${PS.esc(msg)}</div></div>`;
    }
    const up = PS.$("#teleUptime"); if (up) up.textContent = "降级展示 · 不记录正文";
  },

  renderConsole(d) {
    const dg = PS.$("#tele-degraded"); if (dg) { dg.style.display = "none"; dg.innerHTML = ""; }
    const t = d.totals || {};
    const lat = d.latency || {};
    const isShadow = d.mode === "shadow";

    /* —— 元信息 pills —— */
    const mlPill = d.ml_degraded
      ? `<span class="pill block"><i class="dotmini"></i>ML 已降级</span>`
      : (d.ml_available
        ? `<span class="pill ok"><i class="dotmini"></i>ML 就绪 (PG2)</span>`
        : `<span class="pill"><i class="dotmini"></i>ML 未启用 · 规则档</span>`);
    PS.$("#tele-meta").innerHTML =
      `<span class="pill ${isShadow ? "purple" : "ok"}">模式 ${isShadow ? "shadow 影子" : "enforce 强制"}</span>` +
      mlPill +
      (d.version ? `<span class="pill">Guard v${PS.esc(d.version)}</span>` : "") +
      `<span class="pill">运行 ${this.fmtUptime(d.uptime_s)}</span>`;

    /* —— ① 总览卡片排 —— */
    const k = (l, v, cl, sub) => `<div class="kpi ${cl || ""}"><div class="k-label">${l}</div><div class="k-value">${v}</div>${sub ? `<div class="k-sub">${sub}</div>` : ""}</div>`;
    const kpis = [];
    kpis.push(k("总请求", PS.fmt(t.requests || 0), "accent", "input+output 各 stage 求和"));
    if (isShadow) {
      kpis.push(k("影子·本会拦率", PS.pct(t.would_block_rate || 0), "purple", `本会拦 ${PS.fmt(t.would_block || 0)} 次 · 已放行`));
    } else {
      kpis.push(k("拦截率", PS.pct(t.block_rate || 0), (t.block_rate || 0) > 0 ? "warn" : "ok", `拦 ${PS.fmt(t.blocked || 0)} · 放行 ${PS.fmt((t.requests || 0) - (t.blocked || 0))}`));
    }
    kpis.push(k("p50 / p95 延迟", `${(lat.p50 || 0).toFixed(1)}<small> / ${(lat.p95 || 0).toFixed(1)}ms</small>`, "", `p99 ${(lat.p99 || 0).toFixed(1)}ms`));
    const mlCl = d.ml_degraded ? "warn" : (d.ml_available ? "ok" : "");
    const mlVal = d.ml_degraded ? "降级" : (d.ml_available ? "就绪" : "规则档");
    kpis.push(k("ML 状态", mlVal, mlCl, d.ml_degraded ? "配置要 ML 但运行时不可用" : (d.ml_available ? "PG2 分类器运行中" : "未配置 ML")));
    PS.$("#tele-kpis").innerHTML = kpis.join("");

    /* —— ② 拦截原因 Top-N —— */
    const reasons = (d.by_reason || []).slice(0, 8).map(r => ({
      label: r.reason, count: r.count, color: this.reasonColor(r.reason)
    }));
    PS.$("#tele-reasons").innerHTML = PS.charts.bars(reasons, { empty: "暂无命中 —— 去 Demo 检测或注入合成负载", total: t.blocked || undefined });

    /* —— ③ 决策来源分布 by_scanner —— */
    const scMeta = [
      ["regex", "regex · 确定性短语", "var(--accent)"],
      ["ml", "ml · 机器学习层", "var(--purple)"],
      ["deobf", "deobf · 去混淆", "#3aa6c2"],
      ["canary", "canary · 逐字泄露", "var(--ok)"],
      ["protected_id", "protected_id · 受保护词", "var(--warn)"],
      ["pii", "pii · 输出 PII/密钥", "var(--block)"],
    ];
    const sc = d.by_scanner || {};
    const scTotal = scMeta.reduce((s, m) => s + (sc[m[0]] || 0), 0);
    const scItems = scMeta.map(m => ({ label: m[1], count: sc[m[0]] || 0, color: m[2] }));
    PS.$("#tele-scanners").innerHTML =
      PS.charts.bars(scItems, { total: scTotal || undefined, empty: "暂无确定性命中" }) +
      `<p class="tiny faint" style="margin-top:10px">六桶恒定齐全;llm_judge 不归确定性桶(仅进原因)。各桶反映纵深防御的「哪一层真正出力」。</p>`;

    /* —— ④ 四道防线分解 by_stage —— */
    const stMeta = [
      ["build", "s-build", "① 构建期加固", "种 canary / 注入受保护标识 / 模板加固"],
      ["input", "s-input", "② 输入检测", "注入·越狱·套取 regex + ML 分类"],
      ["output", "s-output", "③④ 输出双闸", "canary 逐字泄露 + 标识符 + PII/密钥"],
    ];
    const by = d.by_stage || {};
    PS.$("#tele-stages").innerHTML = `<div class="stage-cards">` + stMeta.map(m => {
      const s = by[m[0]] || { req: 0, blocked: 0, rate: 0 };
      const rate = s.rate || 0;
      const rcl = rate > 0 ? "var(--block)" : "var(--faint)";
      return `<div class="stage-card ${m[1]}">` +
        `<div class="sc-no">${m[0]}</div><div class="sc-name">${m[2]}</div>` +
        `<div class="sc-desc">${m[3]}</div>` +
        `<div class="sc-stat"><span class="sc-req">${PS.fmt(s.req)}<small> 请求</small></span>` +
        `<span class="sc-rate" style="color:${rcl}">${PS.pct(rate)} 拦截</span></div>` +
        `<div class="sc-meter"><span style="width:${Math.min(rate * 100, 100)}%;background:${rcl}"></span></div>` +
        `<div class="tiny faint mono" style="margin-top:6px">拦 ${PS.fmt(s.blocked)} / ${PS.fmt(s.req)}</div></div>`;
    }).join("") + `</div>`;

    /* —— ⑤ 延迟分布直方图 —— */
    PS.$("#tele-lat-note").textContent = `均值 ${(lat.avg_ms || 0).toFixed(2)}ms`;
    const marks = [
      { label: "p50", value: lat.p50 || 0, color: "var(--ok)" },
      { label: "p95", value: lat.p95 || 0, color: "var(--warn)" },
      { label: "p99", value: lat.p99 || 0, color: "var(--block)" },
    ];
    PS.$("#tele-latency").innerHTML =
      (lat.buckets && lat.buckets.length)
        ? PS.charts.histogram(lat.buckets, marks) + `<p class="tiny faint" style="margin-top:8px">横轴 = 累积 le 桶上界(ms),柱高 = 落入该桶的请求增量;分位由桶线性内插估算。</p>`
        : '<p class="muted small">暂无延迟样本 —— 发起几次检测后显示</p>';

    /* —— ⑥ 影子模式看板 —— */
    this.renderShadow(d, isShadow);

    /* —— ⑦ 错误 / 限流 —— */
    const er = d.errors || {};
    const errMeta = [
      ["ratelimit", "限流拒绝", "429", "超过速率上限被拒"],
      ["oversize", "超大请求体", "413", "请求体超过上限被拒"],
      ["error", "服务端错误", "5xx", "下游异常 / 处理器 ≥500"],
    ];
    PS.$("#tele-errors").innerHTML = `<div class="err-cards">` + errMeta.map(m => {
      const v = er[m[0]] || 0;
      return `<div class="err-card ${v > 0 ? "hot" : ""}"><div class="ec-v">${PS.fmt(v)}</div>` +
        `<div class="ec-l">${m[1]} <span class="ec-code">${m[2]}</span></div>` +
        `<div class="ec-code">${m[3]}</div></div>`;
    }).join("") + `</div>` +
      `<p class="tiny faint" style="margin-top:10px">中间件层在引擎检测前就拒绝的请求(promptsentinel_rejected_total)· 均为累计计数。全 0 表示无异常。</p>`;

    /* —— ⑧ 成本分析 —— */
    this.refreshCost(d);

    /* —— 顶部 uptime —— */
    PS.$("#teleUptime").textContent = `运行 ${this.fmtUptime(d.uptime_s)} · 不记录正文`;
  },

  renderShadow(d, isShadow) {
    const panel = PS.$("#tele-shadow-panel");
    const t = d.totals || {};
    if (isShadow) {
      panel.style.opacity = "1";
      PS.$("#tele-shadow").innerHTML =
        `<div class="shadow-box">` +
        `<div class="sb-head"><span class="sb-big">${PS.pct(t.would_block_rate || 0)}</span>` +
        `<span class="sb-cap">本会拦率 · 累计本会拦 <b class="mono">${PS.fmt(t.would_block || 0)}</b> 次<br>(已全部放行,零业务影响)</span></div>` +
        `<div class="sb-why">🟣 <b>影子灰度上线</b>:引擎照常检测但<b>不拦截</b>,只记录「本会拦」。` +
        `用真实流量观测<b>误拦率(FPR)</b>—— 把上面的本会拦率当作"如果现在切 enforce 会拦多少"。` +
        `确认 FPR 可接受后,再把 <code>mode</code> 从 <code>shadow</code> 切到 <code>enforce</code> 正式拦截。</div></div>`;
    } else {
      panel.style.opacity = "1";
      PS.$("#tele-shadow").innerHTML =
        `<div class="callout info" style="margin-bottom:10px">当前为 <b>enforce 强制模式</b> —— 命中即真实拦截。</div>` +
        `<div class="sb-why" style="font-size:12.5px;color:var(--ink-2);line-height:1.6">` +
        `🟣 <b>影子模式</b>用于<b>灰度上线</b>:先以 <code>mode=shadow</code> 跑真实流量,引擎检测但只记录「本会拦」不拦截,` +
        `观测误拦率(would_block_rate)。FPR 可接受后再切 <code>enforce</code>。` +
        `<br><br>当前累计 would_block = <b class="mono">${PS.fmt(t.would_block || 0)}</b>` +
        `(enforce 下此值通常为 0,因为命中已直接计入 blocked)。</div>`;
    }
  },

  /* —— ⑧ 成本分析(全本地估算,数据来自 /telemetry 延迟 + 请求量)—— */
  ensureCostPanel() {
    if (PS.$("#tele-cost-host")) return;
    const console = PS.$("#tele-console");
    const host = PS.el(`<div id="tele-cost-host" style="margin-top:18px"></div>`);
    host.innerHTML =
      `<div class="panel">` +
      `<div class="panel-head"><span class="card-title">💰 成本分析 · 运行成本画像</span>` +
      `<span class="small muted" id="tele-cost-note"></span></div>` +
      `<div class="panel-body"><div id="tele-cost-body"></div></div></div>`;
    console.appendChild(host);
  },

  refreshCost(d) {
    this.ensureCostPanel();
    const total = (d.totals && d.totals.requests) || 0;
    const lat = d.latency || {};
    const obsP50 = lat.p50 || 0, obsP95 = lat.p95 || 0, obsMean = lat.avg_ms || 0;
    const mlOn = !!d.ml_available;

    const regexMs = 0.1;
    const hybridMs = Math.round((mlOn && obsMean > regexMs ? Math.max(obsMean, 1) : 20) * 10) / 10;
    const cpuSecPerM = (ms) => ms * 1e6 / 1000;
    const regexCpuM = cpuSecPerM(regexMs);
    const hybridCpuM = cpuSecPerM(hybridMs);
    const ratio = hybridCpuM / regexCpuM;
    const regexQps = Math.round(1000 / regexMs);
    const hybridQps = mlOn ? Math.round(1000 / hybridMs) : 230;
    const fmtCpu = (s) => s >= 1000 ? (s / 1000).toFixed(1) + "k" : s.toFixed(s < 10 ? 2 : 0);
    const regexCostNow = total * regexMs / 1000;
    const hybridCostNow = total * hybridMs / 1000;

    PS.$("#tele-cost-note").textContent = total
      ? `基于当前 ${PS.fmt(total)} 条观测 · 全本地估算 · 无外部定价 API`
      : "去「⚡ 注入合成负载」后看真实画像 · 全本地估算";

    const card = (cls, tier, sub, qps, ms, cpuM, costNow, why) =>
      `<div class="cost-card ${cls}">` +
      `<div class="cost-tier">${tier}</div><div class="cost-sub">${sub}</div>` +
      `<div class="cost-metrics">` +
      `<div><span class="cm-v mono">${PS.fmt(qps)}</span><span class="cm-l">QPS·核</span></div>` +
      `<div><span class="cm-v mono">${ms}<small>ms</small></span><span class="cm-l">单条 CPU</span></div>` +
      `<div><span class="cm-v mono">${fmtCpu(cpuM)}</span><span class="cm-l">CPU·秒/百万</span></div>` +
      `</div>` +
      `<div class="cost-now">当前 ${PS.fmt(total)} 条 ≈ <b class="mono">${costNow < 0.01 && costNow > 0 ? "<0.01" : fmtCpu(costNow)}</b> CPU·秒</div>` +
      `<div class="cost-why">${why}</div></div>`;

    const cards =
      `<div class="cost-cards">` +
      card("ok", "零成本档 · regex", "纯正则 / 零依赖 / 单线程", regexQps, regexMs,
        regexCpuM, regexCostNow,
        "亚毫秒纯 CPU、无模型加载、无 GPU、无内存常驻 → 每百万请求算力成本<b>≈0</b>。可裸跑万级 QPS。") +
      card("purple", "hybrid 档 · PG2 ML", "Prompt Guard 2 · 22M ONNX", hybridQps, hybridMs,
        hybridCpuM, hybridCostNow,
        `每条要跑一次 ONNX 前向(<b>~${hybridMs}ms CPU</b>)+ 模型常驻内存(数百 MB)→ 算力是 regex 的 <b>${Math.round(ratio)}×</b>,QPS 掉到百级/核。`) +
      `</div>`;

    const row = (kk, a, b, diff, cls) =>
      `<tr><td class="small">${kk}</td><td class="mono small">${a}</td><td class="mono small">${b}</td>` +
      `<td><span class="badge ${cls || "muted"}">${diff}</span></td></tr>`;

    const cmp =
      `<div class="section-title" style="margin-top:16px">两档对比 · 同样 ${PS.fmt(total || 0)} 条流量代入</div>` +
      `<table class="tbl cost-tbl"><thead><tr>` +
      `<th>维度</th><th>零成本档 (regex)</th><th>hybrid 档 (PG2)</th><th>差距</th></tr></thead><tbody>` +
      row("单条 CPU 时间", regexMs + "ms", hybridMs + "ms", "贵 " + Math.round(hybridMs / regexMs) + "×", "warn") +
      row("理论吞吐", PS.fmt(regexQps) + " QPS·核", PS.fmt(hybridQps) + " QPS" + (mlOn ? "·核" : "·worker"), "降 " + Math.round(regexQps / hybridQps) + "×", "warn") +
      row("p50 延迟", "~0.1ms", (mlOn ? obsP50.toFixed(1) : "~17") + "ms", "—", "") +
      row("p95 延迟", "~0.3ms", (mlOn ? obsP95.toFixed(1) : "~25") + "ms", "—", "") +
      row("算力 / 百万请求", fmtCpu(regexCpuM) + " CPU·秒", fmtCpu(hybridCpuM) + " CPU·秒", Math.round(ratio) + "× 成本", "warn") +
      row("外部 API 费", "¥0 · 全本地", "¥0 · 全本地", "数据不出域", "ok") +
      `</tbody></table>`;

    const cascade =
      `<div class="cost-tip">🪜 <b>级联省成本</b>:生产用「regex 先筛 → 仅可疑流量过 PG2」,绝大多数正常请求停在亚毫秒的 regex 档,` +
      `所以级联下 hybrid <b>p50 仍≈0.1ms</b> —— 只有少数命中规则的请求才真正付出 ${hybridMs}ms 的 ML 算力。这就是为什么 ` +
      `<b>regex 几乎免费</b>、而 hybrid 的钱<b>只花在该花的可疑请求上</b>。</div>`;

    PS.$("#tele-cost-body").innerHTML = cards + cmp + cascade;
  },

  /* —— helpers —— */
  reasonColor(reason) {
    const r = reason || "";
    if (r.indexOf("canary") >= 0 || r.indexOf("system_prompt_leak") >= 0) return "var(--ok)";
    if (r.indexOf("pii") >= 0) return "var(--block)";
    if (r.indexOf("protected") >= 0) return "var(--warn)";
    if (r.indexOf("ml_classifier") >= 0 || r.indexOf("llm_guard") >= 0 || r.indexOf("llm_judge") >= 0) return "var(--purple)";
    if (r.indexOf("output") === 0) return "#3aa6c2";
    return "var(--accent)";
  },

  fmtUptime(s) {
    s = Math.floor(s || 0);
    if (s < 60) return s + "s";
    if (s < 3600) return Math.floor(s / 60) + "m" + (s % 60) + "s";
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return h + "h" + m + "m";
  },

  async load() {
    const b = PS.$("#teleLoad"); if (!b) return;
    b.disabled = true; b.textContent = "注入中…";
    try { const r = await PS.post("/load"); PS.toast("已注入 " + r.replayed + " 条合成请求", "ok"); await this.refresh(); }
    catch (e) { PS.toast("注入失败"); }
    finally { b.disabled = false; b.textContent = "⚡ 注入合成负载"; }
  },

  async reset() {
    try { await PS.post("/telemetry/reset"); PS.toast("门户侧遥测已清空(Guard 累积计数不受影响)", "ok"); await this.refresh(); }
    catch (e) {}
  }
});
