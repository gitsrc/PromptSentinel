/* 监控遥测 view:KPI + 时间线/延迟图 + 命中原因 + 事件 + 全链路追踪 + 成本分析。自动刷新。 */
const COST_CSS = `
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
@media(max-width:760px){#tele-cost-host .cost-cards{grid-template-columns:1fr}}
`;
PS.view("telemetry", {
  render() {
    if (!this._init) {
      this._init = true;
      PS.$("#teleLoad").addEventListener("click", () => this.load());
      PS.$("#teleReset").addEventListener("click", () => this.reset());
    }
    this.refresh();
    clearInterval(this._timer);
    this._timer = setInterval(() => { if (PS.$("#view-telemetry").classList.contains("active")) this.refresh(); }, 4000);
  },
  async refresh() {
    let d; try { d = await PS.api("/telemetry"); } catch (e) { return; }
    const k = (l, v, cl, sub) => `<div class="kpi ${cl || ""}"><div class="k-label">${l}</div><div class="k-value">${v}</div>${sub ? `<div class="k-sub">${sub}</div>` : ""}</div>`;
    const isShadow = d.mode === "shadow";
    PS.$("#tele-kpis").innerHTML =
      k("总请求", PS.fmt(d.total), "accent") +
      (isShadow
        ? k("影子·本会拦率", PS.pct(d.would_block_rate || 0), "purple", `本会拦 ${d.would_block} 次 · 已放行未影响业务`)
        : k("拦截率", PS.pct(d.block_rate), d.block_rate > 0 ? "warn" : "ok", `拦截 ${d.blocked} / 放行 ${d.allowed}`)) +
      k("p50 延迟", d.latency_ms.p50 + "ms", "") +
      k("p95 延迟", d.latency_ms.p95 + "ms", "purple");
    const shadowBanner = isShadow
      ? `<div style="background:rgba(139,92,246,.08);border:1px solid rgba(139,92,246,.32);border-radius:8px;padding:9px 13px;margin-bottom:12px;font-size:13px;line-height:1.5">🟣 <b>影子灰度模式</b> —— 引擎照常检测但<b>不拦截</b>,仅记录"本会拦";用真实流量观测误拦,<b>零业务影响</b>。确认 FPR 可接受后切 <code>enforce</code> 正式拦截。</div>`
      : "";
    PS.$("#tele-charts").innerHTML = shadowBanner +
      (isShadow
        ? `<div class="section-title">影子·本会拦趋势(红=本会拦)</div>` + PS.charts.timeline((d.wb_timeline || []).map(x => (x ? 0 : 1)))
        : `<div class="section-title">放行 / 拦截时间线</div>` + PS.charts.timeline(d.timeline)) +
      `<div class="section-title" style="margin-top:14px">检测延迟分位</div>` + PS.charts.latency(d.latency_ms.p50, d.latency_ms.p95, d.latency_ms.mean);
    const max = (d.reasons[0] && d.reasons[0].count) || 1;
    PS.$("#tele-reasons").innerHTML = d.reasons.length ? d.reasons.map(r =>
      `<div class="row spread" style="padding:5px 0"><span class="small mono">${PS.esc(r.name)}</span>` +
      `<div class="row"><div class="meter block" style="width:140px"><span style="width:${r.count / max * 100}%"></span></div>` +
      `<span class="mono small" style="width:34px;text-align:right">${r.count}</span></div></div>`).join("") : '<p class="muted small">暂无命中</p>';
    PS.$("#tele-events").innerHTML = `<div class="events">` + (d.events.length ? d.events.map(e =>
      `<div class="event ${e.allowed ? "" : "blocked"}"><span class="etime">${e.ts}</span>` +
      `<span><b class="small">${e.stage}</b> <span class="tiny faint">${e.source}</span>${e.reasons.length ? " · " + PS.esc(e.reasons.join(",")) : ""}</span>` +
      `<span class="badge ${e.allowed ? "ok" : "block"}">${e.allowed ? "放行" : "拦截"}</span></div>`).join("") : '<p class="muted small">暂无事件 —— 去 Demo 检测或运行合成负载</p>') + `</div>`;
    PS.$("#teleUptime").textContent = "运行 " + d.uptime_s + "s · 不记录正文";
    this.refreshTraces();
    this.refreshCost(d);
  },

  /* —— 成本分析(独占注入,不依赖 index.html;数据全来自 /api/telemetry 的延迟分位 + 请求量,纯本地估算)—— */
  ensureCostPanel() {
    if (PS.$("#tele-cost-host")) return;
    if (!document.getElementById("tele-cost-style")) {
      const s = document.createElement("style"); s.id = "tele-cost-style"; s.textContent = COST_CSS; document.head.appendChild(s);
    }
    // 注入到监控页:挂在「事件/追踪」那一行的 grid 之后(全宽)
    const view = PS.$("#view-telemetry");
    const anchor = PS.$("#tele-traces") ? PS.$("#tele-traces").closest(".grid") : null;
    const host = PS.el(`<div id="tele-cost-host" style="margin-top:18px"></div>`);
    if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(host, anchor.nextSibling);
    else view.appendChild(host);
    host.innerHTML =
      `<div class="panel">` +
      `<div class="panel-head"><span class="card-title">💰 成本分析 · 运行成本画像</span>` +
      `<span class="small muted" id="tele-cost-note"></span></div>` +
      `<div class="panel-body"><div id="tele-cost-body"></div></div></div>`;
  },

  refreshCost(d) {
    this.ensureCostPanel();
    const total = d.total || 0;
    // 观测到的 hybrid 档延迟:优先用真实 p50/mean(级联下 p50 常≈0.1ms),hybrid 单条以 mean 兜底估算
    const obsP50 = d.latency_ms.p50, obsP95 = d.latency_ms.p95, obsMean = d.latency_ms.mean;
    const mlOn = !!(PS.status && PS.status.health && PS.status.health.ml_classifier);

    // —— 两档单请求 CPU 时间模型(ms/req)——
    // regex 档:亚毫秒、纯 CPU、零依赖 —— 取 0.1ms(与级联 p50 一致)
    const regexMs = 0.1;
    // hybrid 档(PG2 ML):取观测 mean(若已开 ML 用真实值),否则用业界基线 ~20ms
    const hybridMs = Math.round((mlOn && obsMean > regexMs ? Math.max(obsMean, 1) : 20) * 10) / 10;

    // 每百万请求的 CPU·秒(单条 ms × 1e6 / 1000)
    const cpuSecPerM = (ms) => ms * 1e6 / 1000;
    const regexCpuM = cpuSecPerM(regexMs);     // ≈100 CPU·s / 百万
    const hybridCpuM = cpuSecPerM(hybridMs);   // ≈20000 CPU·s / 百万
    const ratio = hybridCpuM / regexCpuM;      // hybrid 比 regex 贵多少倍

    // 单核理论 QPS(1000ms / 单条ms);worker 实测 hybrid≈230 QPS
    const regexQps = Math.round(1000 / regexMs);                 // ≈10000 QPS·核
    const hybridQps = mlOn ? Math.round(1000 / hybridMs) : 230;  // ≈50/核理论,实测 230/worker

    // 把当前观测请求量代入两档,估算「这些流量」的 CPU·秒
    const fmtCpu = (s) => s >= 1000 ? (s / 1000).toFixed(1) + "k" : s.toFixed(s < 10 ? 2 : 0);
    const regexCostNow = total * regexMs / 1000;   // CPU·秒
    const hybridCostNow = total * hybridMs / 1000;

    PS.$("#tele-cost-note").textContent = total
      ? `基于当前 ${PS.fmt(total)} 条观测 · 全本地估算 · 无外部定价 API`
      : "去「⚡ 注入合成负载」后看真实画像 · 全本地估算";

    // —— 两张档位卡片 ——
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

    // —— 对比小表格 ——
    const cmp =
      `<div class="section-title" style="margin-top:16px">两档对比 · 同样 ${PS.fmt(total || 0)} 条流量代入</div>` +
      `<table class="tbl cost-tbl"><thead><tr>` +
      `<th>维度</th><th>零成本档 (regex)</th><th>hybrid 档 (PG2)</th><th>差距</th></tr></thead><tbody>` +
      row("单条 CPU 时间", regexMs + "ms", hybridMs + "ms", "贵 " + Math.round(hybridMs / regexMs) + "×", "warn") +
      row("理论吞吐", PS.fmt(regexQps) + " QPS·核", PS.fmt(hybridQps) + " QPS" + (mlOn ? "·核" : "·worker"), "降 " + Math.round(regexQps / hybridQps) + "×", "warn") +
      row("p50 延迟", "~0.1ms", (mlOn ? obsP50 : "~17") + "ms", "—", "") +
      row("p95 延迟", "~0.3ms", (mlOn ? obsP95 : "~25") + "ms", "—", "") +
      row("算力 / 百万请求", fmtCpu(regexCpuM) + " CPU·秒", fmtCpu(hybridCpuM) + " CPU·秒", Math.round(ratio) + "× 成本", "warn") +
      row("外部 API 费", "¥0 · 全本地", "¥0 · 全本地", "数据不出域", "ok") +
      `</tbody></table>`;

    // —— 级联省钱说明 ——
    const cascade =
      `<div class="cost-tip">🪜 <b>级联省成本</b>:生产用「regex 先筛 → 仅可疑流量过 PG2」,绝大多数正常请求停在亚毫秒的 regex 档,` +
      `所以级联下 hybrid <b>p50 仍≈0.1ms</b> —— 只有少数命中规则的请求才真正付出 ${hybridMs}ms 的 ML 算力。这就是为什么 ` +
      `<b>regex 几乎免费</b>、而 hybrid 的钱<b>只花在该花的可疑请求上</b>。</div>`;

    PS.$("#tele-cost-body").innerHTML = cards + cmp + cascade;

    function row(k, a, b, diff, cls) {
      return `<tr><td class="small">${k}</td><td class="mono small">${a}</td><td class="mono small">${b}</td>` +
        `<td><span class="badge ${cls || "muted"}">${diff}</span></td></tr>`;
    }
  },
  async refreshTraces() {
    let t; try { t = await PS.api("/traces"); } catch (e) { return; }
    PS.$("#tele-traces").innerHTML = t.length ? t.slice(0, 8).map(tr =>
      `<div class="row spread" style="padding:7px 0;border-bottom:1px solid var(--line)">` +
      `<span class="small"><span class="tiny faint mono">${tr.ts}</span> ${tr.stage} <span class="tiny faint mono">${tr.trace_id}</span></span>` +
      `<div class="row"><span class="tiny mono faint">${tr.guard_ms}ms</span><span class="badge ${tr.allowed ? "ok" : "block"}">${tr.triggered} 命中</span></div></div>`).join("") : '<p class="muted small">暂无追踪 —— 去 Demo 触发一次</p>';
  },
  async load() {
    const b = PS.$("#teleLoad"); b.disabled = true; b.textContent = "注入中…";
    try { const r = await PS.post("/load"); PS.toast("已注入 " + r.replayed + " 条合成请求", "ok"); await this.refresh(); }
    catch (e) { PS.toast("注入失败"); }
    finally { b.disabled = false; b.textContent = "⚡ 注入合成负载"; }
  },
  async reset() { try { await PS.post("/telemetry/reset"); PS.toast("遥测已清空", "ok"); await this.refresh(); } catch (e) {} }
});
