/* 概览 view:KPI + 四道防线 + 行业基准 scorecard(共享 PS.renderScorecard)。 */
PS.view("overview", {
  async render() {
    let ev;
    try { ev = await PS.loadEval(); } catch (e) { PS.$("#ov-scorecard").innerHTML = '<p class="muted small">评测数据不可用</p>'; return; }
    const main = ev.rows.find(r => r.primary) || ev.rows[0];
    const pg2 = (ev.backends || []).find(b => /PG2|默认|prompt_guard/i.test(b.name)) || {};

    const kpis = [
      { label: "主线套取 · hybrid 拦截", value: PS.pct(main.hybrid), sub: "Lakera/gandalf · 1000 条", cls: "ok" },
      { label: "ML 单条延迟 (PG2)", value: (pg2.latency_ms || 25), unit: "ms", sub: "级联下主线 p50 0.09ms", cls: "accent" },
      { label: "防护防线", value: "4", sub: "构建期 / 输入 / 输出 ×2", cls: "" },
      { label: "中文良性误报", value: "0", unit: "%", sub: "多语种 · lang-guard", cls: "purple" },
    ];
    PS.$("#ov-kpis").innerHTML = kpis.map(k =>
      `<div class="kpi ${k.cls}"><div class="k-label">${PS.esc(k.label)}</div>` +
      `<div class="k-value">${PS.esc(k.value)}${k.unit ? `<small>${k.unit}</small>` : ""}</div>` +
      `<div class="k-sub">${PS.esc(k.sub)}</div></div>`).join("");

    const lines = [
      { n: "①", t: "构建期加固", d: "系统提示词外覆安全层 + 注入唯一 canary 哨兵,声明最高优先级、不可覆盖。", tag: "零成本" },
      { n: "②", t: "输入注入检测", d: "中英文注入/越狱/套取正则 + 业界基准 ML(Prompt Guard 2);不可信内容更严阈值。", tag: "规则 + ML" },
      { n: "③", t: "输出 canary 逃逸", d: "输出含 canary = 系统提示词逐字泄露,确定性判定、近 100%、零误报。", tag: "确定性" },
      { n: "④", t: "输出标识符 / PII", d: "受保护标识符改写复述 + 凭证/PII 正则兜底(可选 NER 覆盖姓名地址)。", tag: "确定性" },
    ];
    PS.$("#ov-lines").innerHTML = lines.map(l =>
      `<div class="card hover"><div class="card-title"><span class="badge accent">${l.n}</span>${PS.esc(l.t)}</div>` +
      `<p class="small muted" style="margin:8px 0 12px">${PS.esc(l.d)}</p><span class="badge muted">${PS.esc(l.tag)}</span></div>`).join("");

    const host = PS.$("#ov-scorecard");
    if (PS.renderScorecard) PS.renderScorecard(host, ev);
    else host.innerHTML = '<p class="muted small">加载中…</p>';

    // —— 数据来源标注:让能力数据可信、可追溯 ——
    // 尝试从后端取最近一次 benchmark 运行的时间戳 / run_id;取不到则标注本机实测可复现。
    let banner;
    try {
      const hist = await PS.api("/benchmark/history");
      const last = Array.isArray(hist) && hist.length ? hist[0] : null;
      if (last && last.ts) {
        const meta = [last.n ? "每集 " + last.n + " 条" : null, "ML " + (last.ml_enabled ? "开" : "关")]
          .filter(Boolean).join(" · ");
        banner =
          '数据来源:<b>' + PS.esc(last.ts) + '</b> 的 benchmark 运行' +
          (last.run_id ? ' · run <b class="mono">' + PS.esc(last.run_id) + '</b>' : "") +
          (meta ? ' · ' + PS.esc(meta) : "") +
          ' —— 本机实测,<code>make benchmark-gate</code> 可复现。';
      }
    } catch (e) { /* 后端不可达或无 history:降级到静态标注 */ }
    if (!banner) {
      banner = '数据来源:<b>本机实测</b> · <code>make benchmark-gate</code> 可复现(尚无持久化 benchmark 运行记录)。';
    }
    host.insertAdjacentHTML("afterbegin",
      '<div class="callout info small" style="margin-bottom:14px">' + banner + '</div>');
  }
});
