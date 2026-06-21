/* 轻量 SVG / DOM 图表助手(零依赖)。挂在 PS.charts。 */
(function () {
  const PS = window.PS = window.PS || {};
  PS.charts = {
    // 时间线柱:values = [1 放行 / 0 拦截]
    timeline(values) {
      if (!values || !values.length) return '<p class="muted small">暂无数据</p>';
      const bars = values.map((v, i) => {
        const h = v ? 58 : 24, c = v ? "var(--ok)" : "var(--block)";
        return `<rect x="${i * 6}" y="${62 - h}" width="4" height="${h}" rx="1.5" fill="${c}" opacity="${v ? .5 : .95}"/>`;
      }).join("");
      return `<svg viewBox="0 0 ${values.length * 6} 64" width="100%" height="76" preserveAspectRatio="none">${bars}</svg>` +
        `<div class="legend" style="margin-top:6px"><span><i style="background:var(--ok)"></i>放行</span><span><i style="background:var(--block)"></i>拦截</span></div>`;
    },
    // 环形进度 0..1
    donut(pct, label, color) {
      const r = 42, c = 2 * Math.PI * r, off = c * (1 - Math.max(0, Math.min(1, pct)));
      color = color || "var(--accent)";
      return `<svg viewBox="0 0 110 110" width="118" height="118"><circle cx="55" cy="55" r="${r}" fill="none" stroke="var(--surface-3)" stroke-width="11"/>` +
        `<circle cx="55" cy="55" r="${r}" fill="none" stroke="${color}" stroke-width="11" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${off}" transform="rotate(-90 55 55)" style="transition:stroke-dashoffset .7s ease"/>` +
        `<text x="55" y="51" text-anchor="middle" font-size="22" font-weight="800" fill="var(--ink)" font-family="var(--mono)">${(pct * 100).toFixed(0)}<tspan font-size="11">%</tspan></text>` +
        `<text x="55" y="69" text-anchor="middle" font-size="9.5" fill="var(--muted)">${label || ""}</text></svg>`;
    },
    // 延迟分位条
    latency(p50, p95, mean) {
      const max = Math.max(p95, mean, 1);
      const row = (lbl, v, c) => `<div class="row" style="gap:8px;margin:5px 0"><span class="small mono faint" style="width:40px">${lbl}</span>` +
        `<div class="meter ${c || ""}" style="flex:1"><span style="width:${Math.min(v / max * 100, 100)}%"></span></div>` +
        `<span class="small mono" style="width:66px;text-align:right">${(+v).toFixed(1)}ms</span></div>`;
      return row("p50", p50, "ok") + row("p95", p95, "") + row("均值", mean, "");
    }
  };
})();
