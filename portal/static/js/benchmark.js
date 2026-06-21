/* 数据集 Benchmark:异步任务执行 + 实时进度轮询 + 结果持久化 + 历史查询 + 完整解释。
   PS.renderScorecard 供 overview(完整静态);PS.renderMeta 供本页(成本分档说明)。 */

const DS_META = {
  gandalf: { name: "Lakera/gandalf", line: "② 系统提示/密钥套取(主线)", attack: true,
    desc: "诱导模型说出系统提示词/密钥的真实攻击集 —— 这是系统提示词防护最切题的<b>主线指标</b>。" },
  inthewild: { name: "In-the-Wild Jailbreak", line: "② 真实越狱", attack: true,
    desc: "野外真实收集的越狱提示,覆盖角色扮演/DAN/绕过等多样手法。" },
  pii: { name: "ai4privacy PII", line: "④ 输出 PII", attack: true,
    desc: "含 PII 的文本,测<b>输出端</b>泄漏拦截。注意:ML 注入分类器只检输入,<b>不检输出面</b>,所以 regex≈当前。" },
  deepset: { name: "deepset(参照)", line: "② 通用注入", attack: false,
    desc: "通用注入/良性二分类,<b>含良性样本故可测 FPR(误拦)</b>;偏泛、非主线,仅作参照。" },
  safeguard: { name: "safe-guard", line: "② 注入检测(含良性)", attack: false,
    desc: "<b>真·注入检测集(威胁模型对齐)</b>,含大量良性样本补 FPR;当前 recall 偏低,反映对英文注入改写的覆盖不足,是真实改进点。" },
  chinese_inject: { name: "中文注入(thu-coai)", line: "② 中文目标劫持", attack: true,
    desc: "清华 thu-coai 中文安全prompts的 <b>Goal_Hijacking(目标劫持)</b>,精筛对齐 —— 原集的 Prompt_Leaking 实为良性安全咨询、Role_Play 为内容安全,<b>均未取</b>;补中文盲区。" },
  adversarial: { name: "对抗变体", line: "⑤ 对抗鲁棒性", attack: true,
    desc: "对已知攻击施加 <b>leetspeak / 字符间隔 / base64 / GCG 后缀</b>。leetspeak、间隔变换能<b>绕过确定性规则(真实缺口)</b> —— benchmark 把对抗鲁棒性短板暴露出来。" },
  business_benign: { name: "业务良性", line: "② 业务良性(FPR)", attack: false,
    desc: "中英文<b>正常业务请求</b>(查询/操作/技术问答),测贴近线上流量的真实 FPR(应≈0);生产应替换为你自己的真实流量样本。" },
};

function _tiersHtml(ev) {
  const tiers = (ev.tiers || []).map((t, i) =>
    `<div class="card" style="${i === 1 ? "border-color:var(--accent)" : ""}"><div style="font-weight:700">${PS.esc(t.name)}</div>` +
    `<div class="small" style="margin-top:6px">主线召回 <b>${PS.esc(t.mainline)}</b></div>` +
    `<div class="small muted" style="margin-top:2px">成本:${PS.esc(t.cost)}</div>` +
    `<div class="tiny faint" style="margin-top:4px">适用:${PS.esc(t.fit)}</div></div>`).join("");
  const backends = (ev.backends || []).map(b =>
    `<tr><td><b>${PS.esc(b.name)}</b></td><td class="t-num">${PS.pct(b.gandalf)}</td><td class="t-num">${PS.pct(b.inthewild)}</td>` +
    `<td class="mono">${b.latency_ms}ms</td><td class="mono">${PS.esc(b.size)}</td><td class="small muted">${PS.esc(b.note)}</td></tr>`).join("");
  return `<div class="section-title">成本分档 · 按预算选档</div><div class="grid cols-2">${tiers}</div>` +
    (backends ? `<div class="section-title" style="margin-top:18px">ML 后端对比(hybrid 口径,实测)</div><div class="panel"><div class="panel-body" style="overflow-x:auto"><table class="tbl"><thead><tr><th>后端</th><th>gandalf 主线</th><th>in-the-wild</th><th>延迟</th><th>大小</th><th>备注</th></tr></thead><tbody>${backends}</tbody></table></div></div>` : "") +
    (ev.cost_notes ? `<div class="callout info" style="margin-top:14px">${PS.esc(ev.cost_notes)}</div>` : "") +
    (ev.caveat ? `<div class="callout" style="margin-top:10px">${PS.esc(ev.caveat)}</div>` : "");
}

PS.renderScorecard = function (host, ev) {
  if (!host) return;
  const pcell = (v) => v == null ? '<span class="faint">—</span>' : `<span style="color:var(--${PS.cls(v)})">${PS.pct(v)}</span>`;
  const rows = ev.rows.map(r =>
    `<tr${r.primary ? ' style="background:var(--accent-soft)"' : ""}>` +
    `<td><b>${PS.esc(r.dataset)}</b><div class="tiny faint">${PS.esc(r.tag || "")}</div></td>` +
    `<td class="mono small">${PS.esc(r.line)}</td>` +
    `<td class="t-num">${pcell(r.regex)}</td><td class="t-num">${pcell(r.ml)}</td><td class="t-num"><b>${pcell(r.hybrid)}</b></td>` +
    `<td class="t-num">${r.fpr == null ? '<span class="faint">—</span>' : `<span style="color:var(--${r.fpr === 0 ? "ok" : "block"})">${PS.pct(r.fpr)}</span>`}</td>` +
    `<td class="faint mono small">${r.n}</td><td class="small muted">${PS.esc(r.note || "")}</td></tr>`).join("");
  host.innerHTML =
    `<div class="callout" style="margin-bottom:12px">下表为<b>预先 make eval 实测落盘</b>的概览;要<b>实时真跑</b>请到 Benchmark 页点"运行真实评测"。</div>` +
    `<div class="panel"><div class="panel-body" style="overflow-x:auto"><table class="tbl"><thead><tr><th>数据集</th><th>防线</th><th>regex</th><th>ML</th><th>hybrid</th><th>FPR</th><th>n</th><th>说明</th></tr></thead><tbody>${rows}</tbody></table></div></div>` +
    `<div style="margin-top:18px">${_tiersHtml(ev)}</div>`;
};

PS.renderMeta = function (host, ev) { if (host) host.innerHTML = _tiersHtml(ev); };

// 结果表(进度中的 partial 与最终 result 复用)
function _dsTable(datasets) {
  const pct = (v) => v == null ? '<span class="faint">—</span>' : `<span style="color:var(--${PS.cls(v)})">${PS.pct(v)}</span>`;
  const ci = (a) => a ? ` <span class="tiny faint">[${(a[0] * 100).toFixed(0)}–${(a[1] * 100).toFixed(0)}]</span>` : "";
  const rows = Object.entries(datasets).map(([k, v]) => {
    const c = v.current, r = v.regex;
    const fpr = (r.fpr == null) ? '<span class="faint">n/a</span>' : `${PS.pct(r.fpr)}→${PS.pct(c.fpr)}`;
    return `<tr><td><b>${PS.esc(k)}</b><div class="tiny faint">${PS.esc(v.line || "")}</div></td>` +
      `<td class="t-num">${pct(r.recall)}</td>` +
      `<td class="t-num"><b>${pct(c.recall)}</b>${ci(c.recall_ci)}</td>` +
      `<td class="t-num">${pct(c.precision)}</td><td class="t-num">${pct(c.f1)}</td>` +
      `<td class="small">${fpr}</td><td class="mono small faint">${c.p50_ms}ms·n${v.n}</td></tr>`;
  }).join("");
  return `<table class="tbl"><thead><tr><th>数据集</th><th>regex</th><th>当前 recall(95%CI)</th><th>precision</th><th>F1</th><th>FPR(r→当前)</th><th>延迟·n</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function _explainHtml(run) {
  const d = run.datasets || {};
  const items = Object.entries(d).map(([k, v]) => {
    const m = DS_META[k] || { name: k, line: v.line, desc: "" };
    const c = v.current || {}, rg = v.regex || {};
    let read = "";
    if (k === "gandalf") read = `主线拦截率:regex <b>${PS.pct(rg.recall)}</b> → 当前 <b>${PS.pct(c.recall)}</b>。这是系统提示词套取的核心指标,越高越好。`;
    else if (k === "pii") read = `regex 与当前接近(<b>${PS.pct(rg.recall)}</b>/<b>${PS.pct(c.recall)}</b>),因为 ML 不检输出面;要提升输出 PII 需开 use_llm_guard(NER)。`;
    else if (k === "deepset") read = `含良性样本,故有 FPR:regex <b>${PS.pct(rg.fpr)}</b> → 当前 <b>${PS.pct(c.fpr)}</b>(越低越好)。recall 偏低是因为它泛、非主线。`;
    else read = `拦截率:regex <b>${PS.pct(rg.recall)}</b> → 当前 <b>${PS.pct(c.recall)}</b>。`;
    return `<div class="check clear" style="align-items:flex-start"><div class="ci">${k === "gandalf" ? "★" : "·"}</div><div>` +
      `<div class="cname">${PS.esc(m.name)} <span class="tiny faint mono">${PS.esc(m.line)}</span> · n=${v.n}</div>` +
      `<div class="cdesc">${m.desc}</div><div class="small" style="margin-top:4px">${read}</div></div></div>`;
  }).join("");
  return `<div class="section-title" style="margin-top:18px">结果完整解释</div>` +
    `<div class="callout info" style="margin-bottom:10px"><b>口径:</b>每个数据集随机抽样 <b>${run.n}</b> 条(seed 固定),逐条过引擎现算。<b>regex 基线</b>=只确定性规则(零成本);<b>当前配置</b>=本次运行时 guard 的实际配置(ML ${run.ml_enabled ? "已启用 PG2" : "未启用"})。<b>recall</b>=攻击拦截率(越高越好);<b>FPR</b>=良性误拦率(越低越好,仅 deepset 含良性);<b>p50</b>=单条检测中位延迟。</div>` +
    `<div class="checks">${items}</div>` +
    `<div class="callout" style="margin-top:12px"><b>诚实说明:</b>页面是<b>抽样实时</b>评测,n 越大越接近全量;改 guard 配置后重跑数字会变。全量精确数字用 <code>make eval-hybrid</code>(1616 条全跑)。受控指标 ≠ 真实对抗上限,系统提示词不泄露的硬保障在 ③canary + ④标识符 + 架构层。</div>`;
}

PS.view("benchmark", {
  async render() {
    try { const ev = await PS.loadEval(); PS.renderMeta(PS.$("#bench-scorecard"), ev); } catch (e) {}
    const dr = PS.$("#dsRun"); if (dr && !dr._bound) { dr._bound = true; dr.addEventListener("click", () => this.runDatasets()); }
    const br = PS.$("#benchRun"); if (br && !br._bound) { br._bound = true; br.addEventListener("click", () => this.runLive()); }
    const ib = PS.$("#dsInfoBtn"); if (ib && !ib._bound) { ib._bound = true; ib.addEventListener("click", () => this.showDatasets()); }
    this.loadHistory();
  },

  async showDatasets() {
    try {
      const d = await PS.api("/datasets");
      const html = Object.entries(d.datasets).map(([k, v]) => {
        const samples = (v.samples || []).map(s =>
          `<div class="code" style="font-size:11.5px;margin:5px 0;white-space:pre-wrap"><span class="badge ${s.label === 1 ? "block" : "ok"}" style="margin-right:6px">${s.label === 1 ? "攻击" : "良性"}</span>${PS.esc(s.text)}</div>`).join("");
        return `<div style="margin-bottom:18px;padding-bottom:16px;border-bottom:1px solid var(--line)">` +
          `<div class="spread"><b>${PS.esc(k)} · <span class="mono small">${PS.esc(v.hf)}</span></b><span class="badge accent">${PS.esc(v.line)}</span></div>` +
          `<div class="small muted" style="margin:6px 0">${PS.esc(v.source)}</div>` +
          `<div class="row" style="gap:7px;margin:8px 0;flex-wrap:wrap"><span class="badge muted">许可 ${PS.esc(v.license)}</span>` +
          (v.paper ? `<span class="badge muted">${PS.esc(v.paper)}</span>` : "") +
          `<span class="badge muted">共 ${v.total}(攻击 ${v.attacks} / 良性 ${v.benign})</span>` +
          `<a href="${PS.esc(v.url)}" target="_blank" rel="noopener" class="badge accent">HuggingFace ↗</a></div>` +
          `<div class="tiny faint" style="margin-top:6px">真实样本(从镜像内缓存直读):</div>${samples}</div>`;
      }).join("");
      PS.modal("公开数据集 · 来源 / 权威性 / 真实样本", html +
        `<div class="callout info">这些数据集随 guard 镜像打包,评测时由<b>同一个引擎实例</b>(即处理真实 /v1/screen 请求的那个)逐条检测,非预录、可溯源。</div>`);
    } catch (e) { PS.toast("加载失败:" + PS.esc(e.message)); }
  },

  async runDatasets() {
    const btn = PS.$("#dsRun"); btn.disabled = true; btn.textContent = "评测中…";
    PS.$("#ds-live").innerHTML = '<div class="skel" style="height:80px"></div>';
    try {
      const r = await PS.post("/benchmark/run?n=" + PS.$("#dsN").value, {});
      this.poll(r.job_id);
    } catch (e) {
      PS.$("#ds-live").innerHTML = '<div class="callout warn">发起失败:' + PS.esc(e.message) + '</div>';
      btn.disabled = false; btn.textContent = "▶ 运行真实评测";
    }
  },

  poll(jobId) {
    clearInterval(this._poll);
    this._poll = setInterval(async () => {
      try {
        const j = await PS.api("/benchmark/status?job_id=" + jobId);
        if (j.status === "done") {
          clearInterval(this._poll);
          const run = await PS.api("/benchmark/result?run_id=" + j.run_id);
          this.renderResult(PS.$("#ds-live"), run, true);
          this.loadHistory();
          PS.toast("评测完成并已存储", "ok");
          const b = PS.$("#dsRun"); b.disabled = false; b.textContent = "▶ 运行真实评测";
        } else {
          this.renderProgress(j);
        }
      } catch (e) {
        clearInterval(this._poll);
        PS.$("#ds-live").innerHTML = '<div class="callout warn">查询状态失败:' + PS.esc(e.message) + '</div>';
        const b = PS.$("#dsRun"); b.disabled = false; b.textContent = "▶ 运行真实评测";
      }
    }, 1200);
  },

  renderProgress(j) {
    const pct = Math.round((j.progress || 0) * 100);
    const done = Math.round((j.progress || 0) * (j.total || 4));
    const partial = (j.partial && Object.keys(j.partial).length) ? _dsTable(j.partial) : "";
    PS.$("#ds-live").innerHTML =
      `<div class="spread"><b class="small">后端任务执行中…</b><span class="small mono faint">job ${j.started || ""}</span></div>` +
      `<div class="meter" style="margin:10px 0"><span style="width:${pct}%"></span></div>` +
      `<div class="small muted">进度 ${pct}% · 已完成 ${done}/${j.total || 4} 个数据集 · 当前:<b>${PS.esc(j.current || "…")}</b></div>` +
      (partial ? `<div style="margin-top:12px"><div class="tiny faint" style="margin-bottom:4px">已完成部分:</div>${partial}</div>` : "");
  },

  renderResult(host, run, fresh) {
    host.innerHTML =
      (fresh ? `<div class="callout ok" style="margin-bottom:12px">✓ 评测完成并<b>已持久化存储</b>(run ${PS.esc(run.run_id)} · ${PS.esc(run.ts)})。</div>` : "") +
      `<div class="spread" style="margin-bottom:8px"><span class="small muted">run <b class="mono">${PS.esc(run.run_id)}</b> · ${PS.esc(run.ts)} · 每集 ${run.n} 条 · ML ${run.ml_enabled ? "开" : "关"}</span></div>` +
      _dsTable(run.datasets) + _explainHtml(run);
  },

  async loadHistory() {
    try {
      const h = await PS.api("/benchmark/history");
      const host = PS.$("#ds-history");
      if (!h.length) { host.innerHTML = '<p class="muted small">暂无历史 —— 运行一次评测后显示。</p>'; return; }
      host.innerHTML = `<div class="panel"><div class="panel-body" style="padding:6px 14px">` + h.map(r =>
        `<div class="row spread" style="padding:9px 0;border-bottom:1px solid var(--line);cursor:pointer" data-run="${r.run_id}">` +
        `<span class="small"><span class="tiny faint mono">${PS.esc(r.ts)}</span> · run <b class="mono">${PS.esc(r.run_id)}</b></span>` +
        `<span class="row"><span class="badge ${r.ml_enabled ? "ok" : "muted"}">${r.ml_enabled ? "ML" : "regex"}</span>` +
        `<span class="small">主线 <b>${PS.pct((r.summary || {}).mainline_recall)}</b></span><span class="tiny faint">每集 ${r.n} · 查看 ›</span></span></div>`).join("") + `</div></div>`;
      if (!host._bound) {
        host._bound = true;
        host.addEventListener("click", async (e) => {
          const row = e.target.closest("[data-run]"); if (!row) return;
          try { const run = await PS.api("/benchmark/result?run_id=" + row.dataset.run); this.renderResult(PS.$("#ds-live"), run, false); window.scrollTo({ top: PS.$("#ds-live").offsetTop - 80, behavior: "smooth" }); }
          catch (err) { PS.toast("加载失败"); }
        });
      }
    } catch (e) {}
  },

  async runLive() {
    const host = PS.$("#bench-live"), btn = PS.$("#benchRun");
    btn.disabled = true; btn.textContent = "评测中…"; host.innerHTML = '<div class="skel" style="height:64px"></div>';
    try {
      const d = await PS.api("/benchmark");
      const m = d.metrics, c = d.confusion;
      const kpi = (l, v, cl) => `<div class="kpi ${cl || ""}"><div class="k-label">${l}</div><div class="k-value">${v}</div></div>`;
      host.innerHTML =
        `<div class="grid cols-4">${kpi("recall", PS.pct(m.recall), "ok")}${kpi("precision", PS.pct(m.precision), "accent")}${kpi("FPR", PS.pct(m.fpr), m.fpr > 0 ? "warn" : "ok")}${kpi("p50 延迟", d.latency_ms.p50 + "ms", "")}</div>` +
        `<div class="row" style="margin:14px 0;gap:10px"><span class="badge ok">TP ${c.TP}</span><span class="badge muted">TN ${c.TN}</span><span class="badge block">FP ${c.FP}</span><span class="badge warn">FN ${c.FN}</span><span class="small muted">共 ${d.totals.samples} 条 · 已记入遥测</span></div>`;
      PS.toast("corpus 实时评测完成", "ok");
    } catch (e) { host.innerHTML = '<p class="badge block">评测失败:' + PS.esc(e.message) + "</p>"; }
    finally { btn.disabled = false; btn.textContent = "▶ 运行"; }
  }
});
