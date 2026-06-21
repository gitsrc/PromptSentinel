/* ============================================================================
   PromptSentinel 门户内核 —— 命名空间 / 路由 / fetch / 工具 / 状态。zero-dep。
   各 section 模块用 PS.view(name, {render}) 注册;PS.boot() 启动。
   ========================================================================== */
(function () {
  const PS = window.PS = window.PS || {};
  PS.views = PS.views || {};

  // —— DOM / 格式化工具 ——
  PS.$ = (s, r) => (r || document).querySelector(s);
  PS.$$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  PS.esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g,
    c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  PS.el = (html) => { const t = document.createElement("template"); t.innerHTML = String(html).trim(); return t.content.firstElementChild; };
  PS.pct = (v) => v == null ? "—" : (v * 100).toFixed(1) + "%";
  PS.fmt = (n) => n == null ? "—" : (typeof n === "number" ? n.toLocaleString() : n);
  PS.cls = (v) => v == null ? "faint" : (v >= 0.7 ? "ok" : (v >= 0.4 ? "warn" : "block"));

  // —— BFF fetch ——
  PS.api = async function (path, opts) {
    const r = await fetch("/api" + path, Object.assign({ headers: { "Content-Type": "application/json" } }, opts || {}));
    if (!r.ok) throw new Error("HTTP " + r.status + " " + (await r.text()).slice(0, 140));
    return r.json();
  };
  PS.post = (path, body) => PS.api(path, { method: "POST", body: JSON.stringify(body || {}) });

  // —— 缓存型加载 ——
  let _eval, _corpus;
  PS.loadEval = async function () { if (!_eval) _eval = await (await fetch("/static/dataset_eval.json")).json(); return _eval; };
  PS.loadCorpus = async function () { if (!_corpus) _corpus = await PS.api("/corpus"); return _corpus; };

  // —— toast ——
  PS.toast = function (msg, kind) {
    const host = PS.$("#toastHost"); if (!host) return;
    const t = PS.el(`<div class="toast"></div>`); t.textContent = msg;
    if (kind === "block") t.style.background = "var(--block)";
    if (kind === "ok") t.style.background = "var(--ok)";
    host.appendChild(t);
    setTimeout(() => { t.style.transition = "opacity .3s"; t.style.opacity = "0"; setTimeout(() => t.remove(), 320); }, 2600);
  };

  // —— 模块注册 / 路由 ——
  PS.view = function (name, def) { PS.views[name] = def; };
  PS.go = function (name) {
    if (!PS.$("#view-" + name)) name = "overview";
    PS.$$(".view").forEach(v => v.classList.toggle("active", v.id === "view-" + name));
    PS.$$("#nav a").forEach(a => a.classList.toggle("active", a.dataset.view === name));
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
    const def = PS.views[name];
    if (def && def.render) Promise.resolve().then(() => def.render()).catch(e => console.error("[" + name + "]", e));
  };

  // —— Guard 状态轮询 ——
  PS.status = {};
  async function pollStatus() {
    const dot = PS.$("#statusDot"), txt = PS.$("#statusText");
    try {
      const s = await PS.api("/status"); PS.status = s;
      const ok = s.guard === "ok";
      const ml = !!(s.health && s.health.ml_classifier);
      dot.className = "dot " + (ok ? "on" : "off");
      txt.textContent = ok ? ("Guard 在线 · " + (ml ? "ML(PG2) 已启用" : "规则档")) : "Guard 不可达";
    } catch (e) { dot.className = "dot off"; txt.textContent = "门户离线"; }
  }

  // —— 复制按钮委托 ——
  document.addEventListener("click", (e) => {
    const c = e.target.closest(".code-copy"); if (!c) return;
    const code = c.parentElement.querySelector("pre, code") || c.parentElement;
    navigator.clipboard && navigator.clipboard.writeText(code.innerText.replace(/复制$/, "")).then(() => PS.toast("已复制", "ok"));
  });

  // reason code → 人话(供 demo / playground 展示"为什么拦/放")
  PS.reasonText = function (r) {
    const map = {
      injection_heuristic: "命中注入 / 越狱 / 套取短语",
      protected_identifier: "命中受保护标识符(内部 ID / schema / 密钥)",
      ml_classifier: "ML 模型判定为注入(语义)",
      llm_guard: "本地 ML 注入扫描命中",
      llm_judge: "LLM 语义裁决判定风险",
      system_prompt_leak: "系统提示词逐字泄露(canary 命中)",
      pii_fallback: "输出含 PII / 密钥",
      pii: "输出含 PII / 密钥",
      engine_error: "引擎异常(fail-closed 拦截)"
    };
    const stage = r.indexOf("untrusted") === 0 ? "不可信内容 · " : (r.indexOf("output") === 0 ? "输出 · " : "输入 · ");
    const ci = r.indexOf(":");
    const body = ci >= 0 ? r.slice(ci + 1) : r;
    const key = body.split("(")[0];
    const m = body.match(/\(([^)]+)\)/);
    let txt = map[key] || key;
    if (m && key.indexOf("protected") >= 0) { const t = (m[1].split(":")[1] || m[1]); txt += "(命中 “" + t + "”)"; }
    else if (m && (key.indexOf("pii") >= 0)) { txt += "(模式 " + m[1] + ")"; }
    return stage + txt;
  };

  // 弹窗(数据集审计等用)
  PS.modal = function (title, html) {
    let host = PS.$("#modalHost");
    if (!host) { host = PS.el('<div id="modalHost"></div>'); document.body.appendChild(host); }
    host.innerHTML = `<div class="modal-mask"><div class="modal"><div class="modal-head"><b>${PS.esc(title)}</b><span class="modal-x">✕</span></div><div class="modal-body">${html}</div></div></div>`;
    const close = () => { host.innerHTML = ""; };
    host.querySelector(".modal-mask").addEventListener("click", (e) => { if (e.target.classList.contains("modal-mask")) close(); });
    host.querySelector(".modal-x").addEventListener("click", close);
  };

  PS.boot = function () {
    PS.$("#nav").addEventListener("click", (e) => { const a = e.target.closest("a[data-view]"); if (a) { e.preventDefault(); PS.go(a.dataset.view); } });
    document.body.addEventListener("click", (e) => { const b = e.target.closest("[data-goto]"); if (b) PS.go(b.dataset.goto); });
    pollStatus(); setInterval(pollStatus, 8000);
    PS.go((location.hash || "#overview").slice(1));
  };
})();
