
function t(key, vars) {
  if (window.CRI18N && typeof window.CRI18N.t === "function") return window.CRI18N.t(key, vars);
  return key;
}

/** UI-only enum presentation. Never mutates Core/session data. */
function severityKind(sev) {
  const s = String(sev || "").toUpperCase().trim();
  if (s === "CONFLICT") return "conflict";
  if (s === "WARNING" || s === "WARN") return "warning";
  if (s === "NO_CONFLICT") return "noconflict";
  if (s.indexOf("CONFLICT") >= 0 && s.indexOf("NO_") < 0 && s.indexOf("NO ") < 0) return "conflict";
  if (s.indexOf("WARN") >= 0) return "warning";
  return "noconflict";
}
function cleanActionText(action) {
  if (!action) return "";
  return String(action).replace(/^\s*ACTION:\s*/i, "").trim();
}
function buildLocalizedExecutive(data) {
  const c = (data && data.core) || {};
  const ux = (data && data.ux) || {};
  const sev = c.severity || "—";
  const kind = severityKind(sev);
  const target =
    (data.request && data.request.decision_text) ||
    c.target_asset_id ||
    t("audit.target.fallback");
  const risk = c.risk_score != null ? c.risk_score : "—";
  const seq = (c.sequence || []).join(" → ") || t("none");
  const summary = t("exec.body.summary", { sev: sev, risk: risk, seq: seq });
  let why;
  if (kind === "conflict") why = t("exec.body.why.conflict", { target: target });
  else if (kind === "warning") why = t("exec.body.why.warning", { target: target });
  else why = t("exec.body.why.noconflict", { target: target });
  let blockers;
  if (kind === "conflict") blockers = t("exec.body.blockers.conflict");
  else if (kind === "warning") blockers = t("exec.body.blockers.warning");
  else blockers = t("exec.body.blockers.none");
  const action = cleanActionText(c.action_rationale) || t("na");
  const next = t("exec.body.next", { action: action });
  return { summary, why, blockers, next, kind, sev, target, risk, seq };
}

function tv(value) {
  if (window.CRI18N && typeof window.CRI18N.translateValue === "function") {
    return window.CRI18N.translateValue(value);
  }
  return value == null || value === "" ? "—" : String(value);
}

function critBadge(value) {
  const cls =
    window.CRI18N && window.CRI18N.criticalityClass
      ? window.CRI18N.criticalityClass(value)
      : "crit-unknown";
  return '<span class="crit-badge ' + cls + '">' + esc(tv(value)) + "</span>";
}


function currentLang() {
  return (window.CRI18N && window.CRI18N.getLang && window.CRI18N.getLang()) || "es";
}

function getPageMeta() {
  return {
    overview: { title: t("page.overview"), sub: t("page.overview.sub") },
    inventory: { title: t("page.inventory"), sub: t("page.inventory.sub") },
    risk: { title: t("page.risk"), sub: t("page.risk.sub") },
    dependencies: { title: t("page.dependencies"), sub: t("page.dependencies.sub") },
    decision: { title: t("page.decision"), sub: t("page.decision.sub") },
    audit: { title: t("page.audit"), sub: t("page.audit.sub") },
  };
}
const PAGE_META = new Proxy({}, { get: (_, k) => getPageMeta()[k] });



function getHelpText(key) {
  const map = {
    overview: "help.overview",
    inventory: "help.inventory",
    risk: "help.risk",
    dependencies: "help.dependencies",
    decision: "help.decision",
    audit: "help.audit",
  };
  return t(map[key] || "help.missing");
}

/* CryptoRisk V4.7 frontend — presentation only. Core decides. */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

function getTitles() {
  return {
    overview: [t("page.overview"), t("page.overview.sub")],
    inventory: [t("page.inventory"), t("page.inventory.sub")],
    risk: [t("page.risk"), t("page.risk.sub")],
    dependencies: [t("page.dependencies"), t("page.dependencies.sub")],
    decision: [t("page.decision"), t("page.decision.sub")],
    audit: [t("page.audit"), t("page.audit.sub")],
  };
}
const TITLES = new Proxy({}, { get: (_, k) => getTitles()[k] });



let state = {
  inventory: null,
  health: null,
  lastDecision: null,
  sortKey: "asset_id",
  sortDir: 1,
};

function resetClientSession() {
  state.inventory = null;
  state.lastDecision = null;
  state.lastStress = null;
  // Clear chart roots
  ["#charts-root", "#risk-charts", "#dep-charts", "#decision-charts"].forEach((sel) => {
    const el = $(sel);
    if (el) el.innerHTML = "";
  });
  const empty = $("#charts-empty");
  if (empty) empty.classList.remove("hidden");
  // Clear tables
  const rt = $("#risk-table tbody");
  if (rt) rt.innerHTML = "";
  const it = $("#inv-table tbody");
  if (it) it.innerHTML = "";
  const im = $("#inv-meta");
  if (im) im.textContent = t("status.no_inventory");
  const dep = $("#dep-out");
  if (dep) dep.textContent = "" + t("deps.load") + "";
  const report = $("#ov-report-out");
  if (report) report.textContent = t("status.not_available_until");
  // Overview counters
  const ot = $("#ov-total");
  if (ot) ot.textContent = "0";
  const oh = $("#ov-high");
  if (oh) oh.textContent = "—";
  const os = $("#ov-source");
  if (os) os.textContent = t("status.nodata");
  ["#kpi-total", "#kpi-critical", "#kpi-attention", "#kpi-toprisk"].forEach((id) => {
    const el = $(id);
    if (el) el.textContent = "—";
  });
  // Empty banners
  const oe = $("#overview-empty");
  const ol = $("#overview-loaded");
  if (oe) oe.classList.remove("hidden");
  if (ol) ol.classList.add("hidden");
  renderCoreEmpty();
  renderDecisionChartsFromLast(null);
  const audit = $("#audit-out");
  if (audit) {
    audit.innerHTML =
      '<div class="empty-state"><strong>' + t("empty.audit") + '</strong><p>' + t("empty.audit.hint") + '</p></div>';
  }
  // Reset file inputs so change fires again for same path
  ["#ov-upload", "#inv-upload", "#welcome-upload"].forEach((sel) => {
    const el = $(sel);
    if (el) el.value = "";
  });
}


async function api(path, opts = {}) {
  const r = await fetch(path, {
    headers: { Accept: "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const ct = r.headers.get("content-type") || "";
  const body = ct.includes("application/json") ? await r.json() : await r.text();
  if (!r.ok) {
    const msg = typeof body === "object" ? JSON.stringify(body) : body;
    throw new Error(msg || r.statusText);
  }
  return body;
}

function showView(name) {
  const meta = PAGE_META[name];
  if (meta) {
    const pt = $("#page-title");
    const ps = $("#page-sub");
    if (pt) pt.textContent = meta.title;
    if (ps) ps.textContent = meta.sub;
  }

  $$(".view").forEach((v) => v.classList.remove("active"));
  $$(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  const el = $(`#view-${name}`);
  if (el) el.classList.add("active");
  const t = TITLES[name] || [name, ""];
  $("#page-title").textContent = t[0];
  $("#page-sub").textContent = t[1];
  if (name === "risk") { renderRisk(); renderRiskCharts(); }
  if (name === "overview") renderOverviewCharts();
  if (name === "dependencies") { renderDeps(); renderDepCharts(); }
  if (name === "decision") {
    fillAssetSelect();
    if (state.lastStress) renderDecisionChartsFromLast(state.lastStress);
  }
  if (name === "audit") {
    renderAuditPanel(state.lastDecision || state.lastStress || null);
  }
  /* tournament UI disabled */
}

function setMsg(el, text, ok) {
  if (!el) return;
  el.textContent = text || "";
  el.className = "msg " + (ok === true ? "ok" : ok === false ? "error" : "");
  el.style.whiteSpace = "pre-wrap";
  el.style.display = "block";
}

async function refreshInventoryCharts() {
  await renderOverviewCharts();
  const active = document.querySelector(".view.active");
  if (active && active.id === "view-risk") await renderRiskCharts();
  if (active && active.id === "view-dependencies") await renderDepCharts();
}

async function refreshHealth() {
  try {
    state.health = await api("/api/health");
    const h = state.health;
    const prov = h.ai_provider_label || (h.ai_provider_status === "nvidia_configured" ? "NVIDIA" : "FALLBACK");
    $("#topbar-status").innerHTML = `Core <strong>ABSOLUTE</strong> · AI <strong>NONE</strong> · Provider <strong>${prov}</strong>`;
    $("#ov-ai").textContent = "NONE";
    $("#ov-provider").textContent = prov;
    $("#ov-sha").textContent = h.core_package_sha || "—";
  } catch (e) {
    $("#topbar-status").textContent = t("status.health_unavailable");
  }
}

async function refreshInventory() {
  const inv = await api("/api/inventory");
  state.inventory = inv;
  const n = (inv.assets && inv.assets.length) || Number(inv.asset_count) || 0;
  const loaded = n > 0;
  const oe = $("#overview-empty");
  const ol = $("#overview-loaded");
  if (oe) oe.classList.toggle("hidden", loaded);
  if (ol) ol.classList.toggle("hidden", !loaded);
  const ot = $("#ov-total");
  const os = $("#ov-source");
  if (loaded) {
    const kind =
      inv.status === "DEMO_DATASET" || inv.dataset_kind === "demo"
        ? t("status.demo")
        : inv.status === "UPLOADED_DATASET" || inv.dataset_kind === "uploaded"
          ? t("status.uploaded")
          : t("status.loaded");
    if (os) os.textContent = kind + " · " + (inv.source || "loaded");
    if (ot) ot.textContent = String(n);
    try {
      const dash = await api("/api/dashboard");
      const oh = $("#ov-high"); if (oh) oh.textContent = String(dash.high_risk_assets ?? "—");
    } catch (_) {
      const oh2 = $("#ov-high"); if (oh2) oh2.textContent = "—";
    }
  } else {
    if (os) os.textContent = t("status.nodata");
    if (ot) ot.textContent = "0";
    const oh = $("#ov-high"); if (oh) oh.textContent = "—";
  }
  renderInventoryTable();
  fillAssetSelect();
}

function renderInventoryTable() {
  const tbody = $("#inv-table tbody");
  const inv = state.inventory;
  if (!inv || !inv.assets || !inv.assets.length) {
    const meta = $("#inv-meta");
    if (meta) meta.textContent = t("inv.meta.empty");
    if (tbody) tbody.innerHTML = "";
    return;
  }
  const searchEl = $("#inv-search");
  const q = ((searchEl && searchEl.value) || "").toLowerCase();
  let rows = inv.assets.slice();
  if (q) {
    rows = rows.filter(
      (a) =>
        (a.asset_id || "").toLowerCase().includes(q) ||
        (a.name || "").toLowerCase().includes(q) ||
        (a.algorithm || "").toLowerCase().includes(q)
    );
  }
  const kindLabel =
    inv.dataset_kind === "demo"
      ? t("status.demo")
      : inv.dataset_kind === "uploaded"
        ? t("status.uploaded")
        : "DATASET";
  const meta = $("#inv-meta");
  if (meta) {
    meta.textContent = t("inv.meta.count", {
      kind: kindLabel,
      source: inv.source || "—",
      n: rows.length,
    });
  }
  if (!tbody) return;
  tbody.innerHTML = rows
    .map((a) => {
      const exposed = a.internet_exposed === true || a.internet_exposed === "true" || a.internet_exposed === "yes" || a.internet_exposed === 1;
      return `<tr data-asset="${esc(a.asset_id)}">
      <td><strong>${esc(a.asset_id)}</strong><br><span class="muted">${esc(a.name || "")}</span></td>
      <td>${esc(a.algorithm)}${a.key_size != null && a.key_size !== "" ? " " + esc(a.key_size) : ""}</td>
      <td>${critBadge(a.criticality)}</td>
      <td>${esc(tv(exposed ? "yes" : "no"))}</td>
      <td>${esc(tv(a.migration_status || "not_started"))}</td>
      <td>${a.risk != null ? a.risk : "—"}</td>
      <td class="mono">${esc((a.dependencies || []).join(", ") || "—")}</td>
    </tr>`;
    })
    .join("");
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatUploadFailure(j) {
  const detail = j && j.detail !== undefined ? j.detail : j;
  if (!detail || typeof detail !== "object") {
    return t("msg.upload_failed") + "\n" + String(detail || t("msg.unknown_error"));
  }
  let lines = [t("msg.upload_failed"), detail.message || detail.status || t("msg.invalid_csv")];
  const errs = detail.errors || [];
  const valid = detail.valid_criticality;
  if (valid && valid.length) {
    lines.push(t("msg.valid_crit") + valid.join(", "));
  }
  errs.slice(0, 8).forEach((e) => {
    if (typeof e === "string") {
      lines.push(e);
      return;
    }
    const parts = [];
    if (e.row != null) parts.push("Row: " + e.row);
    if (e.field) parts.push("Field: " + e.field);
    if (e.value != null && e.value !== "") parts.push("Value: " + e.value);
    if (e.expected && e.expected.length) parts.push("Expected: " + e.expected.join("|"));
    if (parts.length) lines.push(parts.join(" · "));
    else if (e.message) lines.push(e.message);
  });
  const prev = detail.previous_dataset;
  if (prev && prev.assets > 0) {
    lines.push(
      t("msg.prev_active") +
        (prev.dataset_kind || "") +
        " · " +
        (prev.source || "") +
        " (" +
        prev.assets +
        " assets)"
    );
  } else {
    lines.push(t("status.active_none"));
  }
  return lines.join("\n");
}

async function uploadFile(file, msgEl) {
  if (!file) return;
  const fd = new FormData();
  fd.append("file", file);
  try {
    const r = await fetch("/api/inventory/upload", { method: "POST", body: fd });
    let j = null;
    try {
      j = await r.json();
    } catch (_) {
      j = null;
    }
    if (!r.ok) {
      const detail = (j && j.detail) || j || {};
      if (detail.status === "REVIEW_REQUIRED" || (j && j.status === "REVIEW_REQUIRED")) {
        const payload = detail.status === "REVIEW_REQUIRED" ? detail : j;
        const n = Number(payload.asset_count != null ? payload.asset_count : payload.valid_count || 0);
        if (Number.isFinite(n) && n > 0) {
          // Partial load may still have occurred — resync inventory
          await refreshInventory();
          await refreshInventoryCharts();
        }
        showImportReview(payload);
        setMsg(
          msgEl,
          t("msg.review") +
            " · " +
            (payload.source || file.name) +
            " · valid " +
            (payload.valid_count != null ? payload.valid_count : "0") +
            " · " +
            t("msg.attention") +
            " " +
            (payload.attention_count != null ? payload.attention_count : "0"),
          false
        );
        return;
      }
      setMsg(msgEl, formatUploadFailure(j || { detail: r.statusText }), false);
      await refreshInventory();
      return;
    }
    hideImportReview();
    const nAssets = Number(j.asset_count != null ? j.asset_count : j.assets);
    const safeN = Number.isFinite(nAssets) ? nAssets : 0;
    if (safeN <= 0) {
      setMsg(msgEl, t("msg.upload.zero"), false);
      await refreshInventory();
      return;
    }
    let msg =
      t("msg.upload.ok") +
      " · " +
      (j.source || file.name) +
      " · " +
      (j.format ? String(j.format).toUpperCase() + " · " : "") +
      safeN +
      " " +
      t("msg.assets");
    if (j.attention_count) msg += " · " + j.attention_count + " " + t("msg.attention");
    setMsg(msgEl, msg, true);
    // Full client resync for replacement (A→B must drop A completely)
    state.lastDecision = null;
    state.lastStress = null;
    renderCoreEmpty();
    renderDecisionChartsFromLast(null);
    await refreshInventory();
    await refreshInventoryCharts();
    await refreshHealth();
    // Allow re-selecting the same file path later
    try {
      if (msgEl && msgEl.closest) {
        /* no-op */
      }
    } catch (_) {}
    ["#ov-upload", "#inv-upload", "#welcome-upload"].forEach((sel) => {
      const el = $(sel);
      if (el) el.value = "";
    });
  } catch (e) {
    setMsg(msgEl, t("msg.upload.fail") + "\n" + (e.message || String(e)), false);
    await refreshInventory();
  }
}

async function loadDemo(msgEl) {
  try {
    const j = await api("/api/inventory/load-demo", { method: "POST" });
    setMsg(msgEl, t("msg.demo") + " (" + j.assets + " " + t("msg.assets") + ") — " + t("msg.demo.note"), true);
    state.lastDecision = null;
    renderCoreEmpty();
    await refreshInventory();
    await refreshInventoryCharts();
  } catch (e) {
    setMsg(msgEl, e.message || String(e), false);
  }
}

async function clearInv(msgEl) {
  try {
    const j = await api("/api/inventory/clear", { method: "POST" });
    resetClientSession();
    await refreshInventory();
    await refreshInventoryCharts();
    await refreshHealth();
    const n = j && (j.asset_count != null ? j.asset_count : j.assets);
    if (n != null && Number(n) !== 0) {
      setMsg(msgEl, t("msg.clear.fail"), false);
      return;
    }
    setMsg(msgEl, t("msg.cleared"), true);
  } catch (e) {
    setMsg(msgEl, e.message || String(e), false);
  }
}

async function renderRisk() {
  const tbody = $("#risk-table tbody");
  try {
    const data = await api("/api/risk");
    const rd = $("#risk-disclaimer");
    if (rd) rd.textContent = data.disclaimer || t("risk.disclaimer.short");
    if (data.empty) {
      $("#risk-empty").classList.remove("hidden");
      tbody.innerHTML = "";
      return;
    }
    $("#risk-empty").classList.add("hidden");
    tbody.innerHTML = data.assets
      .map((a) => {
        const f = a.risk_factors || {};
        return `<tr>
          <td><strong>${esc(a.asset_id)}</strong></td>
          <td><strong>${a.risk != null ? a.risk : "—"}</strong></td>
          <td>${f.algorithm != null ? f.algorithm : "—"}</td>
          <td>${f.exposure != null ? f.exposure : "—"}</td>
          <td>${f.criticality != null ? critBadge(f.criticality) : "—"}</td>
          <td>${f.data_lifetime != null ? f.data_lifetime : "—"}</td>
          <td>${f.dependencies != null ? f.dependencies : "—"}</td>
          <td>${esc(a.algorithm)}</td>
        </tr>`;
      })
      .join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8">${esc(e.message)}</td></tr>`;
  }
}

async function renderDeps() {
  const box = $("#dep-out") || $("#dep-list");
  if (!box) return;
  try {
    const g = await api("/api/graph");
    if (!g.nodes || !g.nodes.length) {
      const empty = $("#dep-empty");
      if (empty) empty.classList.remove("hidden");
      box.textContent = t("deps.none");
      return;
    }
    const empty = $("#dep-empty");
    if (empty) empty.classList.add("hidden");
    const byTo = {};
    (g.edges || []).forEach((e) => {
      byTo[e.to] = byTo[e.to] || [];
      byTo[e.to].push(e);
    });
    const lines = g.nodes.map((n) => {
      const deps = byTo[n.id] || [];
      if (!deps.length) return n.id + " (" + n.status + "): no prerequisites declared";
      return (
        n.id +
        " (" +
        n.status +
        "):\n  " +
        deps
          .map((d) =>
            d.missing
              ? d.from + " → " + d.to + " · MISSING DEPENDENCY"
              : d.from + " → " + d.to
          )
          .join("\n  ")
      );
    });
    box.textContent = lines.join("\n\n");
  } catch (e) {
    box.textContent = String(e.message || e);
  }
}

function fillAssetSelect() {
  const sel = $("#dec-asset");
  if (!sel) return;
  const assets = (state.inventory && state.inventory.assets) || [];
  sel.innerHTML = assets.map((a) => `<option value="${esc(a.asset_id)}">${esc(a.asset_id)}</option>`).join("");
}

function renderCoreEmpty() {
  const set = (id, html) => { const el = $(id); if (el) el.innerHTML = html; };
  set("#core-out", `<div class="empty-state"><strong>${t("empty.decision")}</strong><p>${t("empty.decision.hint")}</p></div>`);
  set("#ai-out", `<div class="empty-state"><strong>${t("empty.ai")}</strong><p>${t("empty.ai.hint")}</p></div>`);
  const badge = $("#ai-provider-badge");
  if (badge) badge.textContent = t("provider.empty");
  set("#audit-out", `<div class="empty-state"><strong>${t("empty.audit")}</strong><p>${t("empty.audit.hint.short")}</p></div>`);
}


function buildAuditNarrative(data, inv) {
  const c = (data && data.core) || {};
  const ux = (data && data.ux) || {};
  const assets = (inv && inv.assets) || [];
  const n = assets.length;
  const source = (inv && (inv.source || inv.source_name)) || t("active.inventory");
  const sevRaw = c.severity || "—";
  const sev = String(sevRaw).toUpperCase();
  const risk = c.risk_score != null ? c.risk_score : "—";
  const target =
    (data.request && data.request.decision_text) ||
    c.target_asset_id ||
    t("audit.target.fallback");
  const seq = (c.sequence || []).join(" → ") || t("none");
  const policies = (c.policies_triggered || []).join(", ") || t("none");
  const blocked = ux.blocked ? t("yes") : t("no");

  const crit = { critical: 0, high: 0, medium: 0, low: 0 };
  assets.forEach((a) => {
    const k = String(a.criticality || "").toLowerCase();
    if (k in crit) crit[k] += 1;
  });

  const findings = [];
  findings.push({
    title: t("chip.sev.title"),
    text: t("audit.find.sev", { sev: sevRaw, blocked: blocked }),
    evidence: t("audit.ev.sev"),
  });
  if (c.risk_score != null) {
    findings.push({
      title: t("chip.risk.title"),
      text: t("audit.find.risk", { risk: c.risk_score }),
      evidence: "core.risk_score",
    });
  }
  if ((c.sequence || []).length) {
    findings.push({
      title: t("chip.seq.title"),
      text: t("audit.find.seq", { seq: seq }),
      evidence: "core.sequence",
    });
  } else {
    findings.push({
      title: t("chip.seq.none"),
      text: t("audit.find.seq.empty"),
      evidence: "core.sequence empty",
    });
  }
  if ((c.policies_triggered || []).length) {
    findings.push({
      title: t("chip.pol.title"),
      text: t("audit.find.pol", { policies: policies }),
      evidence: "core.policies_triggered",
    });
  }
  findings.push({
    title: t("chip.scope.title"),
    text: t("audit.find.scope", {
      n: n,
      source: source,
      critical: crit.critical,
      high: crit.high,
      medium: crit.medium,
      low: crit.low,
    }),
    evidence: t("audit.ev.session"),
  });

  let why;
  if (sev === "CONFLICT") {
    why = t("audit.why.conflict");
  } else if (sev === "WARNING") {
    why = t("audit.why.warning");
  } else if (sev === "NO_CONFLICT") {
    why = t("audit.why.noconflict");
  } else {
    why = t("audit.why.generic");
  }

  let priority;
  if (c.sequence && c.sequence.length) {
    priority = t("audit.priority.head", { head: c.sequence[0] });
  } else {
    priority = t("audit.priority.asset");
  }
  if (c.action_rationale) {
    // Strip duplicated "ACTION:" prefixes from Core text for cleaner UI presentation
    let action = String(c.action_rationale).replace(/^\s*ACTION:\s*/i, "").trim();
    priority += " " + t("audit.priority.action", { action: action });
  }

  return {
    analyzed: t("audit.analyzed", { n: n, source: source, target: target }),
    findings: findings.slice(0, 5),
    why: why,
    priority: priority,
    evidence: [
      "severity=" + sevRaw,
      "risk_score=" + risk,
      "policies=" + policies,
      "sequence=" + seq,
      "inventory_assets=" + n,
    ],
  };
}


function renderAuditPanel(data) {
  const root = $("#audit-out");
  if (!root) return;
  if (!data || !data.core) {
    root.innerHTML =
      '<div class="empty-state"><strong>' + t("empty.audit") + '</strong><p>' + t("empty.audit.hint") + '</p></div>';
    return;
  }
  const audit = data.audit || {};
  const c = data.core || {};
  const ux = data.ux || {};
  const sev = c.severity || "—";
  const seq = (ux.sequence_display || [])
    .map((s) => (s.kind === "MISSING" ? s.label : s.id))
    .join(" → ") || (c.sequence || []).join(" → ") || "—";
  const prov = data.ai_provider || "—";
  const narr = buildAuditNarrative(data, state.inventory || {});
  const findingsHtml = (narr.findings || [])
    .map(
      (f) =>
        '<div class="insight-box" style="margin-top:0.55rem"><h5>' +
        esc(f.title) +
        "</h5><p>" +
        esc(f.text) +
        '</p><p class="muted">' + t("audit.evidence_label") + ' ' +
        esc(f.evidence) +
        "</p></div>"
    )
    .join("");
  const ai = data.ai_explanation || {};
  const aiParts = [ai.contrast, ai.alternative, ai.summary].filter(Boolean);
  let providerBlock = "";
  if (data.request && data.request.ai_mode === "off") {
    providerBlock =
      '<p class="muted">' + t("audit.ai.off") + '</p>';
  } else if (aiParts.length) {
    providerBlock =
      '<p class="muted">' + t("audit.provider.external") + '</p>' +
      "<p><strong>" +
      t("audit.provider.label", { p: prov }) +
      "</strong></p>" +
      aiParts.map((p) => '<p class="ai-provider-evidence">' + esc(p) + "</p>").join("");
  } else {
    providerBlock =
      '<p class="muted">' + t("audit.provider.none", { p: prov }) + "</p>";
  }

  root.innerHTML =
    '<div class="panel">' +
    "<h3>" + t("audit.panel.title") + "</h3>" +
    '<dl class="kv">' +
    "<dt>" + t("audit.decision_id") + "</dt><dd class=\"mono\">" +
    esc(audit.decision_id || "—") +
    "</dd>" +
    "<dt>" + t("audit.timestamp") + "</dt><dd>" +
    esc(audit.timestamp_utc || "—") +
    "</dd>" +
    "<dt>" + t("audit.core_auth") + "</dt><dd>" +
    esc(audit.core_authority || "ABSOLUTE") +
    "</dd>" +
    "<dt>" + t("audit.ai_auth") + "</dt><dd>" +
    esc(audit.ai_authority || "NONE") +
    "</dd>" +
    "<dt>" + t("audit.policy_set") + "</dt><dd>" +
    esc(audit.policy_set_id || "—") +
    " " +
    esc(audit.policy_set_version || "") +
    "</dd>" +
    "<dt>" + t("audit.severity") + "</dt><dd>" +
    esc(sev) +
    "</dd>" +
    "<dt>" + t("audit.sequence") + "</dt><dd class=\"mono\">" +
    esc(seq) +
    "</dd>" +
    "<dt>" + t("audit.ai_provider") + "</dt><dd>" +
    esc(prov) +
    "</dd>" +
    "<dt>" + t("audit.inv_source") + "</dt><dd>" +
    esc((state.inventory && state.inventory.source) || "—") +
    "</dd>" +
    "</dl>" +
    "<h3 style=\"margin-top:1.25rem\">" + t("audit.ai_panel") + "</h3>" +
    providerBlock +
    '<div class="insight-box"><h5>' + t("audit.h1") + '</h5><p>' +
    esc(narr.analyzed) +
    "</p></div>" +
    '<h5 style="margin:0.85rem 0 0.35rem;color:#c4b5fd">' + t("audit.h2") + '</h5>' +
    findingsHtml +
    '<div class="insight-box"><h5>' + t("audit.h3") + '</h5><p>' +
    esc(narr.why) +
    "</p></div>" +
    '<div class="insight-box"><h5>' + t("audit.h4") + '</h5><p>' +
    esc(narr.priority) +
    "</p></div>" +
    '<div class="insight-box"><h5>' + t("audit.h5") + '</h5><p>' +
    esc((narr.evidence || []).join(" · ")) +
    "</p></div>" +
    '<p class="muted" style="margin-top:0.75rem">' + t("audit.disclaimer") + '</p>' +
    "</div>";
}


function renderDecision(data) {
  state.lastDecision = data;
  state.lastStress = data;
  const c = (data && data.core) || {};
  const ux = (data && data.ux) || {};
  const sev = c.severity || "—";
  const kind = severityKind(sev);
  const seq = (ux.sequence_display || [])
    .map((s) => (s.kind === "MISSING" ? s.label : s.id))
    .join(" → ") || (c.sequence || []).join(" → ") || "—";
  const pols = (c.policies_triggered || []).join(", ") || "—";
  const blockedLabel = ux.blocked
    ? " · <strong>" + t("dec.blocked") + "</strong>"
    : " · <span class='muted'>" + t("dec.not_blocked") + "</span>";
  const actionClean = cleanActionText(c.action_rationale) || "—";
  const riskDisc = c.risk_disclaimer
    ? t("dec.risk.disclaimer")
    : t("dec.risk.disclaimer");

  if ($("#core-out")) $("#core-out").innerHTML = `
    <div><span class="sev ${esc(sev)}">${esc(sev)}</span>${blockedLabel}</div>
    <p><strong>${t("dec.label")}:</strong> ${esc(c.label || "—")}</p>
    <p><strong>${t("dec.risk")}:</strong> ${c.risk_score != null ? c.risk_score : "—"}
      <span class="muted"> — ${esc(riskDisc)}</span></p>
    <p><strong>${t("dec.policies")}:</strong> ${esc(pols)}</p>
    <div class="seq"><strong>${t("seq.label")}:</strong> ${esc(seq || (ux.valid_sequence === "NONE" ? t("seq.none") : "—"))}</div>
    <p><strong>${t("label.action")}:</strong> ${esc(actionClean)}</p>
    <p class="muted">${t("audit.core_auth")}: ${esc(c.core_authority || "ABSOLUTE")} · ${t("audit.ai_auth")}: ${esc(c.ai_authority || "NONE")}</p>
  `;

  const prov = data.ai_provider || "—";
  const badge = $("#ai-provider-badge");
  if (badge) badge.textContent = t("provider.line", { p: prov });

  const loc = buildLocalizedExecutive(data);
  const coreHtml = humanCoreSummary(data.core, data.ux);

  const ai = data.ai_explanation || {};
  const parts = [ai.contrast, ai.alternative, ai.summary].filter(Boolean);

  // Always show localized executive narrative (presentation layer)
  let html = "";
  html += `<p><strong>${t("exec.summary")}</strong><br>${esc(loc.summary)}</p>`;
  html += `<p><strong>${t("exec.why")}</strong><br>${esc(loc.why)}</p>`;
  html += `<p><strong>${t("exec.blockers")}</strong></p><ul><li>${esc(loc.blockers)}</li></ul>`;
  html += `<p><strong>${t("exec.next")}</strong><br>${esc(loc.next)}</p>`;

  if (data.request && data.request.ai_mode === "off") {
    html += `<p class="muted">${t("audit.ai.off")}</p>`;
  } else if (parts.length) {
    html += `<p class="muted">${t("audit.provider.external")}</p>`;
    html += `<p><strong>${t("audit.provider.label", { p: prov })}</strong></p>`;
    html += parts.map((p) => `<p class="ai-provider-evidence">${esc(p)}</p>`).join("");
  } else if (data.request && data.request.ai_mode !== "off") {
    html += `<p class="muted">${t("audit.provider.none", { p: prov })}</p>`;
  }
  html += `<p class="muted">${t("audit.ai.none")}</p>`;
  if ($("#ai-out")) $("#ai-out").innerHTML = html;

  renderDecisionChartsFromLast(data);
  renderAuditPanel(data);
}



async function runStress() {
  const asset_id = $("#dec-asset").value;
  const ai_mode = $("#dec-ai").value;
  if (!asset_id) {
    setMsg($("#dec-msg"), t("dec.load.select"), false);
    return;
  }
  try {
    const data = await api("/api/stress-test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ asset_id, ai_mode }),
    });
    renderDecision(data);
    setMsg($("#dec-msg"), t("dec.core.produced"), true);
  } catch (e) {
    setMsg($("#dec-msg"), e.message || String(e), false);
  }
}

async function runCompare() {
  const asset_id = $("#dec-asset").value;
  if (!asset_id) {
    setMsg($("#dec-msg"), t("dec.select.asset"), false);
    return;
  }
  try {
    const r = await api("/api/stress-test/compare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ asset_id }),
    });
    const prov = r.providers || {};
    $("#compare-out").innerHTML = `
      <p><strong>Parity:</strong> ${r.parity ? "YES — Core outcomes identical" : "NO — investigate"}</p>
      <p><strong>AI authority:</strong> ${esc(r.ai_authority)} · <strong>Core:</strong> ${esc(r.core_authority)}</p>
      <p><strong>Providers:</strong> OFF=${esc(prov.off)} · ON=${esc(prov.on)} · ADV=${esc(prov.adversarial)}</p>
      <pre class="code-block">${esc(JSON.stringify(r.core_keys, null, 2))}</pre>`;
    if (r.on) renderDecision({ ...r.on, ai_provider: prov.on });
    setMsg($("#dec-msg"), r.parity ? t("dec.boundary.ok") : t("dec.parity.fail"), r.parity);
  } catch (e) {
    setMsg($("#dec-msg"), e.message || String(e), false);
  }
}

/* Tournament (unchanged server contract) */
async function refreshTournament() {
  try {
    const tournaments = await api("/api/t/tournaments");
    const t = (tournaments.tournaments || tournaments || [])[0];
    if (!t) {
      if ($("#t-case")) $("#t-case").textContent = t("tournament.none");
      return;
    }
    const tid = t.id || t.tournament_id;
    const rounds = t.rounds || [];
    const rid = rounds[0]?.id || rounds[0]?.round_id;
    let caseText = JSON.stringify(t, null, 2);
    if (rid) {
      try {
        const cases = await api(`/api/t/rounds/${rid}/cases`);
        const c0 = (cases.cases || cases || [])[0];
        if (c0) {
          const cid = c0.id || c0.case_id;
          const full = await api(`/api/t/cases/${cid}`);
          caseText = JSON.stringify(full, null, 2);
        }
      } catch (_) {}
      try {
        const board = await api(`/api/t/leaderboards/${rid}`);
        $("#t-board").textContent = JSON.stringify(board, null, 2);
      } catch (_) {
        $("#t-board").textContent = "—";
      }
    }
    $("#t-case").textContent = caseText;
  } catch (e) {
    $("#t-case").textContent = e.message || String(e);
  }
}

async function registerParticipant() {
  try {
    const r = await api("/api/t/participants", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ display_name: "operator-" + Date.now() }),
    });
    const part = r.participant || r;
    const token = part.access_token || r.access_token || "";
    const pid = part.participant_id || r.participant_id || "";
    $("#t-token").value = token;
    setMsg(
      $("#t-token-box"),
      "Joined tournament as " + pid + ".\n" +
        "Tournament access code (keep private):\n" + token + "\n" +
        "This code authorizes your submission. It is not shown again if you leave this page.",
      true
    );
  } catch (e) {
    setMsg($("#t-token-box"), e.message || String(e), false);
  }
}

async function submitTournament() {
  try {
    const token = $("#t-token").value.trim();
    const body = JSON.parse($("#t-body").value);
    const r = await fetch("/api/t/submissions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token,
      },
      body: JSON.stringify(body),
    });
    const j = await r.json();
    $("#t-result").textContent = JSON.stringify(j, null, 2);
    if (!r.ok) throw new Error(JSON.stringify(j));
  } catch (e) {
    $("#t-result").textContent = e.message || String(e);
  }
}

async function loadExecutiveReport() {
  try {
    const r = await api("/api/executive-report");
    $("#ov-report-out").textContent = JSON.stringify(r, null, 2);
  } catch (e) {
    $("#ov-report-out").textContent = e.message || String(e);
  }
}


function showImportReview(payload) {
  const box = $("#import-review");
  if (!box) return;
  box.classList.remove("hidden");
  const meta = $("#import-review-meta");
  if (meta) {
    meta.textContent =
      (payload.source || "") +
      " · " +
      (payload.format || "") +
      " · valid " +
      (payload.valid_count ?? "—") +
      " · attention " +
      (payload.attention_count ?? "—");
  }
  const body = $("#import-review-body");
  if (body) {
    const rows = payload.rows || [];
    body.textContent = rows
      .slice(0, 20)
      .map((r) => (r.asset_id || "?") + " | " + (r.algorithm || "") + " | " + tv(r.criticality || "") + " | " + tv(r._status || r.migration_status || ""))
      .join("\n");
  }
}
function hideImportReview() {
  const box = $("#import-review");
  if (box) box.classList.add("hidden");
}
async function confirmImport() {
  try {
    const j = await api("/api/inventory/confirm-import", { method: "POST" });
    hideImportReview();
    setMsg($("#ov-upload-msg"), t("msg.uploaded_dataset", { source: j.source || "", n: j.assets }), true);
    state.lastDecision = null;
    renderCoreEmpty();
    await refreshInventory();
    await refreshInventoryCharts();
  } catch (e) {
    setMsg($("#ov-upload-msg"), t("msg.confirm.fail") + "\n" + (e.message || String(e)), false);
  }
}
async function cancelImport() {
  try {
    await api("/api/inventory/cancel-import", { method: "POST" });
  } catch (_) {}
  hideImportReview();
  setMsg($("#ov-upload-msg"), t("msg.import.cancelled"), true);
}

function on(id, event, handler) {
  const el = typeof id === "string" ? $(id) : id;
  if (!el) return;
  el.addEventListener(event, handler);
}

function bind() {
  try {
  $$(".nav-btn").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
  $$("[data-goto]").forEach((b) =>
    b.addEventListener("click", () => showView(b.dataset.goto))
  );
  on("#ov-upload", "change", (e) => uploadFile(e.target.files[0], $("#ov-upload-msg")));
  on("#inv-upload", "change", (e) => uploadFile(e.target.files[0], $("#inv-msg")));
  on("#ov-demo", "click", () => loadDemo($("#ov-upload-msg")));
  on("#inv-demo", "click", () => loadDemo($("#inv-msg")));
  on("#inv-clear", "click", () => clearInv($("#inv-msg")));
  on("#ov-clear", "click", () => clearInv($("#ov-upload-msg")));
  on("#inv-search", "input", renderInventoryTable);
  on("#dec-run", "click", runStress);
  on("#dec-compare", "click", runCompare);
  /* tournament UI disabled: t-refresh */
  /* tournament UI removed */
  /* tournament UI disabled: t-submit */
  on("#import-confirm", "click", confirmImport);
  on("#import-cancel", "click", cancelImport);
  const tb = $("#btn-tutorial");
  if (tb) tb.addEventListener("click", openTutorial);
  const tbt = $("#btn-tutorial-top");
  if (tbt) tbt.addEventListener("click", openTutorial);
  const tc = $("#tutorial-close");
  if (tc) tc.addEventListener("click", closeTutorial);
  const tn = $("#tutorial-next");
  if (tn) tn.addEventListener("click", tutorialNext);
  const tp = $("#tutorial-prev");
  if (tp) tp.addEventListener("click", tutorialPrev);
  const wu = $("#welcome-upload");
  if (wu) wu.addEventListener("change", (e) => uploadFile(e.target.files[0], $("#ov-upload-msg")));
  const wdemo = $("#welcome-demo");
  if (wdemo) wdemo.addEventListener("click", () => loadDemo($("#ov-upload-msg")));
  const whowto = $("#welcome-howto");
  if (whowto) whowto.addEventListener("click", openTutorial);

  const modal = $("#tutorial-modal");
  if (modal) modal.addEventListener("click", (e) => { if (e.target === modal) closeTutorial(); });
  $$(".help-btn").forEach((b) => b.addEventListener("click", (e) => showHelp(b.dataset.help, b)));
  const wd = $("#welcome-dismiss");
  if (wd) wd.addEventListener("click", () => {
    try { localStorage.setItem("cryptorisk_welcome_dismissed", "1"); } catch (_) {}
    const w = $("#welcome-banner");
    if (w) w.classList.add("hidden");
  });

  const rb = $("#ov-report");
  if (rb) rb.addEventListener("click", loadExecutiveReport);

  const tbod = $("#t-body");
  if (tbod) tbod.value = JSON.stringify(
    {
      case_id: "case-v0-payment-migration",
      priority_assets: ["demo-pki", "demo-pki-int", "demo-identity", "demo-sso", "demo-payment"],
      target_assessments: [
        { asset_id: "demo-payment", label: "CONFLICT" },
        { asset_id: "demo-legacy-ftp", label: "WARNING" },
      ],
      migration_sequence: ["demo-pki", "demo-pki-int", "demo-identity", "demo-sso", "demo-payment"],
      justification_tags: ["deps_first"],
    },
    null,
    2
  );
  } catch (e) { console.error("bind failed", e); }
}


function getTutorialSteps() {
  if (window.CRI18N && window.CRI18N.tutorialSteps) return window.CRI18N.tutorialSteps();
  return [];
}
// compatibility alias updated on each render
let TUTORIAL_STEPS = getTutorialSteps();


let tutorialIndex = 0;

function renderTutorialStep() {
  TUTORIAL_STEPS = getTutorialSteps();
  const pane = $("#tutorial-pane");
  const prog = $("#tutorial-progress");
  const prev = $("#tutorial-prev");
  const next = $("#tutorial-next");
  if (!pane) return;
  const step = TUTORIAL_STEPS[tutorialIndex];
  pane.innerHTML = "<h3>" + esc(step.title) + "</h3><p class=\"muted\">" + esc(step.body) + "</p>";
  if (prog) prog.textContent = t("tut.step") + " " + (tutorialIndex + 1) + " " + t("tut.of") + " " + TUTORIAL_STEPS.length;
  if (prev) prev.disabled = tutorialIndex === 0;
  if (next) next.textContent = tutorialIndex >= TUTORIAL_STEPS.length - 1 ? t("btn.finish") : (tutorialIndex === 0 ? t("btn.start") : t("btn.understood"));
}

function openTutorial() {
  const m = $("#tutorial-modal");
  if (!m) return;
  tutorialIndex = 0;
  renderTutorialStep();
  m.classList.remove("hidden");
}
function closeTutorial() {
  const m = $("#tutorial-modal");
  if (m) m.classList.add("hidden");
}
function tutorialNext() {
  if (tutorialIndex >= TUTORIAL_STEPS.length - 1) {
    closeTutorial();
    return;
  }
  tutorialIndex += 1;
  renderTutorialStep();
}
function tutorialPrev() {
  if (tutorialIndex > 0) {
    tutorialIndex -= 1;
    renderTutorialStep();
  }
}
function showHelp(key, anchor) {
  const pop = $("#help-popover");
  if (!pop) return;
  pop.textContent = getHelpText(key);
  pop.classList.remove("hidden");
  if (anchor && anchor.getBoundingClientRect) {
    const r = anchor.getBoundingClientRect();
    pop.style.top = Math.min(window.innerHeight - 120, r.bottom + 8) + "px";
    pop.style.left = Math.min(window.innerWidth - 340, Math.max(8, r.left)) + "px";
  }
  clearTimeout(window.__helpTimer);
  window.__helpTimer = setTimeout(() => pop.classList.add("hidden"), 8000);
}

function humanCoreSummary(core, ux) {
  if (!core) return t("core.none");
  const sev = core.severity || t("na");
  const seq = (core.sequence || []).join(" → ") || t("none");
  const risk = core.risk_score != null ? core.risk_score : t("na");
  let why = "";
  if (ux && ux.p001_cycle) why = t("core.why.cycle");
  else if (ux && ux.blocked) why = t("core.why.blocked");
  else if (sev === "WARNING") why = t("core.why.warning");
  else if (sev === "NO_CONFLICT") why = t("core.why.noconflict");
  else why = t("why.core.eval");
  return (
    "<p><strong>" + t("core.what") + "</strong> " + esc(sev) + "</p>" +
    "<p><strong>" + t("core.why") + "</strong> " + esc(why) + "</p>" +
    "<p><strong>" + t("core.seq") + "</strong> " + esc(seq) + "</p>" +
    "<p><strong>" + t("core.risk") + "</strong> " + esc(String(risk)) + "</p>" +
    (core.action_rationale ? "<p><strong>" + t("core.rationale") + "</strong> " + esc(core.action_rationale) + "</p>" : "") +
    (core.policies_triggered && core.policies_triggered.length
      ? "<p><strong>" + t("core.policies") + "</strong> " + esc(core.policies_triggered.join(", ")) + "</p>"
      : "")
  );
}


async function loadAnalytics() {
  try {
    return await api("/api/analytics/summary");
  } catch (e) {
    console.warn("analytics unavailable", e);
    return { status: "NO_DATA", message: String(e.message || e), error: true };
  }
}


function chipListHTML(title, desc, items, takeaway) {
  if (!items || !items.length) {
    return (
      '<div class="chart-card"><h4>' +
      esc(title) +
      '</h4><p class="chart-desc">' +
      esc(desc) +
      '</p><div class="chart-empty">' + t("chart.nodata.short") + '</div></div>'
    );
  }
  const chips = items
    .map(
      (it) =>
        '<span class="policy-chip" title="' +
        esc(it.label) +
        '">' +
        esc(it.label) +
        (it.value != null && Number(it.value) !== 1 ? " · " + esc(String(it.value)) : "") +
        "</span>"
    )
    .join("");
  return (
    '<div class="chart-card chart-card--compact"><h4>' +
    esc(title) +
    '</h4><p class="chart-desc">' +
    esc(desc) +
    '</p><div class="chip-row">' +
    chips +
    "</div>" +
    (takeaway
      ? '<p class="chart-take"><strong>' + t("insight") + ':</strong> ' + esc(takeaway) + "</p>"
      : "") +
    "</div>"
  );
}

function barChartHTML(title, desc, items, takeaway, opts) {
  opts = opts || {};
  if (!items || !items.length) {
    return (
      '<div class="chart-card"><h4>' +
      esc(title) +
      '</h4><p class="chart-desc">' +
      esc(desc) +
      '</p><div class="chart-empty">' + t("chart.nodata.short") + '<br><span class="muted">' + t("chart.nodata.need") + '</span></div></div>'
    );
  }
  const max = Math.max.apply(
    null,
    items.map((it) => Number(it.value) || 0).concat([1])
  );
  // HTML bars (high contrast) — guaranteed visible without external libs
  const rows = items
    .map((it) => {
      const v = Number(it.value) || 0;
      const pct = Math.max(6, Math.round((100 * v) / max));
      const cls = opts.clickable ? "bar-row clickable" : "bar-row";
      const data = it.id ? ' data-asset="' + esc(it.id) + '"' : "";
      const suffix = opts.valueSuffix || "";
      const display = opts.valueFormatter
        ? opts.valueFormatter(v)
        : String(v) + suffix;
      return (
        '<div class="' +
        cls +
        '"' +
        data +
        ' title="' +
        esc(it.label + ": " + display) +
        '"><span class="bar-label">' +
        esc(it.label) +
        '</span><span class="bar-track"><span class="bar-fill" style="width:' +
        pct +
        '%"></span></span><span class="bar-val">' +
        esc(display) +
        "</span></div>"
      );
    })
    .join("");
  // Companion SVG for extra visual weight on larger sets
  const rowH = 36;
  const svgH = Math.max(200, items.length * rowH + 24);
  const svgW = 640;
  const labelW = 140;
  const barMax = svgW - labelW - 56;
  const svgBars = items
    .map((it, i) => {
      const v = Number(it.value) || 0;
      const w = Math.max(12, Math.round((barMax * v) / max));
      const y = 12 + i * rowH;
      return (
        '<text class="bar-name" x="0" y="' +
        (y + 18) +
        '">' +
        esc(String(it.label).slice(0, 18)) +
        "</text>" +
        '<rect class="bar-rect" x="' +
        labelW +
        '" y="' +
        y +
        '" width="' +
        w +
        '" height="24" rx="6"></rect>' +
        '<text class="bar-value" x="' +
        (labelW + w + 8) +
        '" y="' +
        (y + 17) +
        '">' +
        esc((opts.valueFormatter ? opts.valueFormatter(v) : String(v) + (opts.valueSuffix || ""))) +
        "</text>"
      );
    })
    .join("");
  const svg =
    '<svg class="svg-chart" viewBox="0 0 ' +
    svgW +
    " " +
    svgH +
    '" role="img" aria-label="' +
    esc(title) +
    '"><defs><linearGradient id="crBarGrad" x1="0" y1="0" x2="1" y2="0">' +
    '<stop offset="0%" stop-color="#6d28d9"/><stop offset="55%" stop-color="#8b5cf6"/><stop offset="100%" stop-color="#c4b5fd"/>' +
    "</linearGradient></defs>" +
    svgBars +
    "</svg>";
  const scale = opts.scaleLabel
    ? '<p class="chart-scale">' + esc(opts.scaleLabel) + "</p>"
    : "";
  const cap =
    opts.totalCount && opts.totalCount > items.length
      ? '<p class="chart-cap">' +
        t("chart.showing") +
        " " +
        items.length +
        " " +
        t("chart.of") +
        " " +
        opts.totalCount +
        "</p>"
      : "";
  return (
    '<div class="chart-card"><h4>' +
    esc(title) +
    '</h4><p class="chart-desc">' +
    esc(desc) +
    "</p>" +
    scale +
    cap +
    rows +
    (opts.svg === true ? svg : "") +
    (takeaway
      ? '<p class="chart-take"><strong>' + t("insight") + ':</strong> ' + esc(takeaway) + "</p>"
      : "") +
    "</div>"
  );
}

function takeawayCriticality(dist) {
  const entries = Object.entries(dist || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length || entries.every((e) => e[1] === 0)) return t("take.crit.none");
  const total = entries.reduce((s, e) => s + (Number(e[1]) || 0), 0);
  const crit = (dist && (dist.critical || dist.CRITICAL)) || 0;
  const high = (dist && (dist.high || dist.HIGH)) || 0;
  const top = entries[0];
  return t("take.crit", {
    total: total,
    band: top[0],
    n: top[1],
    ch: Number(crit) + Number(high),
  });
}

function takeawayExposure(exp) {
  const face = (exp && exp.internet_facing) || 0;
  const internal = (exp && exp.internal) || 0;
  const total = face + internal;
  if (!total) return t("take.exp.none");
  return t("take.exp", { face: face, total: total });
}

function takeawayAlgs(algs) {
  const entries = Object.entries(algs || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return t("take.alg.none");
  const top3 = entries.slice(0, 3).map((e) => e[0] + "×" + e[1]).join(", ");
  return t("take.alg", { top3: top3, dom: entries[0][0], n: entries[0][1] });
}

function takeawayTopRisk(rows) {
  if (!rows || !rows.length) return t("take.risk.none");
  const top = rows[0];
  if (top.risk == null) return t("take.risk.missing");
  return t("take.risk", { id: top.asset_id, score: top.risk });
}

function takeawayHubs(hubs) {
  if (!hubs || !hubs.length) return t("take.hub.none");
  const h = hubs[0];
  const h2 = hubs[1];
  let msg = t("take.hub", { id: h.asset_id, n: h.consumers });
  if (h2) msg += t("take.hub.next", { id: h2.asset_id, n: h2.consumers });
  msg += t("take.hub.tail");
  return msg;
}

function wireChartClicks(root) {
  if (!root) return;
  root.querySelectorAll(".bar-row.clickable[data-asset]").forEach((el) => {
    el.addEventListener("click", () => {
      const id = el.getAttribute("data-asset");
      if (!id) return;
      showView("decision");
      const sel = $("#dec-asset");
      if (sel) {
        sel.value = id;
      }
    });
  });
}

async function renderOverviewCharts() {
  try {
  const root = $("#charts-root");
  const empty = $("#charts-empty");
  if (!root) return;
  const data = await loadAnalytics();
  if (!data || data.status === "NO_DATA" || !data.asset_count) {
    root.innerHTML = "";
    if (empty) empty.classList.remove("hidden");
    ["#kpi-total","#kpi-critical","#kpi-attention","#kpi-toprisk"].forEach((id) => {
      const el = $(id); if (el) el.textContent = "—";
    });
    const fs0 = $("#findings-summary-body");
    if (fs0) fs0.textContent = t("findings.empty");
    const st0 = $("#findings-start-body");
    if (st0) st0.innerHTML = "<li>" + t("findings.start.1") + "</li><li>" + t("findings.start.2") + "</li><li>" + t("findings.start.3") + "</li><li>" + t("findings.start.4") + "</li>";
    return;
  }
  if (empty) empty.classList.add("hidden");
  // KPI cards from active analytics only
  const setTxt = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  const dist = data.criticality_distribution || {};
  const critN = Number(dist.critical || 0);
  const highN = Number(dist.high || 0);
  setTxt("#kpi-total", String(data.asset_count || 0));
  setTxt("#kpi-critical", String(critN));
  setTxt("#kpi-attention", String(critN + highN));
  const topRisk = (data.top_by_core_risk || []).find((r) => r.risk != null);
  setTxt("#kpi-toprisk", topRisk ? (topRisk.asset_id + " · " + topRisk.risk) : "—");

  const critItems = ["critical", "high", "medium", "low"]
    .filter((k) => data.criticality_distribution && data.criticality_distribution[k] != null)
    .map((k) => ({ label: tv(k), value: data.criticality_distribution[k], raw: k }));
  if (!critItems.length) {
    Object.entries(data.criticality_distribution || {}).forEach(([k, v]) => {
      critItems.push({ label: k, value: v });
    });
  }
  const expItems = Object.entries(data.exposure || {}).map(([k, v]) => ({
    label: k.replace("_", " "),
    value: v,
  }));
  const algItems = Object.entries(data.algorithms || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([k, v]) => ({ label: k, value: v }));
  const land = data.algorithm_landscape || {};
  const landItems = [
    { label: "legacy-named", value: land.legacy_named || 0 },
    { label: "pqc-named", value: land.pqc_named || 0 },
    { label: "other", value: land.other || 0 },
  ];
  const topItems = (data.top_by_core_risk || [])
    .filter((r) => r.risk != null)
    .slice(0, 8)
    .map((r) => ({ label: r.asset_id, value: r.risk, id: r.asset_id }));
  const hubItems = (data.dependency_hubs || [])
    .slice(0, 8)
    .map((h) => ({ label: h.asset_id, value: h.consumers, id: h.asset_id }));

  // Data-grounded overview narrative (no invented numbers)
  const fs = $("#findings-summary-body");
  const reviewN = Number(data.review_required_count || data.attention_count || 0);
  if (fs) {
    let sum = t("findings.summary", { n: data.asset_count || 0, c: critN, h: highN });
    if (reviewN > 0) sum += " " + t("findings.review", { r: reviewN });
    const top = (data.top_by_core_risk || []).find((r) => r.risk != null);
    if (top) sum += " " + t("findings.top", { id: top.asset_id, score: top.risk });
    fs.textContent = sum;
  }
  const hubs = data.dependency_hubs || [];
  const startEl = $("#findings-start-body");
  if (startEl) {
    const lines = [];
    lines.push(t("start.crit", { n: critN }));
    lines.push(t("start.risk"));
    if (hubs.length) {
      const h0 = hubs[0];
      const hid = h0.asset_id || h0.id || h0.label || "hub";
      const hc = h0.count != null ? h0.count : h0.dependents;
      const extra = hc != null ? " (" + hc + ")" : "";
      lines.push(t("start.hub", { id: hid, extra: extra }));
    } else {
      lines.push(t("start.hub.fallback"));
    }
    lines.push(reviewN > 0 ? t("start.review", { n: reviewN }) : t("start.review.fallback"));
    startEl.innerHTML = lines.map((line) => "<li>" + line + "</li>").join("");
  }

  root.innerHTML =
    barChartHTML(
      t("chart.crit.dist"),
      t("chart.crit.dist.desc"),
      critItems,
      takeawayCriticality(data.criticality_distribution),
      { scaleLabel: t("scale.crit") }
    ) +
    barChartHTML(
      "EXPOSURE",
      t("chart.exp.desc"),
      expItems,
      takeawayExposure(data.exposure)
    ) +
    barChartHTML(
      t("chart.alg.title"),
      t("chart.alg.desc"),
      algItems,
      takeawayAlgs(data.algorithms)
    ) +
    barChartHTML(
      t("chart.land.title"),
      t("chart.land.desc"),
      landItems,
      t("chart.land.take")
    ) +
    barChartHTML(
      t("chart.risk.title"),
      t("chart.risk.desc"),
      topItems,
      takeawayTopRisk(data.top_by_core_risk),
      {
        clickable: true,
        valueSuffix: "/100",
        scaleLabel: t("scale.risk"),
        totalCount: (data.top_by_core_risk || []).filter((r) => r.risk != null).length,
      }
    ) +
    barChartHTML(
      t("chart.hubs.title"),
      t("chart.hubs.desc"),
      hubItems,
      takeawayHubs(data.dependency_hubs),
      { clickable: true }
    );
  wireChartClicks(root);
  } catch (e) {
    console.warn("overview charts failed", e);
    const root = $("#charts-root");
    if (root) root.innerHTML = "<div class=\"chart-card\"><strong>" + t("chart.analytics.fail") + "</strong><p class=\"muted\">" + t("chart.analytics.fail.hint") + "</p></div>";
  }
}

async function renderRiskCharts() {
  const root = $("#risk-charts");
  if (!root) return;
  const data = await loadAnalytics();
  if (!data || data.status === "NO_DATA") {
    root.innerHTML =
      '<div class="chart-card"><strong>' + t("chart.nodata.short") + '</strong><p class="muted">' + t("chart.load.risk") + '</p></div>';
    return;
  }
  const topItems = (data.top_by_core_risk || [])
    .filter((r) => r.risk != null)
    .slice(0, 10)
    .map((r) => ({ label: r.asset_id, value: r.risk, id: r.asset_id }));
  const critItems = ["critical", "high", "medium", "low"]
    .filter((k) => data.criticality_distribution && data.criticality_distribution[k] != null)
    .map((k) => ({ label: tv(k), value: data.criticality_distribution[k], raw: k }));
  if (!critItems.length) {
    Object.entries(data.criticality_distribution || {}).forEach(([k, v]) => {
      critItems.push({ label: k, value: v });
    });
  }
  root.innerHTML =
    barChartHTML(
      t("chart.risk.title"),
      t("chart.risk.desc"),
      topItems,
      takeawayTopRisk(data.top_by_core_risk),
      {
        clickable: true,
        valueSuffix: "/100",
        scaleLabel: t("scale.risk"),
        totalCount: (data.top_by_core_risk || []).filter((r) => r.risk != null).length,
      }
    ) +
    barChartHTML(
      t("chart.crit.title"),
      t("chart.crit.desc"),
      critItems,
      takeawayCriticality(data.criticality_distribution)
    );
  wireChartClicks(root);
}

async function renderDepCharts() {
  const root = $("#dep-charts");
  if (!root) return;
  const data = await loadAnalytics();
  if (!data || data.status === "NO_DATA") {
    root.innerHTML =
      '<div class="chart-card"><strong>' + t("chart.nodata.short") + '</strong><p class="muted">' + t("chart.load.deps") + '</p></div>';
    return;
  }
  const hubItems = (data.dependency_hubs || []).map((h) => ({
    label: h.asset_id,
    value: h.consumers,
    id: h.asset_id,
  }));
  root.innerHTML = barChartHTML(
    t("chart.hubs.title"),
    "Fan-in: how many assets list this asset as a prerequisite (active inventory only).",
    hubItems,
    takeawayHubs(data.dependency_hubs),
    { clickable: true, valueSuffix: " deps" }
  );
  wireChartClicks(root);
}

function renderDecisionChartsFromLast(data) {
  const root = $("#decision-charts");
  if (!root) return;
  if (!data || !data.core) {
    root.innerHTML =
      '<div class="chart-card"><strong>' + t("chart.nodata.short") + '</strong><p class="muted">' + t("chart.load.stress") + '</p></div>';
    return;
  }
  const seq = data.core.sequence || [];
  const seqItems = seq.map((id, idx) => ({ label: id, value: seq.length - idx, id: id }));
  const pol = data.core.policies_triggered || [];
  const polItems = pol.map((p) => ({ label: String(p), value: 1 }));
  const sev = data.core.severity || t("na");
  const kind = severityKind(sev);
  const sevCls =
    kind === "conflict"
      ? "conflict"
      : kind === "warning"
        ? "warning"
        : "safe";
  root.innerHTML =
    '<div class="chart-card"><h4>' + t("dec.what") + '</h4><p class="chart-desc">' + t("dec.what.desc") + '</p>' +
    '<div class="severity-badge ' +
    sevCls +
    '">' +
    esc(sev) +
    "</div>" +
    (data.core.action_rationale
      ? "<p><strong>" + t("dec.rationale") + "</strong> " + esc(cleanActionText(data.core.action_rationale)) + "</p>"
      : "") +
    '<div class="insight-box"><h5>' + t("insight") + '</h5><p>' +
    esc(
      kind === "conflict"
        ? t("dec.insight.conflict")
        : kind === "warning"
          ? t("dec.insight.warning")
          : t("dec.insight.noconflict")
    ) +
    "</p></div></div>" +
    (seq.length
      ? barChartHTML(
          t("chart.seq.title"),
          t("chart.seq.desc"),
          seqItems,
          t("chart.seq.len", { n: seq.length }),
          { clickable: true }
        )
      : '<div class="chart-card chart-card--compact"><h4>' + t("chart.seq.title") + '</h4><p class="chart-desc">' + t("chart.seq.desc") + '</p><div class="chart-empty">' + t("insight") + ': ' + t("chart.seq.empty") + '</div></div>') +
    (polItems.length
      ? chipListHTML(
          t("chart.pol.title"),
          t("chart.pol.desc"),
          polItems,
          t("chart.pol.take")
        )
      : "");
  wireChartClicks(root);
}

(async function init() {
  if (window.CRI18N) window.CRI18N.applyStatic();
  bindLanguageSwitch();
  bind();
  await refreshHealth();
  await refreshInventory();
  showView("overview");
  if (window.CRI18N) window.CRI18N.applyStatic();
  try {
    if (!localStorage.getItem("cryptorisk_welcome_dismissed")) {
      const w = $("#welcome-banner");
      if (w) w.classList.remove("hidden");
    }
  } catch (_) {}
})();


window.onLanguageChange = async function () {
  if (window.CRI18N) window.CRI18N.applyStatic();
  TUTORIAL_STEPS = getTutorialSteps();
  // refresh active page titles
  const activeBtn = document.querySelector(".nav-btn.active");
  const view = activeBtn ? activeBtn.dataset.view : "overview";
  const meta = getPageMeta()[view];
  if (meta) {
    const pt = $("#page-title");
    const ps = $("#page-sub");
    if (pt) pt.textContent = meta.title;
    if (ps) ps.textContent = meta.sub;
  }
  // ALWAYS re-render inventory enums for the active language (presentation only).
  try {
    renderInventoryTable();
  } catch (e) {
    console.warn("renderInventoryTable on lang change", e);
  }
  try {
    await refreshInventory();
    renderInventoryTable();
    await refreshInventoryCharts();
    await refreshHealth();
    if (view === "risk") {
      await renderRisk();
      await renderRiskCharts();
    }
    if (view === "dependencies") {
      await renderDeps();
      await renderDepCharts();
    }
    if (view === "decision" && state.lastStress) renderDecisionChartsFromLast(state.lastStress);
    // Always refresh audit narrative for language switch (presentation only)
    try {
      renderAuditPanel(state.lastDecision || state.lastStress || null);
    } catch (e) {
      console.warn("renderAuditPanel on lang change", e);
    }
    if (view === "decision" && (state.lastDecision || state.lastStress)) {
      try { renderDecision(state.lastDecision || state.lastStress); } catch (e) {}
    }
    if (!$("#tutorial-modal").classList.contains("hidden")) renderTutorialStep();
  } catch (e) {
    console.warn("lang refresh", e);
  }
};

function bindLanguageSwitch() {
  document.querySelectorAll("[data-lang]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const next = btn.getAttribute("data-lang");
      if (window.CRI18N) window.CRI18N.setLang(next);
    });
  });
}

// Event delegation backup for language switch
document.addEventListener("click", function (ev) {
  const btn = ev.target && ev.target.closest && ev.target.closest("[data-lang]");
  if (!btn) return;
  const next = btn.getAttribute("data-lang");
  if (next && window.CRI18N) window.CRI18N.setLang(next);
});
