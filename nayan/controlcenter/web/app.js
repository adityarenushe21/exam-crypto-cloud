"use strict";
/* ExamVault Control Center - dashboard (vanilla JS, no build step).
 * Security: every value from the server is inserted with textContent (never innerHTML),
 * the page's CSP forbids inline scripts, and the session token lives only in sessionStorage
 * for this tab. The backend re-checks every role; hiding a button here is NOT security. */

const API = "/api/v1";
const state = { token: sessionStorage.getItem("cc_token") || "", user: null, timer: null };

// ------------------------------------------------------------------ helpers
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) {
    if (k === null || k === undefined || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}
const $main = () => document.getElementById("main");
function show(...nodes) { $main().replaceChildren(...nodes.flat().filter((n) => n !== null && n !== undefined && n !== false)); }
function banner(msg, kind = "err") {
  const b = document.getElementById("banner");
  if (!msg) { b.hidden = true; return; }
  b.className = "banner " + kind; b.textContent = msg; b.hidden = false;
  if (kind === "ok") setTimeout(() => { b.hidden = true; }, 4000);
}
const local = (utc) => utc ? new Date(utc).toLocaleString() : "—";
const short = (s, n = 12) => (s && s.length > n ? s.slice(0, n) + "…" : s || "—");

const BADGE = {
  RELEASABLE: "ok", RELEASED: "ok", valid: "ok", SUCCESS: "ok", CLOSED: "plain", ANCHORED: "ok", MOCK_ANCHORED: "ok",
  NOT_YET_RELEASABLE: "plain", AWAITING_CUSTODIANS: "warn", SEALED: "plain", REVIEWING: "warn", ACKNOWLEDGED: "warn",
  MEDIUM: "warn", DENIED: "warn", LOW: "plain", NEW: "bad",
  BLOCKED: "bad", HIGH: "bad", FAILED: "bad", invalid: "bad", mismatch: "bad", FROZEN: "bad", REVOKED: "bad",
  COMPROMISED: "bad", ERROR: "bad", RESTRICTED: "bad", LOCKED: "bad", "AUDIT LOG TAMPERED": "bad",
  "NOT ON CHAIN": "warn", active: "ok", LIFTED: "ok", running: "ok", OK: "ok", off: "plain",
};
const badge = (v) => h("span", { class: "badge " + (BADGE[v] || "") }, v ?? "—");

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  if (state.token) headers.Authorization = "Bearer " + state.token;
  let body = opts.body;
  if (body && !(body instanceof FormData)) { headers["Content-Type"] = "application/json"; body = JSON.stringify(body); }
  const res = await fetch(API + path, { method: opts.method || "GET", headers, body });
  if (opts.raw && res.ok) return res;
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && path !== "/auth/login") { logout(true); throw new Error(data.message || "session expired"); }
  if (!res.ok) { const e = new Error(data.message || data.reason_code || res.statusText); e.code = data.reason_code; e.status = res.status; throw e; }
  return data;
}

// --------------------------------------------------------------- navigation
const PAGES = {
  overview: { title: "Overview", roles: ["admin", "auditor"], render: renderOverview, refresh: true },
  papers:   { title: "Papers", roles: ["admin", "auditor", "exam_authority", "release_officer"], render: renderPapers, refresh: true },
  alerts:   { title: "Alerts", roles: ["admin", "auditor"], render: renderAlerts, refresh: true },
  audit:    { title: "Audit log", roles: ["admin", "auditor"], render: renderAudit },
  access:   { title: "Access", roles: ["admin", "auditor"], render: renderAccess },
  system:   { title: "System", roles: ["admin", "auditor"], render: renderSystem, refresh: true },
};
const allowed = () => Object.entries(PAGES).filter(([, p]) => state.user && p.roles.includes(state.user.role));
const current = () => (location.hash.replace("#/", "") || "").split("?")[0];
const isAdmin = () => state.user && state.user.role === "admin";

function renderNav() {
  const nav = document.getElementById("nav"), who = document.getElementById("who");
  if (!state.user) { nav.replaceChildren(); who.replaceChildren(); return; }
  nav.replaceChildren(...allowed().map(([k, p]) => h("a", { href: "#/" + k, class: current() === k ? "active" : null }, p.title)));
  who.replaceChildren(h("span", {}, state.user.username, " ", badge(state.user.role)),
    h("button", { onclick: () => logout(false) }, "Log out"));
}

async function route() {
  banner("");
  clearInterval(state.timer);
  if (!state.user) return renderLogin();
  const pages = allowed();
  let key = current();
  if (!pages.find(([k]) => k === key)) { location.hash = "#/" + pages[0][0]; return; }
  renderNav();
  const page = PAGES[key];
  try { await page.render(); } catch (e) { banner(e.message); }
  if (page.refresh) state.timer = setInterval(() => {
    const busy = document.activeElement && ["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement.tagName);
    if (!busy && current() === key) page.render().catch(() => {});
  }, 10000);
}

// -------------------------------------------------------------------- login
function renderLogin(needMfa = false, keep = {}) {
  renderNav();
  const err = h("p", { class: "muted", id: "login-msg" });
  const user = h("input", { name: "username", autocomplete: "username", required: true, value: keep.u || "" });
  const pass = h("input", { name: "password", type: "password", autocomplete: "current-password", required: true });
  const code = needMfa ? h("input", { name: "totp", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6", required: true }) : null;
  if (keep.p) pass.value = keep.p;
  const form = h("form", { class: "stack", onsubmit: async (ev) => {
      ev.preventDefault();
      try {
        const r = await api("/auth/login", { method: "POST", body: { username: user.value, password: pass.value, totp: code ? code.value : null } });
        state.token = r.token; sessionStorage.setItem("cc_token", r.token);
        state.user = { username: r.username, role: r.role };
        location.hash = ""; route();
      } catch (e) {
        if (e.code === "MFA_REQUIRED") return renderLogin(true, { u: user.value, p: pass.value });
        err.textContent = e.message; err.className = "badge bad";
      }
    } },
    h("label", {}, "Username", user), h("label", {}, "Password", pass),
    code && h("label", {}, "Authenticator code", code),
    h("button", { class: "primary", type: "submit" }, needMfa ? "Verify code" : "Log in"), err);
  show(h("div", { class: "card login" }, h("h1", {}, "Sign in"),
    h("p", { class: "muted sub" }, "Accounts are created by an administrator. Five wrong attempts lock the account for 15 minutes."), form));
  (code || user).focus();
}

async function logout(expired) {
  if (!expired && state.token) { try { await api("/auth/logout", { method: "POST" }); } catch (_) {} }
  state.token = ""; state.user = null; sessionStorage.removeItem("cc_token");
  clearInterval(state.timer); route();
  if (expired) banner("Your session expired - please log in again.");
}

// ----------------------------------------------------------------- overview
async function renderOverview() {
  const o = await api("/dashboard/overview");
  const a = await api("/alerts?status=NEW");
  const stat = (label, value, detail, kind) => h("div", { class: "card stat" },
    h("div", { class: "label" }, label), h("div", { class: "value" }, value, " ", kind ? badge(kind) : null), h("div", { class: "detail" }, detail));
  const sev = o.alerts.open_by_severity || {};
  const rs = o.papers.by_release_status || {};
  show(h("h1", {}, "Overview"), h("p", { class: "muted sub" }, "Refreshes every 10 seconds."),
    h("div", { class: "grid" },
      stat("Papers", o.papers.total, Object.entries(rs).map(([k, v]) => `${v} ${k.toLowerCase().replaceAll("_", " ")}`).join(" · ") || "none yet"),
      stat("Open alerts", o.alerts.open, `${sev.HIGH || 0} high · ${sev.MEDIUM || 0} medium`, (sev.HIGH || 0) ? "HIGH" : null),
      stat("Restricted accounts", o.access.restricted, `${o.access.users} accounts · ${o.access.active_sessions} signed in`),
      stat("Audit events", o.audit.events, `${o.audit.denied_or_failed} denied/failed · anchored to #${o.chain.anchored_events_up_to_seq ?? "?"}`),
      stat("Blockchain", o.chain.mode, o.chain.reachable ? "reachable" : "NOT reachable", o.chain.reachable ? null : "ERROR"),
      stat("AI watcher", o.watcher.running ? "running" : "off", o.watcher.model || "")),
    h("h2", {}, "New alerts"), alertTable(a.alerts.slice(0, 8), false));
}

// ------------------------------------------------------------------- papers
async function renderPapers() {
  const { papers } = await api("/dashboard/papers");
  const role = state.user.role;
  const rows = papers.slice().reverse().map((p) => h("tr", {},
    h("td", { class: "mono" }, p.paper_id, p.versions && p.versions.length > 1 ? ` (v${p.paper_version} of ${p.versions.length})` : ""),
    h("td", {}, p.exam_id || "—"),
    h("td", {}, local(p.release_at_utc)),
    h("td", {}, badge(p.release_status), p.chain_reason_code ? h("div", { class: "muted mono" }, p.chain_reason_code) : null),
    h("td", {}, badge(p.signature_status), " ", badge(p.integrity_status)),
    h("td", {}, p.blockchain && p.blockchain.found ? [badge(p.blockchain.status), h("div", { class: "muted" }, `${p.blockchain.approvals}/${p.blockchain.threshold} custodians`)] : badge(p.blockchain && p.blockchain.status === "UNAVAILABLE" ? "ERROR" : "NOT ON CHAIN")),
    h("td", {}, role === "release_officer" ? h("button", { class: p.release_status === "RELEASABLE" ? "primary" : "", onclick: () => releasePaper(p) }, "Release") : null)));
  show(h("h1", {}, "Papers"),
    h("p", { class: "muted sub" }, "A paper can be released only after its release time AND after 3 of 5 custodians approve on the blockchain."),
    role === "exam_authority" ? uploadForm() : null,
    papers.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ...["Paper", "Exam", "Release time", "Release", "Signature / integrity", "Blockchain", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, rows))) : h("div", { class: "card empty" }, "No papers yet."));
}

function uploadForm() {
  const file = h("input", { type: "file", accept: "application/pdf,.pdf", required: true });
  const exam = h("input", { placeholder: "CS301-ENDSEM", pattern: "[A-Za-z0-9_\\-]{1,64}", required: true });
  const when = h("input", { type: "datetime-local", required: true });
  return h("div", { class: "card" }, h("h2", {}, "Seal a new paper"),
    h("form", { class: "inline", onsubmit: async (ev) => {
        ev.preventDefault();
        const fd = new FormData();
        fd.append("file", file.files[0]); fd.append("exam_id", exam.value);
        fd.append("release_at_utc", new Date(when.value).toISOString().replace(/\.\d{3}Z$/, "Z"));
        try {
          const r = await api("/papers", { method: "POST", body: fd });
          banner(`Sealed ${r.paper_id} - blockchain: ${r.blockchain_status}`, "ok"); renderPapers();
        } catch (e) { banner(e.message); }
      } },
      h("label", {}, "PDF", file), h("label", {}, "Exam ID", exam), h("label", {}, "Release time (your local time)", when),
      h("button", { class: "primary", type: "submit" }, "Encrypt & seal")));
}

async function releasePaper(p) {
  try {
    const res = await api(`/papers/${encodeURIComponent(p.paper_id)}/release`, { method: "POST", raw: true });
    const blob = await res.blob();
    const a = h("a", { href: URL.createObjectURL(blob), download: `${p.paper_id}_v${p.paper_version}.pdf` });
    document.body.append(a); a.click(); a.remove();
    banner(`Released ${p.paper_id} - download started.`, "ok");
  } catch (e) { banner(`${e.code || "Refused"}: ${e.message}`); }
}

// ------------------------------------------------------------------- alerts
function alertTable(alerts, withActions) {
  if (!alerts.length) return h("div", { class: "card empty" }, "No alerts.");
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ...["Time", "Severity", "Score", "Actor", "Reasons", "Status", ""].map((t) => h("th", {}, t)))),
    h("tbody", {}, alerts.map((a) => h("tr", {},
      h("td", {}, local(a.event_time_utc || a.created_at_utc)),
      h("td", {}, badge(a.severity)), h("td", {}, a.risk_score),
      h("td", {}, h("div", {}, a.actor_id), h("div", { class: "muted" }, a.actor_role)),
      h("td", {}, (a.reason_codes || []).join(", "), a.suppressed_count ? h("div", { class: "muted" }, `+${a.suppressed_count} similar`) : null,
        h("details", {}, h("summary", {}, "details"), alertDetails(a))),
      h("td", {}, badge(a.status), a.access_action ? h("div", {}, badge("RESTRICTED")) : null),
      h("td", {}, withActions && isAdmin() ? alertActions(a) : null))))));
}

function alertDetails(a) {
  const kv = h("dl", { class: "kv" });
  const add = (k, v) => kv.append(h("dt", {}, k), h("dd", { class: "mono" }, v ?? "—"));
  add("recommended", a.recommended_action); add("event", a.event_type); add("paper", a.paper_id);
  add("audit seq", a.event_seq); add("components", JSON.stringify(a.components || {}));
  (a.top_features || []).forEach((f) => add("feature", `${f.feature} = ${f.value} (+${f.contribution})`));
  if (a.chain_flag) add("on-chain flag", `${a.chain_flag.status} ${a.chain_flag.tx_id || ""}`);
  (a.history || []).forEach((x) => add("history", `${x.at_utc} ${x.by}: ${x.status || ""} ${x.review_note || ""}`));
  return kv;
}

function alertActions(a) {
  const review = async (status) => {
    const note = status === "CLOSED" ? prompt("Closing note (what was decided and why):") : (prompt("Optional note:") ?? "");
    if (status === "CLOSED" && !note) return;
    try { await api(`/alerts/${a.alert_id}/review`, { method: "POST", body: { status, note } }); banner(`Alert ${status.toLowerCase()}.`, "ok"); route(); }
    catch (e) { banner(e.message); }
  };
  const restrict = async () => {
    const hours = prompt(`Restrict account "${a.actor_id}" for how many hours? (blank = until lifted)`, "24");
    if (hours === null) return;
    if (!confirm(`Restrict ${a.actor_id}? Their sessions end immediately and every request is refused.`)) return;
    try {
      await api(`/alerts/${a.alert_id}/restrict`, { method: "POST", body: { hours: hours ? Number(hours) : null, reason: `alert: ${(a.reason_codes || []).join(",")}` } });
      banner(`${a.actor_id} restricted.`, "ok"); route();
    } catch (e) { banner(e.message); }
  };
  return h("div", { class: "actions" },
    a.status === "NEW" ? h("button", { onclick: () => review("ACKNOWLEDGED") }, "Acknowledge") : null,
    a.status !== "CLOSED" ? h("button", { onclick: () => review("REVIEWING") }, "Reviewing") : null,
    a.status !== "CLOSED" ? h("button", { onclick: () => review("CLOSED") }, "Close") : null,
    !a.access_action && a.recommended_action === "TEMPORARY_RESTRICT" ? h("button", { class: "danger", onclick: restrict }, "Restrict account") : null);
}

async function renderAlerts() {
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  const sev = params.get("severity") || "", st = params.get("status") || "";
  const { alerts } = await api(`/alerts?severity=${sev}&status=${st}`);
  const sel = (name, value, opts) => h("select", { onchange: (e) => { params.set(name, e.target.value); location.hash = "#/alerts?" + params; } },
    opts.map((o) => { const x = h("option", { value: o }, o || "all"); if (o === value) x.selected = true; return x; }));
  show(h("h1", {}, "AI alerts"),
    h("p", { class: "muted sub" }, "Scores are advisory. Restricting an account is always a human decision and is recorded in the audit log."),
    h("div", { class: "toolbar" }, h("label", {}, "Severity", sel("severity", sev, ["", "HIGH", "MEDIUM"])),
      h("label", {}, "Status", sel("status", st, ["", "NEW", "ACKNOWLEDGED", "REVIEWING", "CLOSED"]))),
    alertTable(alerts, true));
}

// -------------------------------------------------------------------- audit
async function renderAudit() {
  const { events } = await api("/events?limit=300");
  const out = h("span", { class: "muted" });
  const verify = async () => { try { const r = await api("/events/verify"); out.replaceChildren(r.ok ? badge("valid") : badge("invalid"), ` ${r.checked ?? ""} events checked${r.ok ? "" : ` - problem at #${r.bad_seq}: ${r.reason}`}`); } catch (e) { banner(e.message); } };
  const anchor = async () => { try { const r = await api("/events/anchor", { method: "POST" }); const b = r.anchored_batches; banner(b.length ? `Anchored events ${b[0].first_seq}-${b[b.length - 1].last_seq} (${b[b.length - 1].status}).` : "Nothing new to anchor.", "ok"); } catch (e) { banner(e.message); } };
  show(h("h1", {}, "Audit log"),
    h("p", { class: "muted sub" }, "Every request and admin action, hash-chained and signed with ML-DSA-65; batches are anchored on the blockchain."),
    h("div", { class: "toolbar" }, h("button", { onclick: verify }, "Verify signatures & chain"), isAdmin() ? h("button", { onclick: anchor }, "Anchor new events on-chain") : null, out),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ...["#", "Time", "Event", "Result", "Reason / action", "Actor", "Paper / target"].map((t) => h("th", {}, t)))),
      h("tbody", {}, events.slice().reverse().map((e) => h("tr", {},
        h("td", { class: "mono" }, e.seq), h("td", {}, local(e.timestamp_utc)), h("td", {}, e.event_type),
        h("td", {}, badge(e.result)), h("td", { class: "mono" }, e.reason_code || e.action || ""),
        h("td", {}, e.actor_id, h("div", { class: "muted" }, e.actor_role)),
        h("td", { class: "mono" }, e.paper_id || e.target_actor_id || e.alert_id || "")))))));
}

// ------------------------------------------------------------------- access
async function renderAccess() {
  const { users } = await api("/access/users");
  const { history } = await api("/access/restrictions");
  const act = async (u, kind) => {
    const reason = prompt(kind === "restrict" ? `Reason for restricting ${u.username}:` : `Reason for lifting the restriction on ${u.username}:`);
    if (!reason) return;
    const hours = kind === "restrict" ? prompt("Hours (blank = until lifted):", "24") : null;
    try { await api(`/access/users/${u.username}/${kind}`, { method: "POST", body: { reason, hours: hours ? Number(hours) : null } }); banner("Done.", "ok"); renderAccess(); }
    catch (e) { banner(e.message); }
  };
  const name = h("input", { placeholder: "username", required: true });
  const role = h("select", {}, ["exam_authority", "release_officer", "auditor", "admin"].map((r) => h("option", { value: r }, r)));
  const pw = h("input", { type: "password", placeholder: "initial password (10+ chars)", autocomplete: "new-password", required: true });
  show(h("h1", {}, "Access control"),
    h("p", { class: "muted sub" }, "Restricted accounts are refused on every request and their sessions end immediately."),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ...["User", "Role", "MFA", "State", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, users.map((u) => h("tr", {},
        h("td", {}, u.username), h("td", {}, u.role), h("td", {}, u.mfa_enabled ? badge("valid") : badge("off")),
        h("td", {}, u.restriction ? [badge("RESTRICTED"), h("div", { class: "muted" }, u.restriction.until_utc ? "until " + local(u.restriction.until_utc) : "until lifted")] : (u.locked_until ? badge("LOCKED") : badge("active"))),
        h("td", {}, isAdmin() && u.username !== state.user.username ? (u.restriction ? h("button", { onclick: () => act(u, "unrestrict") }, "Lift restriction") : h("button", { class: "danger", onclick: () => act(u, "restrict") }, "Restrict")) : null)))))),
    isAdmin() ? h("div", { class: "card", style: null }, h("h2", {}, "Create account"),
      h("form", { class: "inline", onsubmit: async (ev) => {
          ev.preventDefault();
          try { await api("/access/users", { method: "POST", body: { username: name.value, role: role.value, password: pw.value } }); banner(`Account ${name.value} created.`, "ok"); renderAccess(); }
          catch (e) { banner(e.message); }
        } }, h("label", {}, "Username", name), h("label", {}, "Role", role), h("label", {}, "Password", pw),
        h("button", { class: "primary", type: "submit" }, "Create"))) : null,
    h("h2", {}, "Restriction history"),
    history.length ? h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, history.map((r) => h("tr", {},
      h("td", {}, local(r.at_utc)), h("td", {}, badge(r.record === "restrict" ? "RESTRICTED" : "LIFTED")), h("td", {}, r.username),
      h("td", {}, "by ", r.by), h("td", { class: "muted" }, r.reason)))))) : h("div", { class: "card empty" }, "No restrictions yet."));
}

// ------------------------------------------------------------------- system
async function renderSystem() {
  const s = await api("/system/health");
  const row = (k, v) => h("tr", {}, h("th", {}, k), h("td", {}, v));
  show(h("h1", {}, "System health"),
    h("div", { class: "table-wrap" }, h("table", { class: "kvtable" }, h("tbody", {},
      row("API", badge(s.api)), row("Storage", s.storage),
      row("Blockchain", [s.chain.mode, " ", s.chain.reachable ? badge("valid") : badge("ERROR"), s.chain.reachable ? ` · events anchored to #${s.chain.anchored_events_up_to_seq}` : ` ${s.chain.reason_code || ""}`]),
      row("Release needs custodian approval", s.release_requires_chain ? "yes" : "NO (demo)"),
      row("Audit log", [s.audit_log.ok ? badge("valid") : badge("invalid"), ` ${s.audit_log.checked ?? ""} events, signatures checked`]),
      row("AI watcher", [s.watcher.running ? badge("running") : badge("off"), ` ${s.watcher.model || ""}`, s.watcher.error ? h("div", { class: "badge bad" }, s.watcher.error) : null,
        s.watcher.log_tampered ? h("div", {}, badge("AUDIT LOG TAMPERED")) : null]),
      row("Last AI poll", local(s.watcher.last_poll_utc)), row("On-chain risk flags", s.watcher.on_chain_flags ? "on" : "off")))));
}

// --------------------------------------------------------------------- boot
window.addEventListener("hashchange", route);
window.addEventListener("DOMContentLoaded", async () => {
  if (state.token) {
    try { const me = await api("/auth/me"); state.user = { username: me.username, role: me.role }; }
    catch (_) { state.token = ""; sessionStorage.removeItem("cc_token"); }
  }
  route();
});
