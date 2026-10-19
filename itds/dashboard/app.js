/* Sentry analyst dashboard.
 *
 * Two data sources behind one interface:
 *   live  talks to the FastAPI service (session cookie, JSON).
 *   demo  serves an exported synthetic snapshot (static/demo-data.json) and
 *         applies every action in memory, so the GitHub Pages demo behaves
 *         like the real thing without a server.
 *
 * All text reaches the page through DOM text nodes (see `h`), never innerHTML,
 * so a hostile file name in a log cannot inject markup.
 */
"use strict";

// -- tiny DOM helper ---------------------------------------------------------

// Styles go through the CSSOM, never the style attribute: the server's
// Content-Security-Policy (style-src 'self') blocks inline style attributes.
function setStyle(el, css) {
  for (const decl of String(css).split(";")) {
    const i = decl.indexOf(":");
    if (i > 0) el.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim());
  }
}

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") setStyle(el, v);
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const SVG = "http://www.w3.org/2000/svg";
function s(tag, attrs, ...children) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) el.setAttribute(k, v);
  for (const c of children.flat()) if (c !== null && c !== undefined) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}

// -- formatting --------------------------------------------------------------

const ENGINE_LABEL = { rules: "Rule", statistical: "Statistics", ml: "Model" };
const CONTEXT_LABEL = {
  departing: "Leaving the company", privileged: "Privileged account",
  off_hours: "Off hours", restricted_data: "Restricted data",
};
const DISPOSITION_LABEL = {
  true_positive: "Real threat", benign_positive: "Real but authorised", false_positive: "False alarm",
};
const FEATURES = [
  ["file_read_count", "Files read"],
  ["restricted_file_count", "Restricted files"],
  ["night_event_count", "Night activity"],
  ["total_bytes", "Data moved"],
  ["personal_cloud_bytes", "Personal cloud"],
  ["removable_media_bytes", "USB writes"],
  ["external_email_bytes", "External email"],
  ["privileged_action_count", "Admin commands"],
  ["failed_logon_count", "Failed logons"],
  ["distinct_hosts", "Hosts used"],
];

function fmtBytes(v) {
  if (v >= 1e9) return (v / 1e9).toFixed(1) + " GB";
  if (v >= 1e6) return Math.round(v / 1e6) + " MB";
  if (v >= 1e3) return Math.round(v / 1e3) + " KB";
  return Math.round(v) + " B";
}
function fmtFeature(name, v) {
  return name.endsWith("_bytes") ? fmtBytes(v) : Math.round(v).toLocaleString();
}
function fmtDate(iso, withTime) {
  if (!iso) return "";
  const d = new Date(iso.length === 10 ? iso + "T00:00:00Z" : iso);
  const opts = { day: "numeric", month: "short", timeZone: "UTC" };
  if (withTime) Object.assign(opts, { hour: "2-digit", minute: "2-digit", year: undefined });
  return d.toLocaleString("en-GB", opts);
}
function riskClass(score) { return score >= 85 ? "high" : score >= 70 ? "medium" : ""; }
function engineOf(name) {
  if (name === "behavioural_anomaly") return "ml";
  if (name.startsWith("anomalous_") || name.startsWith("absolute_")) return "statistical";
  return "rules";
}

// -- data sources -------------------------------------------------------------

const PERMISSIONS = {
  analyst: ["cases:read", "cases:feedback", "cases:note", "reveal:request"],
  lead: ["cases:read", "cases:feedback", "cases:note", "reveal:request", "reveal:approve",
         "cases:close", "suppressions:manage", "audit:read"],
  admin: ["users:manage", "audit:read"],
};

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const live = {
  async request(method, path, body) {
    const res = await fetch(path, {
      method, credentials: "same-origin",
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch (_) { /* empty body */ }
    if (!res.ok) {
      let msg = data && data.detail;
      if (Array.isArray(msg)) msg = msg.map((d) => d.msg).join("; ");
      throw new ApiError(res.status, msg || `Request failed (${res.status})`);
    }
    return data;
  },
  get(p) { return this.request("GET", p); },
  post(p, b) { return this.request("POST", p, b || {}); },
  del(p) { return this.request("DELETE", p); },
};

async function sha256(text) {
  if (!window.crypto || !crypto.subtle) return "0".repeat(64);
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function makeDemo(data) {
  const st = {
    role: "analyst",
    cases: structuredClone(data.cases),
    details: structuredClone(data.case_detail),
    reveals: [],
    audit: structuredClone(data.audit.entries).reverse(), // oldest first
  };
  const users = data.users;
  const me = () => ({ username: users[st.role], role: st.role, permissions: PERMISSIONS[st.role] });
  const can = (p) => PERMISSIONS[st.role].includes(p);
  const deny = () => { throw new ApiError(403, "Your role does not allow this"); };
  const now = () => new Date().toISOString();

  async function audit(action, target, details) {
    const prev = st.audit.length ? st.audit[st.audit.length - 1].hash : "0".repeat(64);
    const at = now();
    const actor = users[st.role];
    const body = JSON.stringify(details || {});
    const hash = await sha256(JSON.stringify([prev, at, actor, action, target, body]));
    st.audit.push({ seq: st.audit.length + 1, at, actor, action, target, details: details || {}, prev_hash: prev, hash });
  }
  const pending = () => st.reveals.filter((r) => r.status === "pending").length;

  const routes = [
    ["GET", /^\/api\/me$/, () => me()],
    ["GET", /^\/api\/summary$/, () => {
      const open = st.cases.filter((c) => c.status === "open");
      return { ...data.summary, open_cases: open.length, closed_cases: st.cases.length - open.length,
               high_risk: open.filter((c) => c.risk_score >= 85).length, pending_reveals: pending() };
    }],
    ["GET", /^\/api\/cases(\?status=(\w+))?$/, (m) => {
      const status = m[2] || "open";
      return st.cases.filter((c) => status === "all" || c.status === status);
    }],
    ["GET", /^\/api\/cases\/([\w-]+)$/, async (m) => {
      const id = m[1];
      const base = st.cases.find((c) => c.case_id === id);
      if (!base) throw new ApiError(404, "No such case");
      const d = st.details[id];
      const reqs = st.reveals.filter((r) => r.case_id === id);
      const me_ = users[st.role];
      const approved = reqs.find((r) => r.status === "approved" && (r.requested_by === me_ || r.decided_by === me_));
      await audit("case.view", id, { identity_shown: !!approved });
      return { ...d, ...base, notes: d.notes || [], feedback: d.feedback || [], reveal_requests: reqs,
               identity: approved ? { ...data.identities[id], revealed_by_request: approved.request_id } : null };
    }],
    ["POST", /^\/api\/cases\/([\w-]+)\/feedback$/, async (m, body) => {
      if (!can("cases:feedback")) deny();
      if (body.suppress_days && !can("suppressions:manage")) throw new ApiError(403, "Only a lead can suppress detections");
      const d = st.details[m[1]];
      const names = (d.top_detections || []).map((x) => x.name);
      d.feedback = [{ feedback_id: crypto.randomUUID(), disposition: body.disposition, analyst: users[st.role],
                      note: body.note, at: now(), detection_names: names }, ...(d.feedback || [])];
      await audit("case.feedback", m[1], { disposition: body.disposition });
      return { detections: names, suppressed: body.suppress_days ? names : [] };
    }],
    ["POST", /^\/api\/cases\/([\w-]+)\/notes$/, async (m, body) => {
      if (!can("cases:note")) deny();
      const d = st.details[m[1]];
      d.notes = [...(d.notes || []), { note_id: crypto.randomUUID(), author: users[st.role], body: body.body, at: now() }];
      await audit("case.note", m[1], {});
      return { ok: true };
    }],
    ["POST", /^\/api\/cases\/([\w-]+)\/status$/, async (m, body) => {
      if (!can("cases:close")) deny();
      if (body.status === "closed" && !body.disposition) throw new ApiError(422, "Closing a case needs a disposition");
      const c = st.cases.find((x) => x.case_id === m[1]);
      c.status = body.status;
      if (body.disposition) c.disposition = body.disposition;
      await audit(body.status === "closed" ? "case.close" : "case.reopen", m[1], { disposition: body.disposition || null });
      return { ok: true };
    }],
    ["GET", /^\/api\/reveals$/, () => {
      if (!can("reveal:request")) deny();
      return can("reveal:approve") ? st.reveals : st.reveals.filter((r) => r.requested_by === users[st.role]);
    }],
    ["POST", /^\/api\/reveals$/, async (_m, body) => {
      if (!can("reveal:request")) deny();
      if ((body.reason || "").trim().length < 15)
        throw new ApiError(422, "The reason must describe the investigation, not just name it (15 characters or more).");
      const c = st.cases.find((x) => x.case_id === body.case_id);
      const r = { request_id: crypto.randomUUID(), pseudonym: c.pseudonym, case_id: c.case_id,
                  requested_by: users[st.role], reason: body.reason.trim(), status: "pending",
                  decided_by: null, decided_at: null, created_at: now() };
      st.reveals.unshift(r);
      await audit("reveal.request", c.case_id, { request_id: r.request_id, reason: r.reason });
      return r;
    }],
    ["POST", /^\/api\/reveals\/([\w-]+)\/(approve|deny)$/, async (m) => {
      if (!can("reveal:approve")) deny();
      const r = st.reveals.find((x) => x.request_id === m[1]);
      if (!r) throw new ApiError(404, "No such request");
      if (r.status !== "pending") throw new ApiError(409, `Request already ${r.status}`);
      if (r.requested_by === users[st.role]) throw new ApiError(403, "You cannot decide your own request");
      r.status = m[2] === "approve" ? "approved" : "denied";
      r.decided_by = users[st.role];
      r.decided_at = now();
      await audit(`reveal.${m[2]}`, r.case_id, { request_id: r.request_id, requested_by: r.requested_by });
      return r;
    }],
    ["GET", /^\/api\/rules$/, () => data.rules],
    ["GET", /^\/api\/attack$/, () => data.attack],
    ["GET", /^\/api\/suppressions$/, () => []],
    ["GET", /^\/api\/audit/, () => {
      if (!can("audit:read")) deny();
      return { entries: [...st.audit].reverse(),
               verify: { ok: true, entries: st.audit.length, first_bad_seq: null,
                         head: st.audit.length ? st.audit[st.audit.length - 1].hash : "0".repeat(64) } };
    }],
  ];

  async function request(method, path, body) {
    for (const [m, re, fn] of routes) {
      const match = method === m && path.match(re);
      if (match) return structuredClone(await fn(match, body || {}));
    }
    throw new ApiError(404, "Not available in the demo");
  }
  return {
    demo: true, data, state: st,
    setRole(role) { st.role = role; },
    get: (p) => request("GET", p),
    post: (p, b) => request("POST", p, b),
    del: () => Promise.reject(new ApiError(404, "Not available in the demo")),
  };
}

// -- app state and routing ----------------------------------------------------

const App = { api: live, me: null, summary: null, root: null };

function route() {
  const hash = location.hash.replace(/^#\/?/, "") || "queue";
  const [page, ...rest] = hash.split("/");
  return { page, arg: rest.join("/") };
}
function go(path) { location.hash = "#/" + path; }

async function refreshSummary() {
  if (App.me && App.me.permissions.includes("cases:read")) {
    try { App.summary = await App.api.get("/api/summary"); } catch (_) { App.summary = null; }
  }
}

async function boot() {
  App.root = document.getElementById("app");
  const mode = document.querySelector('meta[name="sentry-mode"]').content;
  if (mode === "demo") {
    const data = await fetch("static/demo-data.json").then((r) => r.json());
    App.api = makeDemo(data);
  }
  try {
    App.me = await App.api.get("/api/me");
  } catch (e) {
    if (e.status === 401) return renderLogin();
    return fail(e);
  }
  await refreshSummary();
  window.addEventListener("hashchange", render);
  render();
}

function fail(err) {
  App.root.replaceChildren(h("main", {}, h("div", { class: "flash err" }, err.message || String(err))));
}

// -- shell -------------------------------------------------------------------

function nav() {
  const { page } = route();
  const can = (p) => App.me.permissions.includes(p);
  const sum = App.summary || {};
  const item = (id, label, count, alert) =>
    h("li", {}, h("a", { href: "#/" + id, "aria-current": page === id || (page === "case" && id === "queue") ? "page" : null },
      h("span", {}, label),
      count !== undefined && count !== null ? h("span", { class: "count" + (alert ? " alert" : "") }, count) : null));
  const items = [];
  if (can("cases:read")) {
    items.push(item("queue", "Case queue", sum.open_cases));
    items.push(item("attack", "ATT&CK coverage"));
    items.push(item("rules", "Detection rules"));
  }
  if (can("reveal:request")) items.push(item("reveals", "Identity requests", sum.pending_reveals || null, sum.pending_reveals > 0));
  if (can("audit:read")) items.push(item("audit", "Audit log"));
  if (can("users:manage")) items.push(item("users", "Accounts"));

  return h("nav", { class: "nav", "aria-label": "Main" },
    h("a", { class: "brand", href: "#/queue" }, h("img", { src: "static/favicon.svg", alt: "" }), h("b", {}, "Sentry")),
    h("ul", {}, items),
    h("div", { class: "whoami" },
      h("span", {}, "Signed in as ", h("strong", {}, App.me.username), " (", App.me.role, ")"),
      App.api.demo ? null : h("button", { class: "linkish", onclick: logout }, "Sign out")));
}

function demoBar() {
  if (!App.api.demo) return null;
  const role = App.me.role;
  const pick = async (r) => {
    App.api.setRole(r);
    App.me = await App.api.get("/api/me");
    await refreshSummary();
    if (route().page === "audit" && r !== "lead") go("queue");
    render();
  };
  return h("div", { class: "demo-bar", role: "region", "aria-label": "Demo controls" },
    h("span", {}, "Demo on synthetic data. Nothing you do here is saved."),
    h("span", { class: "roles" },
      h("button", { "aria-pressed": String(role === "analyst"), onclick: () => pick("analyst") }, "Analyst"),
      h("button", { "aria-pressed": String(role === "lead"), onclick: () => pick("lead") }, "Lead")),
    h("span", {}, "Try asking for an identity as the analyst, then approve it as the lead."),
    h("a", { href: "https://github.com/thespaceio/sentry-itds" }, "Source on GitHub"));
}

async function logout() {
  await App.api.post("/api/logout");
  App.me = null;
  renderLogin();
}

async function render() {
  const { page, arg } = route();
  const main = h("main", { id: "main" }, h("p", { class: "muted" }, "Loading"));
  App.root.replaceChildren(demoBar() || "", nav(), main);
  const pages = { queue: pageQueue, case: pageCase, attack: pageAttack, rules: pageRules,
                  reveals: pageReveals, audit: pageAudit, users: pageUsers };
  const fn = pages[page] || pageQueue;
  try {
    const content = await fn(arg);
    main.replaceChildren(...[content].flat());
  } catch (e) {
    main.replaceChildren(h("div", { class: "flash err" }, e.status === 403 ? "Your role cannot open this page." : e.message));
  }
  window.scrollTo(0, 0);
}

// -- login -------------------------------------------------------------------

function renderLogin(message) {
  const err = h("div", { class: "flash err", hidden: !message }, message || "");
  const form = h("form", {
    onsubmit: async (ev) => {
      ev.preventDefault();
      const fd = new FormData(form);
      try {
        await App.api.post("/api/login", { username: fd.get("username"), password: fd.get("password") });
        App.me = await App.api.get("/api/me");
        await refreshSummary();
        window.addEventListener("hashchange", render);
        render();
      } catch (e) {
        err.textContent = e.message;
        err.hidden = false;
      }
    },
  },
    h("h1", {}, h("img", { src: "static/favicon.svg", alt: "" }), "Sign in to Sentry"),
    h("p", { class: "muted small" }, "Cases are pseudonymous. Every action you take here is recorded in the audit log."),
    err,
    h("label", {}, "Username", h("input", { type: "text", name: "username", autocomplete: "username", required: true })),
    h("label", {}, "Password", h("input", { type: "password", name: "password", autocomplete: "current-password", required: true })),
    h("button", { class: "btn primary", type: "submit" }, "Sign in"));
  App.root.replaceChildren(h("div", { class: "login" }, form));
}

// -- shared pieces -------------------------------------------------------------

function tape(pseudonym, big) {
  return h("span", { class: "tape" + (big ? " big" : ""), title: "Pseudonym. The real identity is hidden until a two-person reveal." }, pseudonym);
}

function composition(c) {
  const contrib = (c.breakdown && c.breakdown.contributions) || {};
  const engines = { rules: 0, statistical: 0, ml: 0 };
  const known = Object.fromEntries((c.top_detections || []).map((d) => [d.name, d.engine]));
  for (const [name, v] of Object.entries(contrib)) engines[known[name] || engineOf(name)] += v;
  const total = Object.values(engines).reduce((a, b) => a + b, 0) || 1;
  const parts = Object.entries(engines).filter(([, v]) => v > 0);
  const label = parts.map(([e, v]) => `${ENGINE_LABEL[e]} ${Math.round((100 * v) / total)}%`).join(", ");
  return h("div", { class: "composition", role: "img", "aria-label": "What drove the score: " + label, title: label },
    parts.map(([e, v]) => h("span", { class: "eng-" + e, style: `width:${(100 * v) / total}%` })));
}

function contextChips(list) {
  return (list || []).map((c) => h("span", { class: "chip ctx-" + c }, CONTEXT_LABEL[c] || c));
}

// -- queue -------------------------------------------------------------------

async function pageQueue() {
  const sum = await App.api.get("/api/summary");
  App.summary = sum;
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  const status = params.get("status") || "open";
  const cases = await App.api.get("/api/cases?status=" + status);

  const n = sum.alert_budget;
  const open = sum.open_cases;
  const budget = h("section", { class: "budget", "aria-label": "Alert budget" },
    h("div", { class: "budget-top" },
      h("p", {}, h("strong", {}, `${open} of ${n}`), " cases in today's review budget"),
      h("p", { class: "muted small" }, `A case opens at risk ${sum.case_threshold}. The budget is what one analyst can review properly in a day.`)),
    h("div", { class: "slots", style: `--n:${n}`, "aria-hidden": "true" },
      Array.from({ length: n }, (_, i) => {
        const c = status === "open" ? cases[i] : null;
        const filled = i < open;
        return h("span", { class: "slot" + (filled ? " filled" : "") + (c && c.risk_score >= 85 ? " high" : ""), title: c ? `${c.pseudonym}: risk ${c.risk_score}` : "" });
      })),
    h("div", { class: "budget-facts" },
      h("span", {}, h("b", {}, sum.high_risk), " at risk 85 or more"),
      h("span", {}, h("b", {}, sum.pending_reveals), " identity request" + (sum.pending_reveals === 1 ? "" : "s") + " waiting"),
      sum.last_run ? h("span", {}, "Last run scored ", h("b", {}, (sum.last_run.events_scored || 0).toLocaleString()), " events from ", fmtDate(sum.last_run.scored_from)) : null,
      sum.active_suppressions ? h("span", {}, h("b", {}, sum.active_suppressions), " active suppressions") : null));

  const tab = (value, label) => h("button", {
    "aria-pressed": String(status === value),
    onclick: () => { location.hash = "#/queue" + (value === "open" ? "" : "?status=" + value); },
  }, label);

  const list = cases.length
    ? h("ol", { class: "queue" }, cases.map((c, i) => {
        const top = (c.top_detections || [])[0];
        return h("li", { class: c.status === "closed" ? "status-closed" : "" },
          h("a", { class: "case-row", href: "#/case/" + c.case_id },
            h("span", { class: "rank" }, "#" + (i + 1)),
            h("div", {}, tape(c.pseudonym), h("p", { class: "muted small", style: "margin-top:6px" }, "Since " + fmtDate(c.opened_at))),
            h("div", { class: "score " + riskClass(c.risk_score) }, Math.round(c.risk_score), h("small", {}, c.status === "closed" ? DISPOSITION_LABEL[c.disposition] || "Closed" : "risk")),
            h("div", { class: "why" },
              top ? h("p", {}, top.explanation) : null,
              composition(c),
              h("div", { class: "chips" }, contextChips(c.context),
                (c.attack || []).slice(0, 4).map((t) => h("span", { class: "chip technique" }, t))))));
      }))
    : h("div", { class: "queue empty" },
        h("h2", {}, status === "open" ? "No open cases" : "No closed cases"),
        h("p", {}, status === "open" ? "Nobody's accumulated risk has crossed the threshold. Run the pipeline again after new logs arrive." : "Closed cases appear here with the verdict they were closed with."));

  return [
    h("div", { class: "page-head" },
      h("div", {}, h("h1", {}, "Case queue"),
        h("p", {}, "People are ranked by accumulated risk, not by single alerts. Each case explains itself, and nobody's name is shown until a lead approves a written request.")),
      h("div", { class: "tabs", role: "group", "aria-label": "Case status" }, tab("open", "Open"), tab("closed", "Closed"), tab("all", "All"))),
    budget,
    h("div", { class: "legend", style: "margin:0 0 10px 2px" }, "What drove each score:",
      ["rules", "statistical", "ml"].map((e) => h("span", {}, h("i", { class: "eng-" + e }), ENGINE_LABEL[e]))),
    list,
  ];
}

// -- case detail ---------------------------------------------------------------

function timelineChart(detail) {
  const days = detail.timeline || [];
  if (!days.length) return h("p", { class: "muted" }, "No daily activity was stored for this case.");
  const flagged = new Set(Object.keys(detail.detections_by_day || {}));

  // Pick the feature that changed most in the scored window as the default.
  const score = (f) => {
    const train = days.filter((d) => !d.scored).map((d) => d.features[f] || 0);
    const win = days.filter((d) => d.scored).map((d) => d.features[f] || 0);
    const mean = train.length ? train.reduce((a, b) => a + b, 0) / train.length : 0;
    return Math.max(0, ...win) / (mean + 1);
  };
  const available = FEATURES.filter(([f]) => days.some((d) => d.features[f]));
  let current = available.slice().sort((a, b) => score(b[0]) - score(a[0]))[0] || FEATURES[0];

  const holder = h("div", {});
  const controls = h("div", { class: "chart-controls", role: "group", "aria-label": "Measure" });
  const draw = () => {
    const [f, label] = current;
    const W = 720, H = 230, L = 52, R = 12, T = 14, B = 28;
    const vals = days.map((d) => d.features[f] || 0);
    const max = Math.max(1, ...vals) * 1.08;
    const x = (i) => L + (i * (W - L - R)) / Math.max(1, days.length - 1);
    const y = (v) => T + (H - T - B) * (1 - v / max);
    const train = days.filter((d) => !d.scored).map((d) => d.features[f] || 0);
    const mean = train.length ? train.reduce((a, b) => a + b, 0) / train.length : 0;
    const sd = train.length > 1 ? Math.sqrt(train.reduce((a, b) => a + (b - mean) ** 2, 0) / (train.length - 1)) : 0;
    const firstScored = days.findIndex((d) => d.scored);
    const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img",
      "aria-label": `${label} per day. Usual level about ${fmtFeature(f, mean)}. Peak ${fmtFeature(f, Math.max(...vals))}.` });
    if (firstScored >= 0) svg.append(s("rect", { class: "window", x: x(firstScored) - 4, y: T, width: W - R - x(firstScored) + 4, height: H - T - B }));
    svg.append(s("rect", { class: "baseline", x: L, y: y(Math.min(max, mean + sd)), width: W - L - R, height: Math.max(1, y(Math.max(0, mean - sd)) - y(Math.min(max, mean + sd))) }));
    for (let k = 0; k <= 4; k++) {
      const v = (max * k) / 4;
      svg.append(s("line", { class: "grid", x1: L, x2: W - R, y1: y(v), y2: y(v) }));
      svg.append(s("text", { x: L - 8, y: y(v) + 4, "text-anchor": "end" }, fmtFeature(f, v)));
    }
    const step = Math.max(1, Math.ceil(days.length / 8));
    days.forEach((d, i) => { if (i % step === 0) svg.append(s("text", { x: x(i), y: H - 8, "text-anchor": "middle" }, fmtDate(d.day))); });
    if (firstScored >= 0) svg.append(s("text", { x: x(firstScored) + 4, y: T + 12 }, "Scored window"));
    svg.append(s("text", { x: L + 6, y: y(Math.min(max, mean + sd)) - 4 }, "Usual range"));
    svg.append(s("path", { class: "line", stroke: "var(--ink)", d: vals.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("") }));
    days.forEach((d, i) => {
      if (flagged.has(d.day)) svg.append(s("circle", { cx: x(i), cy: y(vals[i]), r: 4.5, fill: "var(--crimson)" },
        s("title", {}, `${fmtDate(d.day)}: ${fmtFeature(f, vals[i])}, findings recorded`)));
    });
    holder.replaceChildren(svg);
    controls.replaceChildren(...available.map((pair) =>
      h("button", { "aria-pressed": String(pair[0] === f), onclick: () => { current = pair; draw(); } }, pair[1])));
  };
  draw();
  return [controls, holder,
    h("p", { class: "muted small", style: "margin-top:6px" }, "Red dots mark days with findings. The grey band is this person's usual range before the scored window.")];
}

function withoutTitle(d) {
  const prefix = (d.title || "") + ": ";
  const text = d.explanation || "";
  return text.startsWith(prefix) ? text.charAt(prefix.length).toUpperCase() + text.slice(prefix.length + 1) : text;
}

function finding(d) {
  return h("div", { class: "finding" },
    h("span", { class: "bar eng-" + d.engine, "aria-hidden": "true" }),
    h("div", {},
      h("h3", {}, d.title, h("span", { class: "sev sev-" + d.severity }, d.severity), h("span", { class: "muted small" }, ENGINE_LABEL[d.engine] + ", " + fmtDate(d.day))),
      h("p", {}, withoutTitle(d)),
      h("div", { class: "chips" }, (d.attack || []).map((t) => h("span", { class: "chip technique" }, t)))));
}

async function pageCase(id) {
  const d = await App.api.get("/api/cases/" + encodeURIComponent(id));
  const can = (p) => App.me.permissions.includes(p);
  const flash = h("div", { class: "flash", hidden: true, role: "status" });
  const say = (msg, ok = true) => { flash.className = "flash " + (ok ? "ok" : "err"); flash.textContent = msg; flash.hidden = false; };
  const act = async (fn, okMsg) => {
    try { await fn(); await refreshSummary(); await render(); } catch (e) { say(e.message, false); return; }
    const f = document.querySelector('[role="status"]');
    if (f && okMsg) { f.className = "flash ok"; f.textContent = okMsg; f.hidden = false; }
  };

  // Identity
  const myPending = (d.reveal_requests || []).find((r) => r.status === "pending" && r.requested_by === App.me.username);
  const ident = d.identity;
  const identityBox = h("span", { class: "identity" + (ident ? " revealed" : "") },
    ident ? h("span", { class: "who" }, `${ident.display_name || ident.actor_id}`) : null,
    tape(d.pseudonym, true));
  const reasonInput = h("textarea", { rows: 3, name: "reason", maxlength: 2000,
    placeholder: "Which investigation needs this, and why the behaviour alone is not enough" });
  const identityPanel = h("section", { class: "panel" },
    h("h2", {}, "Identity"),
    ident
      ? h("p", {}, `${ident.display_name}, ${ident.role || "role unknown"}, ${ident.department || "no department"}. Visible to you because request ${String(ident.revealed_by_request).slice(0, 8)} was approved. This view is in the audit log.`)
      : myPending
        ? h("p", {}, "Your request is waiting for a lead to approve it. You will see the name here once they do.")
        : can("reveal:request")
          ? h("form", { class: "actions", onsubmit: (ev) => { ev.preventDefault();
              act(() => App.api.post("/api/reveals", { case_id: d.case_id, reason: reasonInput.value }), "Request sent to the leads."); } },
              h("p", { class: "muted small" }, "Investigate the behaviour first. If you need to know who this is, a lead other than you has to approve a written reason."),
              h("label", {}, "Reason", reasonInput),
              h("button", { class: "btn", type: "submit" }, "Ask to see who this is"))
          : h("p", { class: "muted" }, "Hidden."));

  // Verdict
  let chosen = null;
  const note = h("textarea", { rows: 2, maxlength: 2000, placeholder: "What you found" });
  const suppress = h("input", { type: "checkbox" });
  const verdictBtns = Object.entries(DISPOSITION_LABEL).map(([k, label]) =>
    h("button", { type: "button", class: "btn verdict", "aria-pressed": "false",
      onclick: (ev) => { chosen = k; verdictBtns.forEach((b) => b.setAttribute("aria-pressed", String(b === ev.currentTarget))); } }, label));
  const verdictPanel = can("cases:feedback") ? h("section", { class: "panel" },
    h("h2", {}, "Your verdict"),
    h("p", { class: "sub" }, "Verdicts teach Sentry which detections are worth their weight."),
    h("form", { class: "actions", onsubmit: (ev) => { ev.preventDefault();
        if (!chosen) return say("Pick a verdict first.", false);
        act(() => App.api.post(`/api/cases/${d.case_id}/feedback`, { disposition: chosen, note: note.value,
          suppress_days: chosen === "false_positive" && suppress.checked ? 30 : null }), "Verdict recorded."); } },
      h("div", { class: "verdicts" }, verdictBtns),
      h("label", {}, "Note", note),
      can("suppressions:manage") ? h("label", { class: "check" }, suppress, "If it is a false alarm, mute these detections for this person for 30 days") : null,
      h("button", { class: "btn primary", type: "submit" }, "Record verdict")),
    (d.feedback || []).length ? h("div", { style: "margin-top:14px" }, d.feedback.map((f) =>
      h("div", { class: "note" }, h("div", { class: "by" }, `${DISPOSITION_LABEL[f.disposition]}, ${f.analyst}, ${fmtDate(f.at, true)}`), f.note || ""))) : null) : null;

  // Notes
  const noteBody = h("textarea", { rows: 3, maxlength: 4000, placeholder: "Add a note for whoever picks this up next" });
  const notesPanel = h("section", { class: "panel" },
    h("h2", {}, "Notes"),
    (d.notes || []).length ? d.notes.map((n) => h("div", { class: "note" }, h("div", { class: "by" }, `${n.author}, ${fmtDate(n.at, true)}`), n.body)) : h("p", { class: "muted small" }, "No notes yet."),
    can("cases:note") ? h("form", { class: "actions", style: "margin-top:12px", onsubmit: (ev) => { ev.preventDefault();
        if (!noteBody.value.trim()) return;
        act(() => App.api.post(`/api/cases/${d.case_id}/notes`, { body: noteBody.value }), "Note added."); } },
      noteBody, h("button", { class: "btn", type: "submit" }, "Add note")) : null);

  // Close / reopen
  const closeSel = h("select", {}, Object.entries(DISPOSITION_LABEL).map(([k, l]) => h("option", { value: k }, l)));
  const closePanel = can("cases:close") ? h("section", { class: "panel" },
    h("h2", {}, d.status === "open" ? "Close this case" : "Case closed"),
    d.status === "open"
      ? h("form", { class: "actions", onsubmit: (ev) => { ev.preventDefault();
          act(() => App.api.post(`/api/cases/${d.case_id}/status`, { status: "closed", disposition: closeSel.value }), "Case closed."); } },
          h("label", {}, "Outcome", closeSel), h("button", { class: "btn primary", type: "submit" }, "Close case"))
      : h("div", { class: "actions" }, h("p", {}, "Outcome: " + (DISPOSITION_LABEL[d.disposition] || "not recorded")),
          h("button", { class: "btn", onclick: () => act(() => App.api.post(`/api/cases/${d.case_id}/status`, { status: "open" }), "Case reopened.") }, "Reopen case"))) : null;

  const attackPanel = h("section", { class: "panel" },
    h("h2", {}, "MITRE ATT&CK"),
    h("p", { class: "sub" }, "Techniques the evidence in this case is consistent with."),
    (d.attack_detail || []).map((t) => h("p", { style: "margin-bottom:8px" },
      h("a", { href: t.url, target: "_blank", rel: "noopener noreferrer" }, `${t.id} ${t.name}`), h("br"),
      h("span", { class: "muted small" }, t.tactic))));

  const days = Object.entries(d.detections_by_day || {});
  return [
    h("a", { class: "back", href: "#/queue" }, "Back to the queue"),
    h("div", { class: "case-head" },
      h("div", {}, identityBox,
        h("div", { class: "meta" },
          h("span", {}, "Case " + d.case_id),
          h("span", {}, "Opened " + fmtDate(d.opened_at)),
          h("span", {}, `${d.detection_count} findings from ${d.engines.map((e) => ENGINE_LABEL[e]).join(", ").toLowerCase()}`),
          d.status === "closed" ? h("span", {}, "Closed: " + (DISPOSITION_LABEL[d.disposition] || "")) : null),
        h("div", { class: "chips", style: "margin-top:10px" }, contextChips(d.context),
          App.api.demo && App.api.data.labels[d.case_id]
            ? h("span", { class: "chip", title: "Ground truth from the synthetic generator. A real deployment has no labels." },
                "Planted scenario: " + App.api.data.labels[d.case_id].replace(/_/g, " "))
            : null)),
      h("div", { class: "case-score" }, h("div", { class: "score " + riskClass(d.risk_score) }, Math.round(d.risk_score), h("small", {}, "risk out of 100")),
        h("div", { style: "margin-top:10px; width:200px; margin-left:auto" }, composition(d)))),
    flash,
    h("div", { class: "grid-2" },
      h("div", {},
        h("section", { class: "panel" }, h("h2", {}, "Why Sentry opened this case"), (d.top_detections || []).map(finding)),
        h("section", { class: "panel" }, h("h2", {}, "Activity over time"), timelineChart(d)),
        h("section", { class: "panel" }, h("h2", {}, "Every finding, by day"),
          h("div", { class: "days" }, days.map(([day, list]) => h("div", { class: "day" },
            h("h3", {}, fmtDate(day)),
            list.map((x) => h("div", { class: "det" }, h("span", { class: "eng " + x.engine }, ENGINE_LABEL[x.engine]), h("span", {}, x.explanation)))))))),
      h("div", {}, identityPanel, verdictPanel, notesPanel, closePanel, attackPanel)),
  ];
}

// -- ATT&CK ------------------------------------------------------------------

async function pageAttack() {
  const matrix = await App.api.get("/api/attack");
  const covered = matrix.flatMap((t) => t.techniques).filter((t) => t.rules.length || t.features.length).length;
  const total = matrix.flatMap((t) => t.techniques).length;
  return [
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "ATT&CK coverage"),
      h("p", {}, `${covered} of the ${total} techniques Sentry can observe from activity metadata have at least one rule or measured feature behind them. A coloured edge means open cases show that technique right now.`))),
    h("div", { class: "matrix" }, matrix.map((col) => h("section", { class: "tactic" },
      h("h2", {}, col.tactic),
      col.techniques.map((t) => h("a", { class: "tech" + (t.open_cases >= 2 ? " hot" : t.open_cases ? " warm" : ""), href: t.url, target: "_blank", rel: "noopener noreferrer" },
        h("b", {}, `${t.id} ${t.name}`),
        h("div", { class: "cov" }, [t.rules.length ? `${t.rules.length} rule${t.rules.length > 1 ? "s" : ""}` : null,
          t.features.length ? `${t.features.length} measured feature${t.features.length > 1 ? "s" : ""}` : null,
          t.open_cases ? `${t.open_cases} open case${t.open_cases > 1 ? "s" : ""}` : null].filter(Boolean).join(", ") || "Not covered")))))),
  ];
}

// -- rules -------------------------------------------------------------------

async function pageRules() {
  const { rules } = await App.api.get("/api/rules");
  return [
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Detection rules"),
      h("p", {}, "Rules are YAML files anyone can read and review. Precision comes from analysts' verdicts; a rule with five or more verdicts and under 20% precision is marked for tuning."))),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Rule"), h("th", {}, "Severity"), h("th", {}, "Fires when"), h("th", {}, "ATT&CK"), h("th", {}, "Verdicts"), h("th", {}, "Precision"))),
      h("tbody", {}, rules.map((r) => h("tr", {},
        h("td", {}, h("b", {}, r.title), h("div", { class: "muted small" }, r.description)),
        h("td", {}, h("span", { class: "sev-" + r.severity }, r.severity)),
        h("td", { class: "small" }, r.kind === "match" ? "A matching event occurs" : r.conditions.join(" and "),
          r.require_context.length ? h("div", { class: "muted" }, "Only if: " + r.require_context.join(", ")) : null),
        h("td", { class: "small" }, r.attack.map((t) => h("div", {}, t.id))),
        h("td", { class: "num" }, r.health ? r.health.verdicts : 0),
        h("td", { class: "num" }, r.health && r.health.precision !== null ? Math.round(r.health.precision * 100) + "%" : "",
          r.health && r.health.needs_tuning ? h("div", { class: "sev-high small" }, "Needs tuning") : null)))))),
  ];
}

// -- reveal requests -------------------------------------------------------------

async function pageReveals() {
  const reqs = await App.api.get("/api/reveals");
  const canApprove = App.me.permissions.includes("reveal:approve");
  const decide = async (r, verb) => {
    try { await App.api.post(`/api/reveals/${r.request_id}/${verb}`); await refreshSummary(); render(); }
    catch (e) { alert(e.message); }
  };
  return [
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Identity requests"),
      h("p", {}, canApprove
        ? "An analyst needs a lead's approval to see who is behind a pseudonym. You cannot approve your own requests, and every decision is in the audit log."
        : "Requests you have made to see who is behind a pseudonym."))),
    reqs.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Pseudonym"), h("th", {}, "Requested by"), h("th", {}, "Reason"), h("th", {}, "Status"), h("th", {}, ""))),
      h("tbody", {}, reqs.map((r) => h("tr", {},
        h("td", {}, h("a", { href: "#/case/" + r.case_id }, tape(r.pseudonym))),
        h("td", {}, r.requested_by, h("div", { class: "muted small" }, fmtDate(r.created_at, true))),
        h("td", { class: "small", style: "max-width:42ch" }, r.reason),
        h("td", {}, h("span", { class: "status-pill " + r.status }, r.status), r.decided_by ? h("div", { class: "muted small" }, "by " + r.decided_by) : null),
        h("td", {}, canApprove && r.status === "pending" && r.requested_by !== App.me.username
          ? h("div", { class: "chips" }, h("button", { class: "btn primary", onclick: () => decide(r, "approve") }, "Approve"), h("button", { class: "btn danger", onclick: () => decide(r, "deny") }, "Deny"))
          : null))))))
      : h("div", { class: "queue empty" }, h("h2", {}, "No requests"), h("p", {}, "Requests appear here when an analyst asks to see who is behind a case.")),
  ];
}

// -- audit -------------------------------------------------------------------

async function pageAudit() {
  const { entries, verify } = await App.api.get("/api/audit?limit=300");
  return [
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Audit log"),
      h("p", {}, "Every sign in, case view, verdict and identity decision, hash-chained so that editing or deleting any entry breaks every hash after it."))),
    h("div", { class: "chain " + (verify.ok ? "ok" : "bad"), role: "status" },
      h("b", {}, verify.ok ? `Chain intact across ${verify.entries} entries` : `Chain broken at entry ${verify.first_bad_seq}`),
      h("span", { class: "hash" }, "Latest hash " + String(verify.head).slice(0, 24))),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "#"), h("th", {}, "When"), h("th", {}, "Who"), h("th", {}, "Action"), h("th", {}, "Target"), h("th", {}, "Hash"))),
      h("tbody", {}, entries.map((e) => h("tr", {},
        h("td", { class: "num muted" }, e.seq), h("td", { class: "small" }, fmtDate(e.at, true)),
        h("td", {}, e.actor), h("td", {}, e.action), h("td", { class: "small" }, e.target || ""),
        h("td", { class: "hash" }, String(e.hash).slice(0, 12))))))),
  ];
}

// -- accounts ------------------------------------------------------------------

async function pageUsers() {
  const users = await App.api.get("/api/users");
  const msg = h("div", { class: "flash", hidden: true });
  const form = h("form", { class: "panel actions", style: "max-width:420px; margin-top:18px", onsubmit: async (ev) => {
      ev.preventDefault();
      const fd = new FormData(form);
      try {
        await App.api.post("/api/users", { username: fd.get("username"), password: fd.get("password"), role: fd.get("role") });
        render();
      } catch (e) { msg.className = "flash err"; msg.textContent = e.message; msg.hidden = false; }
    } },
    h("h2", {}, "Add an account"), msg,
    h("label", {}, "Username", h("input", { type: "text", name: "username", required: true })),
    h("label", {}, "Password (12 characters or more)", h("input", { type: "password", name: "password", required: true, minlength: 12, autocomplete: "new-password" })),
    h("label", {}, "Role", h("select", { name: "role" }, ["analyst", "lead", "admin"].map((r) => h("option", { value: r }, r)))),
    h("button", { class: "btn primary", type: "submit" }, "Add account"));
  return [
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Accounts"),
      h("p", {}, "Admins manage accounts but cannot read cases or approve identity requests. Keep those duties with different people."))),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Username"), h("th", {}, "Role"), h("th", {}, "Created"), h("th", {}, "State"), h("th", {}, ""))),
      h("tbody", {}, users.map((u) => h("tr", {},
        h("td", {}, u.username), h("td", {}, u.role), h("td", { class: "small" }, fmtDate(u.created_at)),
        h("td", {}, u.disabled ? "Disabled" : "Active"),
        h("td", {}, !u.disabled && u.username !== App.me.username ? h("button", { class: "btn danger", onclick: async () => {
          await App.api.post(`/api/users/${encodeURIComponent(u.username)}/disable`); render(); } }, "Disable") : null)))))),
    form,
  ];
}

document.addEventListener("DOMContentLoaded", boot);
