"use strict";
// BugBane UI: a calm examination record. Vanilla JS; the server is the source of truth
// (polled once a second); screens are rendered into #app, with small regions updated in place.

// ---- bootstrap -----------------------------------------------------------------------------------
const params = new URLSearchParams(location.search);
const store = {
  get(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } },
  set(k, v) { try { sessionStorage.setItem(k, v); } catch (e) { /* private mode */ } },
};
if (params.get("t")) store.set("bugbane-token", params.get("t"));
const TOKEN = params.get("t") || store.get("bugbane-token");
const DEMO = params.get("demo");
if (params.get("t")) history.replaceState(null, "", DEMO ? `/?demo=${encodeURIComponent(DEMO)}` : "/");

const ui = {
  lang: null, S: {}, local: "lang", learnIdx: 0, mode: "full",
  consentOwn: false, consentProcess: false, consentHistory: false, forget: true,
  state: null, screen: null, regions: {}, startedAt: null, offline: false, error: null,
  history: [], viewing: null, done: null, config: {},
  lastStep: null, lastPrompt: null, dialogOpen: false,
};
const app = document.getElementById("app");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ---- i18n (same format as app/scan/i18n.py) ----------------------------------------------------------
const EN_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const HU_MONTHS = ["jan.", "febr.", "márc.", "ápr.", "máj.", "jún.", "júl.", "aug.", "szept.", "okt.", "nov.", "dec."];
function fmtNum(n) {
  if (ui.lang === "hu") return Math.abs(n) >= 10000 ? n.toLocaleString("en-US").replace(/,/g, " ") : String(n);
  return n.toLocaleString("en-US");
}
function fmtDate(ts, withTime) {
  const d = new Date(ts * 1000);
  const hm = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  const s = ui.lang === "hu"
    ? `${d.getFullYear()}. ${HU_MONTHS[d.getMonth()]} ${d.getDate()}.`
    : `${d.getDate()} ${EN_MONTHS[d.getMonth()]} ${d.getFullYear()}`;
  return withTime ? `${s} ${hm}` : s;
}
function T(key, p = {}) {
  const tpl = ui.S[key] ?? key;
  const val = (v) => {
    if (Array.isArray(v)) return v.map(val).join(", ");
    if (v && typeof v === "object") {
      if (v.t) return T(v.t, v.p || {});
      if (v.d) return fmtDate(v.d, false);
      if (v.dt) return fmtDate(v.dt, true);
      if (v.gb != null) return `${ui.lang === "hu" ? v.gb.toFixed(1).replace(".", ",") : v.gb.toFixed(1)} GB`;
    }
    if (typeof v === "number") return fmtNum(v);
    return esc(v);
  };
  const out = tpl.replace(/\{(\w+)\}/g, (m, k) => (k in p ? val(p[k]) : m));
  // Hungarian suffixes hang off a hyphen ("iPhone-on"); a non-breaking hyphen keeps "on" off its own line
  return ui.lang === "hu" ? out.replace(/(iPhone|Mac)-/g, "$1\u2011") : out;
}
async function setLang(lang) {
  ui.lang = lang;
  ui.S = await (await fetch(`/i18n/${lang}.json`)).json();
  document.documentElement.lang = lang;
  store.set("bugbane-lang", lang);
  ui.screen = null;
  chrome();
  render();
}
function chrome() {
  for (const [id, key] of [["nav-learn", "nav.learn"], ["nav-history", "nav.history"], ["nav-privacy", "nav.privacy"], ["nav-quit", "nav.quit"]]) {
    document.getElementById(id).textContent = T(key);
  }
  document.querySelectorAll(".seg button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.lang === ui.lang)));
  const upd = ui.state && ui.state.update, link = document.getElementById("nav-update");
  link.hidden = !upd;
  if (upd) { link.textContent = T("nav.update", { v: upd.latest }); link.href = upd.url; }
}

// ---- API ------------------------------------------------------------------------------------------
async function api(path, body) {
  const opts = { headers: { "X-Token": TOKEN || "" } };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
const act = (payload) => api("/api/act", payload);
const reportUrl = (id, download) => `/api/report?t=${encodeURIComponent(TOKEN)}&lang=${ui.lang}${id ? `&id=${encodeURIComponent(id)}` : ""}${download ? "&download=1" : ""}`;
const supportUrl = (download) => `/api/support-log?t=${encodeURIComponent(TOKEN)}${download ? "&download=1" : ""}`;

// ---- glyphs and drawings --------------------------------------------------------------------------
const g = (id, size = 16, cls = "") => `<svg class="g ${cls}" width="${size}" height="${size}" aria-hidden="true"><use href="#g-${id}"/></svg>`;
const lv = (level, size = 16) => g(level, size, `l-${level}`);

// Instruction drawings: line art, iOS screens in greyscale, the part to press or tap in plum.
const phone = (inner, w = 168) => `
<svg class="illus" viewBox="0 0 168 300" width="${w}" aria-hidden="true">
  <rect x="24" y="8" width="120" height="250" rx="22" fill="var(--sheet)" stroke="currentColor" stroke-width="1.5"/>
  <rect x="68" y="18" width="32" height="9" rx="4.5" fill="none" stroke="var(--ink-3)" stroke-width="1.25"/>
  ${inner}
</svg>`;
const SVG = {
  connect: () => `
<svg class="illus" viewBox="0 0 220 170" width="200" aria-hidden="true">
  <rect x="88" y="22" width="122" height="80" rx="6" fill="var(--sheet)" stroke="currentColor" stroke-width="1.5"/>
  <path d="M74 112h150l-10 12H84z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
  <rect x="14" y="50" width="44" height="86" rx="9" fill="var(--sheet)" stroke="currentColor" stroke-width="1.5"/>
  <rect x="29" y="56" width="14" height="4" rx="2" fill="none" stroke="var(--ink-3)" stroke-width="1"/>
  <path d="M36 136v14c0 8 6 12 14 12h120c8 0 12-6 12-14v-24" fill="none" stroke="var(--actaea)" stroke-width="1.75" stroke-linecap="round"/>
  <rect x="178" y="118" width="8" height="6" rx="1.5" class="press pulse"/>
</svg>`,
  trust: () => phone(`
  <rect x="36" y="94" width="96" height="118" rx="12" fill="var(--fill)"/>
  <text x="84" y="118" text-anchor="middle" font-size="10.5" font-weight="600" fill="var(--ink)">${T("svg.trust.l1")}</text>
  <text x="84" y="131" text-anchor="middle" font-size="10.5" font-weight="600" fill="var(--ink)">${T("svg.trust.l2")}</text>
  <text x="84" y="147" text-anchor="middle" font-size="7.5" fill="var(--ink-2)">${T("svg.trust.b1")}</text>
  <text x="84" y="157" text-anchor="middle" font-size="7.5" fill="var(--ink-2)">${T("svg.trust.b2")}</text>
  <line x1="36" y1="168" x2="132" y2="168" stroke="var(--rule-strong)"/>
  <rect x="44" y="174" width="80" height="18" rx="6" class="press pulse"/>
  <text x="84" y="187" text-anchor="middle" font-size="10" font-weight="600" fill="var(--c-graphite)">${T("svg.trust.yes")}</text>
  <text x="84" y="205" text-anchor="middle" font-size="9.5" fill="var(--ink-2)">${T("svg.trust.no")}</text>`),
  passcode: (w = 140) => phone(`
  <text x="84" y="84" text-anchor="middle" font-size="10.5" font-weight="600" fill="var(--ink)">${T("svg.passcode")}</text>
  ${[0, 1, 2, 3, 4, 5].map((i) => `<circle cx="${51 + i * 13}" cy="100" r="3.6" fill="none" stroke="var(--actaea)" stroke-width="1.25"/>`).join("")}
  ${[0, 1, 2].map((r) => [0, 1, 2].map((c) => `<circle cx="${52 + c * 32}" cy="${134 + r * 32}" r="12" fill="none" stroke="var(--ink-3)" stroke-width="1.25"/>`).join("")).join("")}
  <circle cx="84" cy="230" r="12" fill="none" stroke="var(--ink-3)" stroke-width="1.25"/>`, w),
  buttons: () => `
<svg class="illus" viewBox="0 0 248 250" width="200" aria-hidden="true">
  <rect x="90" y="20" width="80" height="164" rx="16" fill="var(--sheet)" stroke="currentColor" stroke-width="1.5"/>
  <rect x="117" y="28" width="26" height="7" rx="3.5" fill="none" stroke="var(--ink-3)" stroke-width="1.25"/>
  <rect x="85" y="58" width="5" height="22" rx="1.5" class="press pulse"/>
  <rect x="85" y="86" width="5" height="22" rx="1.5" class="press pulse"/>
  <rect x="170" y="70" width="5" height="34" rx="1.5" class="press pulse"/>
  <path d="M83 69h-3M83 97h-3M177 87h3" stroke="var(--ink-3)" stroke-width="1"/>
  <g font-size="10.5" font-weight="500" fill="var(--ink)">
    <text x="77" y="72.5" text-anchor="end">${T("svg.btn.up")}</text>
    <text x="77" y="100.5" text-anchor="end">${T("svg.btn.down")}</text>
    <text x="183" y="84" text-anchor="start">${T("svg.btn.side1")}</text>
    <text x="183" y="97" text-anchor="start">${T("svg.btn.side2")}</text>
  </g>
  <text x="130" y="212" text-anchor="middle" font-size="12" font-weight="600" fill="var(--ink)">${T("svg.btn.all")}</text>
  <text x="130" y="229" text-anchor="middle" font-size="11" fill="var(--ink-2)">${T("svg.btn.time")}</text>
</svg>`,
  iphone: () => `<svg class="g" width="16" height="22" viewBox="0 0 16 22" aria-hidden="true"><rect x="1.5" y="1" width="13" height="20" rx="3" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M6.5 3.4h3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>`,
};

// Model identifiers to marketing names; shared with the printable report (app/scan/report.py).
let MODELS = {};
const modelName = (id) => MODELS[id] || id || "iPhone";

// ---- frame, regions, focus ---------------------------------------------------------------------
const STATIONS = ["intro", "privacy", "connect", "choose", "check", "results", "finish"];
function mount(key, html) {
  const full = `${key}:${ui.lang}`;
  if (ui.screen === full) return false;
  ui.screen = full;
  ui.regions = {};
  app.innerHTML = html;
  window.scrollTo(0, 0);
  const h1 = app.querySelector("h1");
  if (h1 && !ui.dialogOpen) { h1.setAttribute("tabindex", "-1"); h1.focus({ preventScroll: true }); }
  return true;
}
function region(id, html) {
  const el = document.getElementById(id);
  if (el && ui.regions[id] !== html) {
    ui.regions[id] = html;
    el.innerHTML = html;
    return true;
  }
  return false;
}
// One screen = optional rail + content + fixed action bar. `actions` is static per screen;
// anything that changes while the screen is up lives in a region inside it.
function frame(key, { body, actions = "", rail = true }) {
  return mount(key, `
  <div class="frame${rail ? "" : " solo"}">
    ${rail ? `<ol class="rail" id="r-rail" aria-label="${esc(T("rail.label"))}"></ol>` : ""}
    <main>${rail ? `<div class="railline" id="r-railline"></div>` : ""}<div id="r-back"></div>${body}</main>
  </div>
  <footer class="actions">${actions}</footer>`);
}
function railStations(station, you) {
  const idx = STATIONS.indexOf(station);
  region("r-rail", STATIONS.map((s, i) => {
    const cls = i < idx ? "done" : i === idx ? (you ? "you" : "now") : "";
    const icon = i < idx ? "done" : i === idx ? "now" : "pend";
    const sub = i === idx && you ? `<small>${T("rail.you")}</small>` : "";
    return `<li class="${cls}"${i === idx ? ' aria-current="step"' : ""}>${g(icon)}<span>${T(`rail.${s}`)}${sub}</span></li>`;
  }).join(""));
  region("r-railline", T("rail.line", { i: idx + 1, n: STATIONS.length, name: T(`rail.${station}`) }));
}
function railTopics(current) {
  region("r-rail", [1, 2, 3, 4, 5].map((k) => {
    const i = k - 1;
    const cls = i < current ? "done" : i === current ? "now" : "";
    return `<li class="${cls}"${i === current ? ' aria-current="step"' : ""}>${g(i < current ? "done" : i === current ? "now" : "pend")}<span>${T(`learn.${k}.t`)}</span></li>`;
  }).join(""));
  region("r-railline", T("rail.line", { i: current + 1, n: 5, name: T(`learn.${current + 1}.t`) }));
}
function backToCheck(st) {
  region("r-back", st && st.phase === "running"
    ? `<div class="back-to-check" role="status">${g("now", 12)}<span>${T("run.back")}</span><span class="spacer"></span>
       <button class="btn small" data-a="to-check">${T("run.back_btn")}</button></div>` : "");
}
function say(text, urgent) {
  const el = document.getElementById(urgent ? "sr-alert" : "sr-status");
  el.textContent = "";
  setTimeout(() => { el.textContent = text.replace(/<[^>]+>/g, ""); }, 50);
}

// ---- dialogs (replace window.confirm: it silently returns false inside a WKWebView) ----------------
const dlg = document.getElementById("dlg");
function dialog({ title, body = "", actions = [{ label: T("notice.close"), value: null, primary: true }] }) {
  return new Promise((resolve) => {
    const opener = document.activeElement;
    document.getElementById("dlg-title").textContent = title;
    document.getElementById("dlg-body").innerHTML = body;
    const box = document.getElementById("dlg-actions");
    box.innerHTML = actions.map((a, i) =>
      `<button class="btn${a.danger ? " danger" : a.primary ? " primary" : ""}" data-i="${i}">${esc(a.label)}</button>`).join("");
    const done = (value) => {
      dlg.onclose = null;
      if (dlg.open) dlg.close();
      ui.dialogOpen = false;
      if (opener && document.contains(opener)) opener.focus();
      resolve(value);
    };
    box.onclick = (e) => { const b = e.target.closest("button[data-i]"); if (b) done(actions[+b.dataset.i].value); };
    dlg.onclose = () => done(null);
    ui.dialogOpen = true;
    dlg.showModal();
    // initial focus: the least destructive choice
    const safe = actions.findIndex((a) => a.safe);
    box.querySelectorAll("button")[safe >= 0 ? safe : actions.length - 1]?.focus();
  });
}
const confirmDanger = (title, body, goLabel) => dialog({
  title, body: `<p>${body}</p>`,
  actions: [{ label: T("dlg.cancel"), value: false, safe: true }, { label: goLabel, value: true, danger: true }],
}).then((v) => v === true);
function noticeDialog() {
  return dialog({ title: T("notice.title"), body: T("notice.body", { operator: ui.config.operator || "BugBane", contact: ui.config.contact || "—" }) });
}
async function supportDialog() {
  const text = await (await fetch(supportUrl(false))).text();
  const choice = await dialog({
    title: T("sup.title"),
    body: `<p>${T("sup.lead")}</p><pre class="supportlog">${esc(text)}</pre>`,
    actions: [{ label: T("notice.close"), value: null, safe: true }, { label: T("sup.save"), value: "save", primary: true }],
  });
  if (choice === "save") download(supportUrl(true));
}
function download(href) {
  const a = document.createElement("a");
  a.href = href; a.rel = "noopener";
  document.body.appendChild(a); a.click(); a.remove();
}
function openReport(id, toFile) {
  if (toFile) return download(reportUrl(id, true));
  const w = window.open(reportUrl(id, false), "_blank");
  if (w) w.addEventListener("load", () => w.print());
}

// ---- screens ---------------------------------------------------------------------------------------
function langScreen() {
  mount("lang", `
  <div class="frame solo"><main class="langpick">
    <h1>Válasszon nyelvet<span lang="en">Choose your language</span></h1>
    <div class="group">
      <button class="choice-lang" data-a="pick-lang" data-lang="hu" lang="hu"><span><b>Magyar</b><small>Folytatás magyarul</small></span>${g("chev", 12)}</button>
      <button class="choice-lang" data-a="pick-lang" data-lang="en" lang="en"><span><b>English</b><small>Continue in English</small></span>${g("chev", 12)}</button>
    </div>
  </main></div>`);
}

function welcome(st) {
  frame("welcome", {
    body: `
    <div id="r-restore"></div>
    <div class="welcome">
      <h1 class="display">${T("welcome.title")}</h1>
      <p class="lead">${T("welcome.lead")}</p>
      <dl class="label">
        <dt>${T("welcome.l.looks.t")}</dt><dd>${T("welcome.l.looks.b")}</dd>
        <dt>${T("welcome.l.compares.t")}</dt><dd>${T("welcome.l.compares.b")}</dd>
        <dt>${T("welcome.l.keeps.t")}</dt><dd>${T("welcome.l.keeps.b")}</dd>
      </dl>
      <p class="limit">${T("welcome.limit")}</p>
    </div>`,
    actions: `<button class="btn" data-a="learn">${T("welcome.learn")}</button><span class="spacer"></span>
      <button class="btn primary" data-a="begin">${T("welcome.start")}</button>`,
  });
  railStations("intro");
  region("r-restore", restoreCard(st));
}

function learn(st) {
  const i = ui.learnIdx, last = i === 4;
  frame(`learn-${i}`, {
    body: `<h1>${T(`learn.${i + 1}.t`)}</h1><div class="prose" style="margin-top:20px">${T(`learn.${i + 1}.b`)}</div>`,
    actions: `<button class="btn" data-a="learn-prev">${i === 0 ? T("learn.close") : T("learn.back")}</button><span class="spacer"></span>
      <span class="note">${T("learn.pos", { i: i + 1, n: 5 })}</span>
      <button class="btn primary" data-a="learn-next">${last ? T("learn.done") : T("learn.next")}</button>`,
  });
  railTopics(i);
  backToCheck(st);
}

function privacy() {
  const ok = ui.consentOwn && ui.consentProcess;
  const fresh = frame("privacy", {
    body: `
    <h1>${T("privacy.title")}</h1>
    <p class="lead">${T("privacy.lead")}</p>
    <dl class="ledger">
      ${["read", "change", "online", "stays"].map((k) => `<dt>${T(`privacy.l.${k}.t`)}</dt><dd>${T(`privacy.l.${k}.b`)}</dd>`).join("")}
    </dl>
    <p style="margin-top:16px"><button class="link" data-a="notice">${T("privacy.more")}</button></p>
    <fieldset class="group consents">
      <legend class="sr-only">${T("privacy.legend")}</legend>
      <label><input type="checkbox" id="c-own" required aria-required="true"><span>${T("privacy.c.own")}</span><span class="opt">${T("privacy.required")}</span></label>
      <label><input type="checkbox" id="c-process" required aria-required="true"><span>${T("privacy.c.process")}</span><span class="opt">${T("privacy.required")}</span></label>
      <label><input type="checkbox" id="c-history"><span>${T("privacy.c.history")}<span class="sub">${T("privacy.c.history_sub")}</span></span><span class="opt">${T("privacy.optional")}</span></label>
    </fieldset>`,
    actions: `<button class="btn" data-a="decline">${T("privacy.decline")}</button><span class="spacer"></span>
      <span class="note" id="consent-note"></span>
      <button class="btn primary" data-a="consent" id="consent-go">${T("privacy.continue")}</button>`,
  });
  if (fresh) {
    document.getElementById("c-own").checked = ui.consentOwn;
    document.getElementById("c-process").checked = ui.consentProcess;
    document.getElementById("c-history").checked = ui.consentHistory;
  }
  railStations("privacy");
  const go = document.getElementById("consent-go");
  go.disabled = !ok;
  document.getElementById("consent-note").textContent = ok ? "" : T("privacy.error");
}

function connect(st) {
  frame("connect", {
    body: `
    <div id="r-restore"></div>
    <h1>${T("connect.title")}</h1>
    <div class="instr">
      <div>
        <ol class="num-list"><li><span>${T("connect.s1")}</span></li><li><span>${T("connect.s2")}</span></li><li><span>${T("connect.s3")}</span></li></ol>
        <div class="status" role="status"><span class="spin" aria-hidden="true"></span><span>${T("connect.looking")}</span></div>
        <p class="help">${T("connect.help")}</p>
      </div>
      ${SVG.connect()}
    </div>`,
    actions: `<button class="btn" data-a="to-welcome">${T("nav.back")}</button>`,
  });
  railStations("connect");
  region("r-restore", restoreCard(st));
}

function trust(st) {
  frame("trust", {
    body: `
    <h1>${T("trust.title")}</h1>
    <div class="instr">
      <div>
        <ol class="num-list"><li><span>${T("trust.s1")}</span></li><li><span>${T("trust.s2")}</span></li><li><span>${T("trust.s3")}</span></li></ol>
        <p class="help">${T("trust.note")}</p>
        <div id="r-trust"></div>
      </div>
      ${SVG.trust()}
    </div>`,
    actions: `<button class="btn" data-a="to-welcome">${T("nav.back")}</button>`,
  });
  railStations("connect");
  const hint = { locked: `<p class="status" role="status">${T("trust.locked")}</p>`, denied: `<p class="err" role="alert">${T("trust.denied")}</p>` }[st.trust_hint];
  region("r-trust", hint || `<div class="status" role="status"><span class="spin" aria-hidden="true"></span><span>${T("trust.waiting")}</span></div>`);
}

// Measured 2026-09-29, iPhone 13 with 40 GB used: whole full check 17 minutes (database-only
// backup 5.5 min, 0.9 GB kept). Scaled gently with used storage and padded; refine with more runs.
function fullCheckMinutes(d) {
  const gb = d && d.storage ? d.storage.used / 1e9 : 40;
  const round5 = (x) => Math.max(5, Math.round(x / 5) * 5);
  return { lo: round5(10 + gb * 0.1), hi: round5(20 + gb * 0.25) };
}

function ready(st) {
  const d = st.device || {};
  const est = fullCheckMinutes(d);
  frame(`ready-${d.udid}`, {
    body: `
    <div id="r-restore"></div>
    <h1>${T("ready.title")}</h1>
    <div class="device">${SVG.iphone()}<div><b>${esc(d.name || "iPhone")}</b>
      <span class="small ink2">${T("ready.device", { model: modelName(d.model), ios: d.ios || "?", used: d.storage ? Math.round(d.storage.used / 1e9) : "?" })}</span></div></div>
    <div id="r-devs"></div>
    <fieldset class="section">
      <legend>${T("ready.choose")}</legend>
      <div class="group">
        ${["full", "quick"].map((m) => `<label class="radio-row">
          <input type="radio" name="mode" value="${m}"${ui.mode === m ? " checked" : ""}>
          <span class="t"><b>${T(`mode.${m}.t`)}</b><span>${T(`mode.${m}.tag`)}</span></span>
          <span class="est">${T(`mode.${m}.est`, est)}</span>
          <span class="d">${T(`mode.${m}.b`, { free: st.free_space })}</span></label>`).join("")}
      </div>
    </fieldset>
    <div class="section" id="r-pre"></div>
    <div id="r-starterr" role="alert"></div>`,
    actions: `<button class="btn" data-a="to-welcome">${T("nav.back")}</button><span class="spacer"></span>
      <span class="note">${T("ready.note")}</span>
      <button class="btn primary" data-a="start">${T("ready.start")}</button>`,
  });
  railStations("choose");
  region("r-restore", restoreCard(st));
  region("r-devs", st.devices.length > 1
    ? `<fieldset class="section"><legend>${T("ready.multi")}</legend><div class="group">${st.devices.map((x) => `<label class="radio-row">
        <input type="radio" name="dev" value="${esc(x.udid)}"${x.udid === d.udid ? " checked" : ""}><span class="t"><b>${esc(x.name || "iPhone")}</b></span><span></span></label>`).join("")}</div></fieldset>` : "");
  region("r-pre", ui.mode === "full"
    ? `<h2>${T("ready.pre.t")}</h2><ul class="plain" style="margin-top:8px">${[1, 2, 3].map((k) => `<li>${T(`ready.pre.${k}`)}</li>`).join("")}</ul>` : "");
  const errKey = ui.error && ui.error !== "consent" ? (ui.S[`err.${ui.error}`] ? `err.${ui.error}` : "err.generic") : null;
  region("r-starterr", errKey ? `<p class="err" style="margin-top:16px">${T(errKey)}</p>` : "");
}

// "BugBane needs you": the prompt sheet (plum). It's announced, takes focus, and can't be navigated away from.
function promptCard(p) {
  if (!p) return "";
  if (p.type === "press_buttons") {
    return `<section class="prompt" aria-labelledby="pt">${SVG.buttons()}
      <div><h2 id="pt" tabindex="-1">${T("p.press.title")}</h2><p>${T("p.press.text")}</p>
      <ul class="plain"><li>${T("p.press.tip1")}</li><li>${T("p.press.tip2")}</li></ul>
      <details><summary>${g("chev", 10)}${T("p.press.skip")}</summary>
        <div class="more-body"><p>${T("p.press.skip_cost")}</p>
        <p style="margin-top:10px"><button class="btn small" data-a="answer" data-prompt="press_buttons" data-choice="skip">${T("p.press.skip_go")}</button></p></div></details>
      </div></section>`;
  }
  if (p.type === "backup_password") {
    return `<section class="prompt textonly" aria-labelledby="pt">
      <div><h2 id="pt" tabindex="-1">${T(p.retry ? "p.pw.retry_title" : "p.pw.title")}</h2><p>${T(p.retry ? "p.pw.retry_text" : "p.pw.text")}</p>
      <form class="field" data-form="password">
        <label for="pw">${T("p.pw.label")}</label>
        <div class="inrow"><input type="password" id="pw" autocomplete="off" aria-describedby="pw-help"${p.retry ? ' aria-invalid="true"' : ""}>
        <button class="btn primary" type="submit">${T("p.pw.continue")}</button></div>
        <span class="small ink2" id="pw-help">${T("p.pw.help")}</span>
      </form>
      <details><summary>${g("chev", 10)}${T("p.pw.forgot")}</summary>
        <div class="more-body"><p>${T("p.pw.forgot_text")}</p>
        <p style="margin-top:10px"><button class="btn small" data-a="answer" data-prompt="backup_password" data-choice="forgot">${T("p.pw.skip")}</button></p></div>
      </details></div></section>`;
  }
  if (p.type === "passcode_on_phone") {
    return `<section class="prompt" aria-labelledby="pt">${SVG.passcode(140)}
      <div><h2 id="pt" tabindex="-1">${T("p.passcode.title")}</h2><p>${T("p.passcode.text")}</p></div></section>`;
  }
  if (p.type === "low_space") {
    return `<section class="prompt textonly" aria-labelledby="pt"><div>
      <h2 id="pt" tabindex="-1">${T("p.space.title")}</h2><p>${T("p.space.text", p.params || {})}</p>
      <div class="row"><button class="btn primary" data-a="answer" data-prompt="low_space" data-choice="continue">${T("p.space.continue")}</button>
      <button class="btn" data-a="answer" data-prompt="low_space" data-choice="quick">${T("p.space.quick")}</button></div></div></section>`;
  }
  return "";
}

// The moments when BugBane needs the person, so nobody has to remember them.
function moments(st) {
  const by = Object.fromEntries(st.steps.map((s) => [s.id, s]));
  const pt = st.prompt && st.prompt.type;
  const sys = by.sysdiagnose || {}, bk = by.backup || {};
  const list = [{ k: "buttons", you: pt === "press_buttons", done: sys.status && sys.status !== "pending" && pt !== "press_buttons" }];
  if (st.mode === "full") {
    if (st.device && st.device.backup_encrypted) {
      list.push({ k: "password", you: pt === "backup_password", done: bk.status && bk.status !== "pending" && pt !== "backup_password" });
    }
    const copying = bk.status === "active" && bk.progress > 0;
    list.push({ k: "passcode", you: pt === "passcode_on_phone", done: ["done", "error", "skipped"].includes(bk.status) || copying });
  }
  return list;
}

function runningLeft(st) {
  if (!ui.startedAt) ui.startedAt = Date.now();
  const m = Math.floor((Date.now() - ui.startedAt) / 60000);
  const { lo, hi } = st.mode === "quick" ? { lo: 10, hi: 15 } : fullCheckMinutes(st.device);
  const left = m >= hi ? T("run.left_over") : T("run.left", { a: Math.max(1, lo - m), b: Math.max(2, hi - m) });
  return `<span>${left}</span><span class="ink3">${T("run.elapsed", { m })}</span>`;
}

const STEP_PROMPT = { press_buttons: "sysdiagnose", backup_password: "backup", passcode_on_phone: "backup", low_space: "prepare" };
const PROMPT_TITLE = { press_buttons: "p.press.title", backup_password: "p.pw.title", passcode_on_phone: "p.passcode.title", low_space: "p.space.title" };

function running(st) {
  frame("running", {
    body: `
    <div class="run">
      <div class="run-head"><h1>${T("run.title", { name: st.device ? st.device.name || "iPhone" : "iPhone" })}</h1><span class="left" id="r-left"></span></div>
      <div id="r-prompt"></div>
      <div id="r-calm"></div>
      <ol class="timeline" id="r-steps" aria-label="${esc(T("run.steps"))}"></ol>
    </div>`,
    actions: `<button class="btn" data-a="stop">${T("run.stop")}</button><span class="spacer"></span>
      <button class="link" data-a="support">${T("sup.link")}</button>`,
  });
  const prompt = st.prompt;
  railStations("check", !!prompt);
  region("r-left", runningLeft(st));

  const youStep = prompt ? STEP_PROMPT[prompt.type] : null;
  region("r-steps", st.steps.map((s) => {
    const you = s.id === youStep;
    const cls = you ? "you" : s.status;
    const mk = you ? g("now") : { done: g("done"), error: g("alert"), skipped: g("dash"), pending: g("pend") }[s.status]
      || `<span class="spin" aria-hidden="true"></span>`;
    const bar = s.status === "active" && s.progress != null ? `<div class="prog" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${s.progress}"><i style="width:${s.progress}%"></i></div>` : "";
    const detail = you ? `<div class="d">${T("st.you")}</div>` : s.detail ? `<div class="d">${T(s.detail.key, s.detail.params)}</div>` : "";
    return `<li class="${cls}"${s.status === "active" ? ' aria-current="step"' : ""}><span class="mk">${mk}</span>
      <div><div class="t">${T(`step.${s.id}`)}<span class="sr-only">, ${T(`st.${you ? "you" : s.status}`)}</span></div>${detail}${bar}</div></li>`;
  }).join(""));

  if (region("r-prompt", promptCard(prompt)) && prompt) {
    const pw = document.getElementById("pw");
    (pw || document.getElementById("pt"))?.focus();
    document.getElementById("r-prompt").scrollIntoView({ behavior: "smooth", block: "start" });
  }
  const ms = moments(st);
  const allDone = ms.every((m) => m.done);
  const active = st.steps.find((s) => s.status === "active");
  region("r-calm", prompt ? "" : `
    <p class="calm">${allDone ? T("run.free") : T("run.calm")}${active ? ` ${T(`explain.${active.id}`)}` : ""}</p>
    <div class="moments"><h3>${T("run.moments")}</h3><ol>${ms.map((m) => `<li class="${m.you ? "you" : m.done ? "done" : ""}">
      ${g(m.done ? "done" : m.you ? "now" : "pend")}<span>${T(`run.m.${m.k}`)}</span><span class="w">${m.done ? T("run.m.done") : m.you ? T("run.m.now") : ""}</span></li>`).join("")}</ol></div>
    <p class="small ink3" style="margin-top:12px">${T("run.tip")}</p>`);

  // Announcements: a prompt is urgent; a new step is polite. The window title stays neutral.
  const pkey = prompt ? prompt.type + (prompt.retry ? "-retry" : "") : null;
  if (pkey && pkey !== ui.lastPrompt) say(T(PROMPT_TITLE[prompt.type] || "run.tab_yourturn"), true);
  ui.lastPrompt = pkey;
  if (active && active.id !== ui.lastStep) say(T(`step.${active.id}`));
  ui.lastStep = active ? active.id : ui.lastStep;
  document.title = prompt ? T("run.tab_yourturn") : "BugBane";
}

// ---- results: the record ------------------------------------------------------------------------
function verdictOf(r) {
  if (r.verdict === "ok" && r.partial && r.partial.length) {
    const list = r.partial.map((id) => T(`chk.${id}.title`)).join(", ");
    return { lvl: "partial", t: T("v.partial.t"), b: T("v.partial.b", { list, fix: { t: r.partial_fix || "v.partial.fix.other" } }) };
  }
  return { lvl: r.verdict, t: T(`v.${r.verdict}.t`), b: T(`v.${r.verdict}.b`, { total: r.indicators.total }) };
}
function nextSteps(verdict) {
  const common = ["next.update", "next.restart", "next.safety", "next.password", "next.lockdown"];
  if (verdict === "alert") return ["next.alert1", "next.alert2", "next.alert3", "next.alert4", "next.alert5"];
  return verdict === "warn" ? ["next.warn", ...common] : common;
}
function firstSentence(html) {
  const text = html.replace(/<[^>]+>/g, "");
  const m = text.match(/^.*?[.!?:](\s|$)/);
  return esc(m ? m[0].trim().replace(/:$/, ".") : text);
}
const ORDER = ["alert", "warn", "info", "ok", "skipped"];

function record(r, { live, st }) {
  const v = verdictOf(r);
  const reasons = [];
  for (const c of r.checks) {
    for (const i of c.items) {
      if (["alert", "warn"].includes(i.level) && reasons.length < 4) {
        reasons.push(`<li>${lv(i.level, 14)}<a href="#chk-${c.id}" data-a="goto" data-id="chk-${c.id}"><b>${T(`chk.${c.id}.title`)}</b> <span class="ink2">${firstSentence(T(i.key, i.params))}</span></a></li>`);
      }
    }
  }
  const counts = r.checks.reduce((a, c) => ((a[c.status] = (a[c.status] || 0) + 1), a), {});
  const d = r.device || {};
  const evidence = live && r.verdict === "alert" ? evidenceSection(st) : "";
  return `
  <article class="record" aria-labelledby="vt">
    <div class="row verdict">
      <div class="flag">${lv(v.lvl, 28)}</div>
      <div>
        <h1 id="vt">${v.t}</h1>
        <p class="lead">${v.b}</p>
        ${reasons.length ? `<ul class="because" aria-label="${esc(T("res.because"))}">${reasons.join("")}</ul>` : ""}
        <dl class="label">
          <dt>${T("res.l.iphone")}</dt><dd>${T("res.v.iphone", { name: d.name || "iPhone", model: modelName(d.model), ios: d.ios || "?" })}</dd>
          <dt>${T("res.l.check")}</dt><dd>${T("res.v.check", { mode: { t: `res.mode.${r.mode}` }, date: { dt: r.finished } })}</dd>
          <dt>${T("res.l.compared")}</dt><dd>${T("res.v.compared", { total: r.indicators.total, feeds: r.indicators.feeds })}</dd>
          ${r.last_restart ? `<dt>${T("res.l.restart")}</dt><dd>${fmtDate(r.last_restart, true)}</dd>` : ""}
        </dl>
        <p class="legend" aria-label="${esc(T("res.legend"))}">${ORDER.filter((k) => counts[k]).map((k) =>
          `<span>${lv(k, 14)}<span>${T(`level.${k}`)}</span><b class="num" style="color:var(--ink)">${counts[k]}</b></span>`).join("")}</p>
      </div>
    </div>
    <section class="row sec"><div></div><div>
      <h2>${T("res.next")}</h2>
      <ol class="num-list">${nextSteps(r.verdict).map((k) => `<li><span>${T(k)}</span></li>`).join("")}</ol>
    </div></section>
    ${evidence}
    <div class="row findings-h"><div></div><h2>${T("res.all")}</h2></div>
    ${r.checks.map((c) => checkRow(c)).join("")}
    <div class="foot">
      ${["ok", "partial"].includes(v.lvl) ? `<p>${T("res.clean_b", { families: (r.indicators?.families || []).join(", ") })}</p>`
        : `<p>${T("res.provenance", { families: (r.indicators?.families || []).join(", ") })}</p>`}
      ${live ? `<p style="margin-top:12px"><label class="forget"><input type="checkbox" id="forget"${ui.forget ? " checked" : ""}><span>${T("res.forget")}</span></label></p>` : ""}
    </div>
  </article>`;
}
function checkRow(c) {
  const open = ["alert", "warn"].includes(c.status) ? " open" : "";
  const items = c.items.map((i) => {
    const word = i.level !== c.status ? `<span class="lv l-${i.level}">${T(`level.${i.level}`)}.</span> ` : "";
    return `<div class="item">${lv(i.level, 14)}<span>${word}${T(i.key, i.params)}</span>${i.detail ? `<code>${esc(i.detail)}</code>` : ""}</div>`;
  }).join("");
  return `<details class="check" id="chk-${c.id}"${open}>
    <summary><span class="flag">${lv(c.status)}</span>
      <span><h3>${T(`chk.${c.id}.title`)}${g("chev", 10)}</h3><span class="sum">${T(c.summary.key, c.summary.params)}</span></span>
      <span class="st l-${c.status}">${T(`level.${c.status}`)}</span></summary>
    <div class="check-body"><div></div><div>
      ${items}
      <details><summary>${g("chev", 10)}${T("res.what")}</summary><div class="more-body">${T(`chk.${c.id}.what`)}</div></details>
    </div></div>
  </details>`;
}
function evidenceSection(st) {
  let inner;
  if (st.raw_deleted) inner = `<p>${T("data.erased")}</p>`;
  else if (st.kept) inner = `<p>${T("data.kept")}</p>`;
  else {
    inner = `<p>${T("data.keep_b")}</p><div class="row-actions">
      <button class="btn" data-a="keep">${T("data.keep_btn")}</button>
      <button class="btn" data-a="erase">${T("data.erase_btn")}</button></div>`;
  }
  return `<section class="row sec" id="evidence"><div></div><div><h2>${T("data.keep_t")}</h2>${inner}</div></section>`;
}

function results(st) {
  const r = st.results;
  if (!r) return running(st);
  frame(`results-${r.finished}-${st.kept}-${st.raw_deleted}`, {
    body: `<div id="r-restore"></div>${record(r, { live: true, st })}`,
    actions: `<button class="btn" data-a="download">${T("res.download")}</button>
      <button class="btn" data-a="print">${T("res.print")}</button>
      <span id="r-hist"></span>
      <button class="link" data-a="support">${T("sup.btn")}</button>
      <span class="spacer"></span>
      <button class="btn primary" data-a="finish">${T(st.kept || st.raw_deleted ? "res.finish_kept" : "res.finish")}</button>`,
  });
  railStations("results");
  region("r-restore", restoreCard(st));
  region("r-hist", st.history_id ? `<span class="small ink2" style="display:inline-flex;gap:6px;align-items:center">${g("done", 12)}${T("res.saved_history")}</span>`
    : `<button class="btn" data-a="save-history">${T("res.save_history")}</button>`);
  document.title = "BugBane";
}

function done() {
  const d = ui.done || {};
  frame("done", {
    body: `
    <h1>${T("done.title")}</h1>
    <ul class="plain done-list">
      ${d.kept ? `<li>${T("data.kept")}</li>` : `<li>${T("done.erased")}</li>`}
      ${d.forgot ? `<li>${T("done.forgot")}</li>` : ""}
      ${d.saved ? `<li>${T("done.saved")}</li>` : ""}
      <li>${T("done.unplug")}</li>
    </ul>`,
    actions: `<button class="btn" data-a="history">${T("done.history")}</button><span class="spacer"></span>
      <button class="btn primary" data-a="again">${T("done.again")}</button>`,
  });
  railStations("finish");
}

function historyList(st) {
  const rows = ui.history.map((e) => {
    const lvl = e.verdict === "ok" && e.partial ? "partial" : e.verdict;
    const word = lvl === "partial" ? T("hist.v.partial") : T(`hist.v.${e.verdict}`);
    return `<div class="hrow">${lv(lvl)}
      <div><div class="when">${fmtDate(e.finished, true)}</div>
        <div class="meta">${esc(e.device.name || "iPhone")}, ${esc(modelName(e.device.model))}, iOS ${esc(e.device.ios)}, ${T(`res.mode.${e.mode}`)}${e.evidence ? `<br><span class="ev">${T("hist.evidence")}</span>` : ""}</div></div>
      <span class="vw l-${lvl}">${word}</span>
      <span class="acts"><button class="btn small" data-a="hist-open" data-id="${esc(e.id)}">${T("hist.open")}</button>
        ${e.evidence ? `<button class="link" data-a="hist-erase-ev" data-id="${esc(e.id)}">${T("hist.erase_evidence")}</button>` : ""}
        <button class="link danger" data-a="hist-delete" data-id="${esc(e.id)}">${T("hist.delete")}</button></span></div>`;
  }).join("");
  frame(`history-${ui.history.map((e) => e.id + e.evidence).join()}`, {
    rail: false,
    body: `<h1>${T("hist.title")}</h1><p class="small ink2" style="margin-top:8px;max-width:40em">${T("hist.lead")}</p>
      ${ui.history.length ? `<div class="group hist" style="margin-top:24px">${rows}</div>` : `<p style="margin-top:24px">${T("hist.empty")}</p>`}`,
    actions: `<button class="btn" data-a="close-history">${T("hist.back")}</button><span class="spacer"></span>
      ${ui.history.length ? `<button class="link danger" data-a="hist-delete-all">${T("hist.delete_all")}</button>` : ""}`,
  });
  backToCheck(st);
}

function historyView(st) {
  const { id, r } = ui.viewing;
  frame(`histview-${id}`, {
    rail: false,
    body: `<p class="small ink2" style="margin-bottom:12px">${T("hist.viewing", { date: { dt: r.finished } })}</p>${record(r, { live: false })}`,
    actions: `<button class="btn" data-a="history">${T("hist.back")}</button>
      <button class="btn" data-a="download" data-id="${esc(id)}">${T("res.download")}</button>
      <button class="btn" data-a="print" data-id="${esc(id)}">${T("res.print")}</button><span class="spacer"></span>
      <button class="link danger" data-a="hist-delete" data-id="${esc(id)}">${T("hist.delete")}</button>`,
  });
  backToCheck(st);
}

// An interrupted check can leave backup encryption on with BugBane's temporary password (kept in
// the Keychain); this card lets the person finish switching it off.
function restoreCard(st) {
  const r = st && st.restore;
  if (!r) return "";
  if (r.state === "working") {
    return `<section class="prompt" style="margin-bottom:28px" aria-labelledby="rt">${SVG.passcode(120)}
      <div><h2 id="rt">${T("rs.working_t")}</h2><p>${T("rs.working_b")}</p></div></section>`;
  }
  const done = r.state === "done" ? `<p class="status" style="margin-bottom:24px" role="status">${g("done")}${T("rs.done")}</p>` : "";
  return done + r.pending.map((e) => {
    const failKey = { locked: "rs.failed_locked", timeout: "rs.failed_timeout" }[r.error] || "rs.failed";
    const failed = r.state === "failed" && e.connected ? `<p class="err" role="alert" style="margin-top:12px">${T(failKey)}</p>` : "";
    const since = Date.parse(`${e.since}T12:00:00`) / 1000;
    const action = e.connected
      ? `<div class="row"><button class="btn primary" data-a="restore">${T("rs.btn")}</button><span class="small ink2">${T("rs.btn_note")}</span></div>`
      : `<p class="small ink2" style="margin-top:12px">${T("rs.connect")}</p>`;
    return `<section class="prompt textonly" style="margin-bottom:28px" aria-labelledby="rt-${esc(e.id)}"><div>
      <h2 id="rt-${esc(e.id)}">${T("rs.title")}</h2><p>${T("rs.body", { model: modelName(e.model), date: { d: since } })}</p>
      ${failed}${action}
      <details><summary>${g("chev", 10)}${T("rs.other_t")}</summary><div class="more-body">${T("rs.other_b")}</div></details>
      <p style="margin-top:12px"><button class="link" data-a="restore-dismiss" data-id="${esc(e.id)}">${T("rs.dismiss")}</button></p>
    </div></section>`;
  }).join("");
}

function offlineScreen() {
  mount("offline", `<div class="frame solo"><main><h1>${T("off.t")}</h1><p style="margin-top:12px">${T("off.b")}</p></main></div>`);
}

function render() {
  if (!ui.lang) return langScreen();
  chrome();
  if (ui.offline) return offlineScreen();
  const st = ui.state;
  const busy = st && ["running", "done"].includes(st.phase);
  // A prompt always wins: nothing may hide "BugBane needs you" while a check runs.
  if (st && st.phase === "running" && st.prompt && ui.local !== null && !ui.dialogOpen) ui.local = null;
  if (ui.local === "lang" && !busy) return langScreen();
  if (ui.local === "learn") return learn(st);
  if (ui.local === "history") return historyList(st);
  if (ui.local === "histview") return historyView(st);
  if (ui.local === "done") return done();
  if (!st) return;
  if (ui.local === "welcome" && !busy) return welcome(st);
  if (!st.consent && !busy) return privacy(st);
  if (st.phase === "connect") return connect(st);
  if (st.phase === "trust") return trust(st);
  if (st.phase === "ready") return ready(st);
  if (st.phase === "running") return running(st);
  if (st.phase === "done") return results(st);
}

// ---- events -------------------------------------------------------------------------------------------
async function openHistory() {
  ui.history = (await api("/api/history")).entries;
  ui.local = "history";
}
document.getElementById("nav-learn").onclick = () => { if (!ui.lang) return; ui.local = "learn"; ui.learnIdx = 0; render(); };
document.getElementById("nav-history").onclick = async () => { if (!ui.lang) return; await openHistory(); render(); };
document.getElementById("nav-privacy").onclick = () => { if (ui.lang) noticeDialog(); };
document.getElementById("nav-quit").onclick = async () => {
  if (!ui.lang || !(await confirmDanger(T("quit.confirm_t"), T("quit.confirm"), T("quit.go")))) return;
  try { await api("/api/quit", {}); } catch (e) { /* server already gone */ }
  ui.offline = true; render();
};
document.querySelectorAll(".seg button").forEach((b) => { b.onclick = () => setLang(b.dataset.lang); });

app.addEventListener("click", async (ev) => {
  const el = ev.target.closest("[data-a]");
  if (!el) return;
  const a = el.dataset.a;
  if (a === "goto") {
    ev.preventDefault();
    const t = document.getElementById(el.dataset.id);
    if (t) { t.open = true; t.scrollIntoView({ block: "start" }); t.querySelector("summary").focus(); }
    return;
  }
  if (a === "pick-lang") { await setLang(el.dataset.lang); ui.local = "welcome"; }
  else if (a === "begin") { ui.local = null; ui.error = null; }
  else if (a === "to-welcome") { ui.local = "welcome"; }
  else if (a === "to-check") { ui.local = null; }
  else if (a === "learn") { ui.local = "learn"; ui.learnIdx = 0; }
  else if (a === "learn-prev") { if (ui.learnIdx === 0) ui.local = ui.state && ui.state.phase === "running" ? null : "welcome"; else ui.learnIdx--; }
  else if (a === "learn-next") { if (ui.learnIdx === 4) ui.local = null; else ui.learnIdx++; }
  else if (a === "notice") noticeDialog();
  else if (a === "consent") {
    readConsentBoxes();
    const res = await act({ type: "consent", own: ui.consentOwn, process: ui.consentProcess, history: ui.consentHistory, lang: ui.lang });
    ui.error = res.ok ? null : "consent";
  }
  else if (a === "decline") { ui.local = "welcome"; ui.consentOwn = ui.consentProcess = ui.consentHistory = false; }
  else if (a === "start") {
    const res = await act({ type: "start", mode: ui.mode });
    ui.error = res.ok ? null : res.error;
    ui.startedAt = Date.now(); ui.lastStep = ui.lastPrompt = null;
  }
  else if (a === "stop") {
    if (await confirmDanger(T("run.stop_confirm_t"), T("run.stop_confirm"), T("run.stop"))) { await act({ type: "stop" }); ui.startedAt = null; }
  }
  else if (a === "answer") await act({ type: "answer", prompt: el.dataset.prompt, choice: el.dataset.choice });
  else if (a === "download") openReport(el.dataset.id, true);
  else if (a === "print") openReport(el.dataset.id, false);
  else if (a === "support") await supportDialog();
  else if (a === "save-history") await act({ type: "save_history" });
  else if (a === "keep") await act({ type: "keep_evidence" });
  else if (a === "erase") { if (await confirmDanger(T("data.erase_confirm_t"), T("data.erase_confirm"), T("data.erase_go"))) await act({ type: "erase_evidence" }); }
  else if (a === "restore") await act({ type: "restore_encryption" });
  else if (a === "restore-dismiss") {
    if (await confirmDanger(T("rs.dismiss_confirm_t"), T("rs.dismiss_confirm"), T("rs.dismiss_go"))) await act({ type: "restore_dismiss", id: el.dataset.id });
  }
  else if (a === "finish") {
    const f = document.getElementById("forget");
    if (f) ui.forget = f.checked;
    ui.done = await act({ type: "finish", forget: ui.forget });
    ui.local = "done"; ui.startedAt = null;
    ui.consentOwn = ui.consentProcess = ui.consentHistory = false;
  }
  else if (a === "again") { ui.local = "welcome"; ui.done = null; }
  else if (a === "history") await openHistory();
  else if (a === "close-history") ui.local = ui.state && ui.state.phase === "running" ? null : "welcome";
  else if (a === "hist-open") { ui.viewing = { id: el.dataset.id, r: await api(`/api/history/${encodeURIComponent(el.dataset.id)}`) }; ui.local = "histview"; }
  else if (a === "hist-delete") {
    if (await confirmDanger(T("hist.confirm_delete_t"), T("hist.confirm_delete"), T("hist.del_go"))) { await api("/api/history/delete", { id: el.dataset.id }); await openHistory(); }
  }
  else if (a === "hist-delete-all") {
    if (await confirmDanger(T("hist.confirm_all_t"), T("hist.confirm_all"), T("hist.del_all_go"))) { await api("/api/history/delete", {}); await openHistory(); }
  }
  else if (a === "hist-erase-ev") {
    if (await confirmDanger(T("hist.confirm_erase_t"), T("hist.confirm_erase"), T("hist.erase_go"))) { await api("/api/history/erase_evidence", { id: el.dataset.id }); await openHistory(); }
  }
  await poll();
});

function readConsentBoxes() {
  for (const [id, k] of [["c-own", "consentOwn"], ["c-process", "consentProcess"], ["c-history", "consentHistory"]]) {
    const el = document.getElementById(id);
    if (el) ui[k] = el.checked;
  }
}
app.addEventListener("change", (ev) => {
  const t = ev.target;
  if (t.id && t.id.startsWith("c-")) { readConsentBoxes(); render(); }
  if (t.name === "mode") { ui.mode = t.value; render(); }
  if (t.name === "dev") act({ type: "select_device", udid: t.value }).then(poll);
  if (t.id === "forget") ui.forget = t.checked;
});
app.addEventListener("submit", async (ev) => {
  if (ev.target.dataset.form !== "password") return;
  ev.preventDefault();
  const input = document.getElementById("pw");
  const password = input.value;
  if (!password) return input.focus();
  input.value = "";
  await act({ type: "answer", prompt: "backup_password", password });
  ui.regions["r-prompt"] = null;
  await poll();
});

// ---- polling ------------------------------------------------------------------------------------------
let failures = 0;
async function poll() {
  try {
    ui.state = await api("/api/state");
    failures = 0;
  } catch (e) {
    if (++failures > 4) ui.offline = true;
  }
  if (ui.state && ui.state.phase === "running" && !ui.startedAt) ui.startedAt = Date.now();
  render();
}

(async function init() {
  if (!TOKEN) {
    app.innerHTML = `<div class="frame solo"><main><h1>Please open BugBane from its app icon</h1>
      <p lang="hu" style="margin-top:12px">Kérjük, az alkalmazás ikonjával nyissa meg a BugBane-t.</p></main></div>`;
    return;
  }
  try { ui.config = await api("/api/config"); } catch (e) { /* defaults */ }
  try { MODELS = await (await fetch("/ui/models.json")).json(); } catch (e) { /* identifiers instead */ }
  const saved = store.get("bugbane-lang");
  if (DEMO) {
    await setLang(saved || "en");
    ui.viewing = { id: DEMO, r: await api(`/api/history/${encodeURIComponent(DEMO)}`) };
    ui.local = "histview";
  } else if (saved) {
    // same window (e.g. a reload mid-check): keep the language, skip the picker
    await setLang(saved);
    ui.local = "welcome";
  }
  await poll();
  setInterval(poll, 1000);
})();
