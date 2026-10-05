"use strict";

const state = { range: "today", filters: {} };
const DIMS = ["service", "category", "app", "site", "org", "country"];
const DIM_LABEL = { service: "Service", category: "Category", app: "App", site: "Domain", org: "Operator", country: "Country" };
const tzOffset = -new Date().getTimezoneOffset() * 60; // seconds east of UTC

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// Decimal units (1 GB = 10^9 bytes), as used by energy-per-GB studies.
function fmtBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "kB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  return (n >= 100 || i === 0 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2)) + " " + units[i];
}

function rangeBounds(r) {
  const now = Math.floor(Date.now() / 1000);
  if (r === "today") {
    const d = new Date(); d.setHours(0, 0, 0, 0);
    return { from: Math.floor(d / 1000), to: now, label: "Today since midnight" };
  }
  const spans = { "1h": [3600, "Last hour"], "24h": [86400, "Last 24 hours"], "7d": [7 * 86400, "Last 7 days"], "30d": [30 * 86400, "Last 30 days"] };
  const [s, label] = spans[r];
  return { from: now - s, to: now, label };
}

async function getJSON(path, params) {
  const res = await fetch(path + "?" + new URLSearchParams(params));
  if (!res.ok) throw new Error(path + ": " + res.status);
  return res.json();
}

async function refresh() {
  const b = rangeBounds(state.range);
  const params = { from: b.from, to: b.to, tz: tzOffset, ...state.filters };
  try {
    const [sum, status] = await Promise.all([getJSON("api/summary", params), getJSON("api/status", {})]);
    renderStatus(status);
    renderHero(sum, b.label);
    renderTimeline($("timeline"), sum.timeline || [], sum.from, sum.to, sum.step, true);
    for (const d of DIMS) renderBars($("b-" + d), sum.breakdowns[d] || [], d);
  } catch (e) {
    $("status").textContent = "Dashboard cannot reach the collector";
    $("status").className = "status off";
  }
  renderFilters();
}

async function refreshSrum() {
  const now = Math.floor(Date.now() / 1000);
  const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - 29);
  try {
    const s = await getJSON("api/srum", { from: Math.floor(d / 1000), to: now, tz: tzOffset });
    $("srum-note").textContent = s.first
      ? `${fmtBytes(s.total.in + s.total.out)} in 30 days · data since ${new Date(s.first * 1000).toLocaleDateString()}`
      : "Not imported yet (runs automatically when the collector has administrator rights)";
    renderTimeline($("srum-days"), s.days, Math.floor(d / 1000), now, 86400, false);
    renderBars($("srum-apps"), s.apps, null);
  } catch (e) { /* the live view already reports connection problems */ }
}

function renderStatus(s) {
  const el = $("status");
  if (s.capturing) {
    el.className = "status live";
    el.textContent = "Recording" + (s.lostEvents ? ` · ${s.lostEvents} events lost` : "");
    el.title = `${s.events.toLocaleString()} events · ${s.dnsAddrs} known addresses · DB ${s.db}`;
  } else {
    const viewOnly = (s.captureError || "").includes("serve mode");
    el.className = viewOnly ? "status" : "status off";
    el.textContent = viewOnly ? "View only — not recording" : "Not recording (hover for details)";
    el.title = s.captureError || "";
  }
}

function renderHero(sum, label) {
  const i = sum.internet;
  $("total").textContent = fmtBytes(i.in + i.out);
  $("down").textContent = fmtBytes(i.in);
  $("up").textContent = fmtBytes(i.out);
  $("lan").textContent = fmtBytes(sum.lan.in + sum.lan.out);
  const f = Object.entries(state.filters).map(([k, v]) => `${DIM_LABEL[k]}: ${v}`).join(", ");
  $("range-label").textContent = label + (f ? " · " + f : "");
}

function renderFilters() {
  const el = $("filters");
  const entries = Object.entries(state.filters);
  el.hidden = entries.length === 0;
  el.innerHTML = entries.map(([k, v]) =>
    `<button class="chip" data-k="${k}" title="Remove filter">${DIM_LABEL[k]}: <b>${esc(v)}</b> ✕</button>`).join("") +
    (entries.length > 1 ? `<button class="chip" data-k="*">Clear all</button>` : "");
}

$("filters").addEventListener("click", (e) => {
  const k = e.target.closest("[data-k]")?.dataset.k;
  if (!k) return;
  if (k === "*") state.filters = {}; else delete state.filters[k];
  refresh();
});

function renderBars(el, items, dim) {
  if (!items.length) { el.innerHTML = `<div class="none">No data in this period</div>`; return; }
  const max = Math.max(...items.map((it) => it.in + it.out)) || 1;
  el.innerHTML = items.map((it, idx) => {
    const tot = it.in + it.out;
    const w = Math.max(0.5, (tot / max) * 100);
    const segs = [it.in ? `<i class="in" style="flex:${it.in}"></i>` : "", it.out ? `<i class="out" style="flex:${it.out}"></i>` : ""].join("");
    return `<div class="bar-row${dim ? "" : " static"}" data-i="${idx}">
      <span class="bar-name">${esc(it.name)}</span><span class="bar-val">${fmtBytes(tot)}</span>
      <span class="bar-track" style="width:${w}%">${segs}</span></div>`;
  }).join("");
  el.onclick = dim ? (e) => {
    const row = e.target.closest(".bar-row"); if (!row) return;
    state.filters[dim] = items[row.dataset.i].name;
    hideTip();
    refresh();
  } : null;
  el.onmousemove = (e) => {
    const row = e.target.closest(".bar-row"); if (!row) return hideTip();
    const it = items[row.dataset.i];
    showTip(e, it.name, it.in, it.out);
  };
  el.onmouseleave = hideTip;
}

// Nice axis maximum and ticks for byte values.
function niceMax(v) {
  if (v <= 0) return 1000;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function fmtTick(t, step) {
  const d = new Date(t * 1000);
  if (step >= 86400) return d.toLocaleDateString(undefined, { day: "numeric", month: "short" });
  if (step >= 3600) return d.toLocaleDateString(undefined, { weekday: "short" }) + " " + d.toLocaleTimeString(undefined, { hour: "2-digit" });
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

function renderTimeline(el, points, from, to, step, live) {
  const W = el.clientWidth || 800, H = el.clientHeight || 220;
  const m = { l: 56, r: 8, t: 8, b: 22 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  // Fill every bucket so gaps show as empty time rather than being squeezed out.
  const align = (t) => Math.floor((t + tzOffset) / step) * step - tzOffset;
  const byT = new Map(points.map((p) => [p.t, p]));
  const buckets = [];
  for (let t = align(from); t <= to; t += step) buckets.push(byT.get(t) || { t, in: 0, out: 0 });
  const max = niceMax(Math.max(0, ...buckets.map((b) => b.in + b.out)));
  const slot = iw / buckets.length;
  const bw = Math.max(1, Math.min(24, slot * 0.7));
  const y = (v) => m.t + ih - (v / max) * ih;

  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Traffic over time">`;
  for (let k = 0; k <= 4; k++) {
    const v = (max / 4) * k, yy = y(v);
    svg += `<line class="${k ? "gridline" : "baseline"}" x1="${m.l}" x2="${W - m.r}" y1="${yy}" y2="${yy}"/>`;
    svg += `<text x="${m.l - 8}" y="${yy + 4}" text-anchor="end">${fmtBytes(v)}</text>`;
  }
  const every = Math.ceil(buckets.length / Math.max(1, Math.floor(iw / 90)));
  buckets.forEach((b, idx) => {
    const cx = m.l + slot * idx + slot / 2;
    const x = cx - bw / 2;
    const hIn = (b.in / max) * ih, hOut = (b.out / max) * ih;
    const gap = hIn > 0 && hOut > 0 ? 2 : 0;
    if (hIn > 0) svg += bar(x, y(0) - hIn, bw, hIn, "var(--in)", hOut === 0);
    if (hOut > 0) svg += bar(x, y(0) - hIn - gap - hOut, bw, hOut, "var(--out)", true);
    if (idx % every === 0) svg += `<text x="${cx}" y="${H - 6}" text-anchor="middle">${fmtTick(b.t, step)}</text>`;
    svg += `<rect class="hit" data-i="${idx}" x="${m.l + slot * idx}" y="${m.t}" width="${slot}" height="${ih}"/>`;
  });
  if (!points.length) {
    svg += `<text class="empty" x="${m.l + iw / 2}" y="${m.t + ih / 2}" text-anchor="middle">${live ? "No traffic recorded in this period yet" : "No history"}</text>`;
  }
  svg += "</svg>";
  el.innerHTML = svg;
  el.onmousemove = (e) => {
    const i = e.target.dataset?.i; if (i === undefined) return hideTip();
    const b = buckets[i];
    const end = new Date((b.t + step) * 1000);
    const title = step >= 86400 ? new Date(b.t * 1000).toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" })
      : `${fmtTick(b.t, 60)} – ${end.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}`;
    showTip(e, title, b.in, b.out);
  };
  el.onmouseleave = hideTip;
}

// Column with a 4px rounded data-end and a square base.
function bar(x, y, w, h, fill, roundTop) {
  const r = roundTop ? Math.min(4, w / 2, h) : 0;
  return `<path fill="${fill}" d="M${x},${y + h} V${y + r} Q${x},${y} ${x + r},${y} H${x + w - r} Q${x + w},${y} ${x + w},${y + r} V${y + h} Z"/>`;
}

const tip = $("tip");
function showTip(e, title, down, up) {
  tip.innerHTML = `<div class="t">${esc(title)}</div>
    <div class="r"><span><i class="key k-in"></i>Downloaded</span><b>${fmtBytes(down)}</b></div>
    <div class="r"><span><i class="key k-out"></i>Uploaded</span><b>${fmtBytes(up)}</b></div>
    <div class="r"><span>Total</span><b>${fmtBytes(down + up)}</b></div>`;
  tip.hidden = false;
  const pad = 14, r = tip.getBoundingClientRect();
  let x = e.clientX + pad, yy = e.clientY + pad;
  if (x + r.width > innerWidth - 8) x = e.clientX - r.width - pad;
  if (yy + r.height > innerHeight - 8) yy = e.clientY - r.height - pad;
  tip.style.left = x + "px"; tip.style.top = yy + "px";
}
function hideTip() { tip.hidden = true; }

document.querySelector(".ranges").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-range]"); if (!btn) return;
  state.range = btn.dataset.range;
  for (const b of document.querySelectorAll(".ranges button")) b.classList.toggle("on", b === btn);
  refresh();
});

let resizeTimer;
addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { refresh(); refreshSrum(); }, 200); });

refresh();
refreshSrum();
setInterval(refresh, 30000);
setInterval(refreshSrum, 10 * 60000);
