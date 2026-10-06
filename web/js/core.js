// Tiny DOM + data helpers (no framework, no build step).
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'html') el.innerHTML = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  add(el, kids);
  return el;
}
function add(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k.nodeType ? k : document.createTextNode(String(k)));
  }
}
export const svg = (tag, attrs, ...kids) => {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) if (v != null) el.setAttribute(k, v);
  add(el, kids);
  return el;
};
export const clear = (el, ...kids) => { el.replaceChildren(); add(el, kids); return el; };

// ---- icons (single-path 24px, stroke style) ----
const P = {
  shield: 'M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z',
  chip: 'M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3M7 6h10v12H7z',
  chain: 'M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1',
  alert: 'M12 3l10 18H2L12 3zM12 10v5M12 18h.01',
  brain: 'M9 4a3 3 0 00-3 3 3 3 0 00-2 5 3 3 0 002 5 3 3 0 006 0V4a3 3 0 00-3 0zM15 4a3 3 0 013 3 3 3 0 012 5 3 3 0 01-2 5 3 3 0 01-6 0',
  flask: 'M9 3h6M10 3v6L4 19a2 2 0 002 3h12a2 2 0 002-3l-6-10V3',
  siren: 'M5 20h14M7 20v-6a5 5 0 0110 0v6M12 4V2M4 8L2.5 7M20 8l1.5-1',
  home: 'M3 11l9-8 9 8M5 10v10h14V10',
  check: 'M5 12.5l4.5 4.5L19 7',
  x: 'M6 6l12 12M18 6L6 18',
  lock: 'M6 11h12v10H6zM8 11V7a4 4 0 018 0v4',
  info: 'M12 8h.01M11 12h1v5h1M3 12a9 9 0 1018 0 9 9 0 10-18 0',
  diamond: 'M12 3l9 9-9 9-9-9z',
  circle: 'M12 7a5 5 0 100 10 5 5 0 000-10z',
  tri: 'M12 4l9 16H3z',
  sun: 'M12 8a4 4 0 100 8 4 4 0 000-8zM12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5',
  bolt: 'M13 2L4 14h7l-1 8 9-12h-7z',
  radar: 'M12 12l6-6M3 12a9 9 0 1018 0 9 9 0 10-18 0M7.5 12a4.5 4.5 0 109 0',
  play: 'M7 4l13 8-13 8z',
  db: 'M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
};
export function icon(name, size) {
  const s = svg('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', width: size, height: size });
  s.append(svg('path', { d: P[name] || P.circle }));
  return s;
}
const SEV_ICON = { SAFE: 'check', LOW: 'check', ACTIVE: 'check', MATCH: 'check', OK: 'check', SUSPICIOUS: 'tri', MEDIUM: 'tri', RECOVERY_PENDING: 'tri', HIGH: 'diamond', CRITICAL: 'x', QUARANTINED: 'lock', MISMATCH: 'x', TAMPERING_DETECTED: 'x', LOCAL_RECORD_MISSING: 'x', NOT_ON_CHAIN: 'info' };
export const badge = (v, label) => h('span', { class: `badge b-${v}` }, icon(SEV_ICON[v] || 'circle'), (label ?? String(v)).replaceAll('_', ' '));

// ---- formatting ----
export const fmt = {
  n: (v, d = 1) => (v == null || Number.isNaN(v) ? '–' : Number(v).toFixed(d)),
  pct: (v, d = 0) => (v == null ? '–' : (v * 100).toFixed(d) + '%'),
  hash: (s, n = 8) => (s ? s.slice(0, n) + '…' : '–'),
  time: (ts) => (ts ? new Date(ts * 1000).toLocaleTimeString([], { hour12: false }) : '–'),
  dt: (ts) => (ts ? new Date(ts * 1000).toLocaleString([], { hour12: false }) : '–'),
  ago: (ts, now) => { if (!ts) return '–'; const d = Math.max(0, (now ?? Date.now() / 1000) - ts); return d < 60 ? `${d.toFixed(0)}s ago` : d < 3600 ? `${(d / 60).toFixed(0)}m ago` : `${(d / 3600).toFixed(1)}h ago`; },
  name: (id) => (id || '').split(':').slice(-2).join(':'),
  type: (t) => (t || '').replaceAll('_', ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase()),
};

// ---- API ----
const tokenKey = 'tc_admin_token';
export const getToken = () => { try { return sessionStorage.getItem(tokenKey) || ''; } catch { return ''; } };
export const setToken = (t) => { try { sessionStorage.setItem(tokenKey, t); } catch { /* storage blocked */ } };

async function ask(path, opts) {
  const r = await fetch(path, opts);
  let body = null;
  try { body = await r.json(); } catch { /* empty */ }
  if (!r.ok) { const e = new Error(body?.detail || r.statusText); e.status = r.status; throw e; }
  return body;
}
export const api = {
  get: (p) => ask(p),
  async post(p, body, { admin = false } = {}) {
    const run = () => ask(p, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Admin-Token': getToken() }, body: JSON.stringify(body ?? {}) });
    try { return await run(); } catch (e) {
      if (e.status === 401 && admin !== null) { await promptAdmin(); return run(); }
      throw e;
    }
  },
};
// Run an action with toast feedback.
export async function act(label, fn) {
  try { const r = await fn(); toast(label, 'ok'); return r; } catch (e) { toast(e.message || String(e), 'err'); throw e; }
}

export function toast(msg, kind = '') {
  let box = document.querySelector('.toasts');
  if (!box) { box = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' }); document.body.append(box); }
  const t = h('div', { class: `toast ${kind}` }, msg);
  box.append(t);
  setTimeout(() => t.remove(), 4200);
}

export function modal(content, { onclose } = {}) {
  const bg = h('div', { class: 'modal-bg', onclick: (e) => { if (e.target === bg) close(); } });
  const box = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' });
  const close = () => { bg.remove(); document.removeEventListener('keydown', esc); onclose?.(); };
  const esc = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', esc);
  box.append(h('div', { class: 'row', style: { justifyContent: 'flex-end', marginBottom: '6px' } }, h('button', { class: 'btn sm', onclick: close, 'aria-label': 'Close' }, icon('x', 14), 'Close')), content);
  bg.append(box);
  document.body.append(bg);
  return { close, box };
}

export function promptAdmin() {
  return new Promise((resolve, reject) => {
    const input = h('input', { type: 'password', placeholder: 'Admin token', autofocus: true, style: { width: '100%' } });
    const m = modal(h('div', { class: 'stack' },
      h('h2', null, 'Administrator action'),
      h('p', { class: 'muted' }, 'This action changes security state and is logged on the ledger. Enter the admin token (default for local demos: ', h('code', null, 'admin'), ').'),
      input,
      h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: async () => {
        setToken(input.value);
        try { await ask('/api/session/check', { method: 'POST', headers: { 'X-Admin-Token': input.value } }); m.close(); resolve(); } catch { toast('Wrong token', 'err'); }
      } }, 'Authorise'))), { onclose: () => reject(new Error('cancelled')) });
    input.focus();
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') m.box.querySelector('.btn.primary').click(); });
  });
}

// ---- live store (WebSocket with polling fallback) ----
export const store = { data: null, feed: [], subs: new Set(), connected: false };
export function subscribe(fn) { store.subs.add(fn); if (store.data) fn(store.data); return () => store.subs.delete(fn); }
function push(msg) {
  store.data = msg.data;
  for (const f of msg.feed || []) store.feed.unshift(f);
  store.feed.length = Math.min(store.feed.length, 300);
  store.subs.forEach((fn) => fn(store.data));
}
export function connect() {
  let ws, wsOpen = false, polling = false;
  // Fallback: if the WebSocket is blocked or slow, poll the REST API instead.
  const poll = async () => {
    if (wsOpen) { polling = false; return; }
    polling = true;
    try { const [d, f] = await Promise.all([api.get('/api/overview'), api.get('/api/feed?since=' + (store.feed[0]?.seq || 0))]); store.connected = true; push({ data: d, feed: f.items.reverse() }); } catch { store.connected = false; }
    setTimeout(poll, 1500);
  };
  const open = () => {
    try { ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws'); } catch { poll(); return; }
    ws.onopen = () => { wsOpen = true; store.connected = true; };
    ws.onmessage = (e) => { try { push(JSON.parse(e.data)); } catch { /* ignore */ } };
    ws.onclose = () => { wsOpen = false; store.connected = false; if (!polling) poll(); setTimeout(open, 3000); };
    setTimeout(() => { if (!wsOpen && !polling) poll(); }, 1200);
  };
  open();
}
export const sevOrder = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
export const bandColor = { SAFE: 'var(--good)', SUSPICIOUS: 'var(--warn)', HIGH: 'var(--serious)', CRITICAL: 'var(--crit)' };
export const seriesColor = (i) => `var(--s${(i % 8) + 1})`;
