import { h, clear, icon, badge, fmt, api, modal, toast, store } from '../js/core.js';
import { ring } from '../js/charts.js';
import { pageHeader, card, kpi, empty, trustColor } from '../js/shared.js';

export const money = (n) => '$' + Math.round(n || 0).toLocaleString('en-US');

/** [badge key, label] describing a device's current condition, never colour alone. */
export function statusOf(d) {
  if (d.status === 'QUARANTINED') return ['QUARANTINED', 'Quarantined'];
  if (d.status === 'RECOVERY_PENDING') return ['RECOVERY_PENDING', 'Recovery pending'];
  if (d.attack) return ['HIGH', 'Under attack'];
  if (d.online === false) return ['NOT_ON_CHAIN', 'Offline'];
  if (d.band === 'SAFE') return ['SAFE', 'OK'];
  return [d.band, d.band === 'SUSPICIOUS' ? 'Suspicious' : fmt.type(d.band) + ' risk'];
}
const stateKey = (d) => (d.status === 'ACTIVE' ? (d.attack ? 'HIGH' : d.band) : d.status);
const metric = (d) => {
  const v = d.sample?.primary;
  return v == null ? '—' : `${(d.primary_name || '').replaceAll('_', ' ')} ${fmt.n(v, Math.abs(v) >= 100 ? 0 : 1)}`;
};

export default function home(root, { param } = {}) {
  let cat = 'all', built = null, last = null, opened = false;
  const tiles = new Map();           // device id -> element (updated in place, never rebuilt each tick)
  const kpis = h('div', { class: 'grid kpis' }), chips = h('div', { class: 'chips', role: 'toolbar', 'aria-label': 'Filter by category' }), grid = h('div', { class: 'rooms' });
  root.append(pageHeader('Smart home', 'Every room and device under TrustChain protection, with live trust, risk and safety status. Click a device to inspect or control it.'), kpis, chips, grid);

  function tileFor(d) {
    const el = h('button', { class: 'tile', 'data-id': d.id, onclick: () => openDevice(d.id), 'aria-label': d.name });
    el.append(h('div', { class: 't-top' }, h('span', { class: 't-ico', 'aria-hidden': 'true' }, d.icon || '📟'), h('span', { class: 't-badge' })),
      h('div', { class: 't-name' }, d.name), h('div', { class: 't-meta' }), h('div', { class: 't-state' }),
      h('div', { class: 't-foot' }, h('span', { class: 't-trust' }, h('i')), h('span', { class: 't-val' }, money(d.value_usd))));
    if (d.critical) el.querySelector('.t-name').append(h('span', { class: 'star', title: 'Safety-critical device', 'aria-label': 'safety-critical' }, ' ★'));
    return el;
  }
  function paintTile(el, d) {
    const [bk, bl] = statusOf(d);
    el.className = `tile s-${stateKey(d)}${d.attack ? ' atk' : ''}${el.classList.contains('hide') ? ' hide' : ''}`;
    el.querySelector('.t-badge').replaceChildren(badge(bk, bl));
    el.querySelector('.t-meta').textContent = metric(d);
    el.querySelector('.t-state').textContent = Object.values(d.state || {}).join(' · ') || ' ';
    const bar = el.querySelector('.t-trust i'); bar.style.width = Math.max(2, d.trust) + '%'; bar.style.background = trustColor(d.trust);
    el.title = `${d.name} · trust ${fmt.n(d.trust, 0)} · risk ${fmt.n(d.risk, 2)}`;
  }
  function build(d) {
    const key = d.devices.map((x) => x.id).join('|') + d.rooms.map((r) => r.id).join('|');
    if (built === key) return;
    built = key; tiles.clear(); clear(grid);
    for (const r of d.rooms) {
      const body = h('div', { class: 'tiles' });
      for (const id of r.devices) { const dev = d.devices.find((x) => x.id === id); const t = tileFor(dev); tiles.set(id, t); body.append(t); }
      grid.append(h('section', { class: 'room', 'data-room': r.id, 'aria-label': r.name },
        h('div', { class: 'rh' }, h('span', { class: 'ri', 'aria-hidden': 'true' }, r.icon), h('div', { class: 'grow' }, h('h2', null, r.name), h('small', null, `${r.zone} · ${r.count} devices · ${money(r.value_usd)}`)), h('span', { class: 'rbadge' })), body));
    }
  }
  function paintChips(d) {
    const counts = {}; d.devices.forEach((x) => { counts[x.category] = (counts[x.category] || 0) + 1; });
    const mk = (id, label, n, ico) => h('button', { class: `chip${cat === id ? ' on' : ''}`, 'aria-pressed': cat === id, onclick: () => { cat = id; paintChips(last); applyFilter(); } }, ico && h('span', { 'aria-hidden': 'true' }, ico), label, h('small', null, n));
    clear(chips, mk('all', 'All devices', d.devices.length), Object.entries(d.categories).filter(([k]) => counts[k]).map(([k, v]) => mk(k, v.label, counts[k], v.icon)));
  }
  function applyFilter() {
    if (!last) return;
    for (const dev of last.devices) tiles.get(dev.id)?.classList.toggle('hide', cat !== 'all' && dev.category !== cat);
    grid.querySelectorAll('.room').forEach((r) => { r.style.display = [...r.querySelectorAll('.tile')].every((t) => t.classList.contains('hide')) ? 'none' : ''; });
  }
  function update(d) {
    last = d; build(d);
    const hm = d.home, nq = d.kpis.quarantined, issues = d.rooms.filter((r) => r.worst_band !== 'SAFE' || r.quarantined).length;
    clear(kpis,
      kpi('Devices protected', hm.devices, `${d.devices.filter((x) => x.online !== false).length} online · ${hm.critical} safety-critical ★`, 'chip'),
      kpi('Equipment value', money(hm.value_usd), `${money(hm.value_quarantined_usd)} currently quarantined`, 'db'),
      kpi('Rooms', d.rooms.length, issues ? `${issues} need attention` : 'all clear', 'home'),
      kpi('Average trust', fmt.n(d.kpis.avg_trust, 0), `${nq} quarantined`, 'check'),
      kpi('Threat level', badge(d.threat_level), d.attacks.length ? `${d.attacks.length} attack(s) in progress` : 'no attack in progress', 'shield'));
    if (!chips.childElementCount) paintChips(d);
    for (const dev of d.devices) paintTile(tiles.get(dev.id), dev);
    for (const r of d.rooms) {
      const sec = grid.querySelector(`[data-room="${r.id}"]`); if (!sec) continue;
      const worst = r.quarantined ? 'CRITICAL' : r.worst_band; sec.className = `room s-${worst}`;
      sec.querySelector('.rbadge').replaceChildren(r.quarantined ? badge('QUARANTINED', `${r.quarantined} quarantined`) : r.attacks ? badge('HIGH', 'under attack') : badge(r.worst_band, r.worst_band === 'SAFE' ? 'all OK' : fmt.type(r.worst_band)));
    }
    applyFilter();
    if (param && !drawer.id && !opened) { opened = true; if (tiles.has(decodeURIComponent(param))) openDevice(decodeURIComponent(param)); }
    if (drawer.id) paintDrawer();
  }

  // ---- device drawer ------------------------------------------------------------------
  const drawer = { id: null, el: null, out: null };
  function openDevice(id) {
    drawer.id = id;
    const body = h('div', { class: 'stack' });
    const m = modal(body, { onclose: () => { drawer.id = null; drawer.el = null; } });
    drawer.el = body; drawer.out = h('div'); paintDrawer(true);
  }
  function paintDrawer(first) {
    const d = last?.devices.find((x) => x.id === drawer.id); if (!d || !drawer.el) return;
    if (!first && drawer.el.querySelector('.cmd-row button:focus')) return;       // do not steal focus mid-click
    const [bk, bl] = statusOf(d);
    const room = last.rooms.find((r) => r.id === d.room);
    const cmds = (d.commands || []).map((c) => h('button', { class: 'btn sm', onclick: () => send(d, c) }, c.replaceAll('_', ' ')));
    const keep = drawer.out;
    clear(drawer.el,
      h('div', { class: 'drawer-hd' }, h('div', { class: 'big', 'aria-hidden': 'true' }, d.icon), h('div', { style: { flex: 1 } }, h('h2', { style: { fontSize: '20px' } }, d.name), h('div', { class: 'muted' }, `${d.model || d.dtype} · ${room?.name || ''}`), h('div', { class: 'row', style: { marginTop: '6px' } }, badge(bk, bl), d.critical && h('span', { class: 'badge' }, '★ safety-critical'), h('span', { class: 'badge' }, money(d.value_usd)))), ring(d.trust, { color: trustColor(d.trust), label: 'trust', size: 78 })),
      h('dl', { class: 'kv' },
        h('dt', null, 'Category'), h('dd', null, last.categories[d.category]?.label || d.category),
        h('dt', null, 'Risk / trust'), h('dd', null, `${fmt.n(d.risk, 2)} (${d.band}) · trust ${fmt.n(d.trust, 0)}`),
        h('dt', null, 'Telemetry'), h('dd', null, `${fmt.n(d.sample?.req_rate, 1)} req/s · ${metric(d)}`),
        h('dt', null, 'State'), h('dd', null, Object.entries(d.state || {}).map(([k, v]) => `${k} ${v}`).join(' · ') || '—'),
        h('dt', null, 'If quarantined'), h('dd', null, d.fail_policy || '—'),
        h('dt', null, 'Identity'), h('dd', { class: 'mono' }, d.id)),
      cmds.length ? h('div', null, h('h3', { style: { marginBottom: '8px' } }, 'Controls (through the gateway)'), h('div', { class: 'cmd-row' }, cmds)) : h('div', { class: 'muted small' }, 'Read-only sensor — no remote controls.'),
      keep,
      h('div', { class: 'row' }, h('a', { class: 'btn sm', href: `#/devices/${encodeURIComponent(d.id)}`, onclick: () => document.querySelector('.modal-bg')?.remove() }, 'Full details →'),
        d.status === 'ACTIVE' && h('button', { class: 'btn danger sm', onclick: () => api.post(`/api/devices/${encodeURIComponent(d.id)}/quarantine`, {}, { admin: true }).then(() => toast(`${d.name} quarantined`, 'ok')).catch((e) => toast(e.message, 'err')) }, icon('lock', 13), 'Quarantine')));
  }
  async function send(d, command) {
    try {
      const r = await api.post('/api/commands', { to: d.id, command }, { admin: true });
      clear(drawer.out, h('div', { class: `note${r.allowed ? '' : ' warn'}` }, h('b', null, r.allowed ? 'Allowed. ' : 'Blocked. '), r.reason));
    } catch (e) { clear(drawer.out, h('div', { class: 'note warn' }, e.message)); }
  }
  return { update, destroy() {} };
}
